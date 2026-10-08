#include "verification_internal.h"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#endif
#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <memory>
#include <mutex>

namespace pesign::detail {
namespace {

struct Download {
    std::vector<std::uint8_t> bytes;
    std::size_t limit = 0;
    bool exceeded = false;
};

std::size_t receive(char* data, std::size_t size, std::size_t count, void* user) {
    auto& download = *static_cast<Download*>(user);
    if (count && size > std::numeric_limits<std::size_t>::max() / count) return 0;
    const std::size_t length = size * count;
    if (length > download.limit - download.bytes.size()) {
        download.exceeded = true;
        return 0;
    }
    try {
        download.bytes.insert(download.bytes.end(), data, data + length);
    } catch (...) {
        return 0; // Never allow an exception to cross libcurl's C callback.
    }
    return length;
}

} // namespace

HttpResponse http_request(const std::string& url,
    const std::vector<std::uint8_t>& request_body,
    const std::string& content_type, unsigned timeout_seconds,
    std::size_t maximum_bytes) {
    HttpResponse response;
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char character) { return static_cast<char>(std::tolower(character)); });
    const std::size_t authority = lower.find("://");
    const std::size_t authority_end = authority == std::string::npos ? 0 :
        lower.find_first_of("/?#", authority + 3);
    if (url.size() > 4096 || (lower.rfind("http://", 0) != 0 &&
            lower.rfind("https://", 0) != 0) ||
        url.substr(authority + 3, authority_end - (authority + 3)).find('@') !=
            std::string::npos || url.find('\0') != std::string::npos ||
        content_type.find_first_of("\r\n") != std::string::npos ||
        maximum_bytes == 0 || maximum_bytes > 64u * 1024u * 1024u ||
        request_body.size() > 16u * 1024u * 1024u) {
        response.error = "Unsupported or oversized HTTP request";
        return response;
    }
    static std::once_flag initialized;
    static CURLcode initialization = CURLE_FAILED_INIT;
    std::call_once(initialized, [] { initialization = curl_global_init(CURL_GLOBAL_DEFAULT); });
    if (initialization != CURLE_OK) {
        response.error = "libcurl initialization failed";
        return response;
    }
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> handle(curl_easy_init(), curl_easy_cleanup);
    if (!handle) {
        response.error = "libcurl handle allocation failed";
        return response;
    }
    Download download{{}, maximum_bytes, false};
    char error[CURL_ERROR_SIZE]{};
    bool configured = true;
    const auto set = [&](CURLoption option, auto value) {
        if (curl_easy_setopt(handle.get(), option, value) != CURLE_OK) configured = false;
    };
    set(CURLOPT_URL, url.c_str());
    set(CURLOPT_ERRORBUFFER, error);
    set(CURLOPT_NOSIGNAL, 1L);
    set(CURLOPT_TIMEOUT, static_cast<long>(std::clamp(timeout_seconds, 1u, 300u)));
    set(CURLOPT_CONNECTTIMEOUT, static_cast<long>(std::min(timeout_seconds ? timeout_seconds : 1u, 10u)));
    set(CURLOPT_FOLLOWLOCATION, 1L);
    set(CURLOPT_MAXREDIRS, 3L);
    set(CURLOPT_SSL_VERIFYPEER, 1L);
    set(CURLOPT_SSL_VERIFYHOST, 2L);
#if defined(_WIN32) && defined(CURLSSLOPT_NATIVE_CA)
    // Use Windows trust roots even when the curl DLL is distributed without
    // its original installation's CA bundle.
    set(CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
#endif
    set(CURLOPT_NETRC, static_cast<long>(CURL_NETRC_IGNORED));
    set(CURLOPT_FAILONERROR, 1L);
    set(CURLOPT_USERAGENT, "PESignAnalyzerOpenSSL/0.2");
    set(CURLOPT_WRITEFUNCTION, &receive);
    set(CURLOPT_WRITEDATA, &download);
    set(CURLOPT_MAXFILESIZE_LARGE, static_cast<curl_off_t>(maximum_bytes));
#if LIBCURL_VERSION_NUM >= 0x075500
    set(CURLOPT_PROTOCOLS_STR, "http,https");
    set(CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    set(CURLOPT_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
    set(CURLOPT_REDIR_PROTOCOLS, static_cast<long>(CURLPROTO_HTTP | CURLPROTO_HTTPS));
#endif
    std::unique_ptr<curl_slist, decltype(&curl_slist_free_all)> headers(nullptr, curl_slist_free_all);
    if (!request_body.empty()) {
        headers.reset(curl_slist_append(nullptr, ("Content-Type: " + content_type).c_str()));
        if (!headers) configured = false;
        set(CURLOPT_HTTPHEADER, headers.get());
        set(CURLOPT_POSTFIELDS, reinterpret_cast<const char*>(request_body.data()));
        set(CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request_body.size()));
    }
    if (!configured) {
        response.error = "Cannot configure bounded HTTP transfer";
        return response;
    }
    const CURLcode result = curl_easy_perform(handle.get());
    curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &response.status_code);
    if (result != CURLE_OK || response.status_code < 200 || response.status_code >= 300) {
        response.error = download.exceeded ? "HTTP response exceeds size limit" :
            (error[0] ? error : curl_easy_strerror(result));
        return response;
    }
    response.body = std::move(download.bytes);
    response.success = true;
    return response;
}

} // namespace pesign::detail
