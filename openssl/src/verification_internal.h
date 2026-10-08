#pragma once

#include "internal.h"

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <optional>

namespace pesign::detail {

struct ChainResult {
    std::string status = "untrusted";
    std::string revocation = "not_checked";
    int error_code = 0;
    std::vector<Certificate> chain;
    std::vector<std::vector<std::uint8_t>> encoded_chain;
    std::vector<std::string> details;
};

struct HttpResponse {
    bool success = false;
    long status_code = 0;
    std::vector<std::uint8_t> body;
    std::string error;
};

std::vector<std::uint8_t> read_file(const std::filesystem::path& file,
    std::size_t maximum_bytes = 1024u * 1024u * 1024u);

// GET when request_body is empty, POST otherwise. HTTP/HTTPS only, bounded.
HttpResponse http_request(const std::string& url,
    const std::vector<std::uint8_t>& request_body = {},
    const std::string& content_type = {}, unsigned timeout_seconds = 10,
    std::size_t maximum_bytes = 16u * 1024u * 1024u);

ChainResult verify_chain(X509* signer, STACK_OF(X509)* untrusted,
    const Options& options, std::optional<std::time_t> signing_time, bool timestamp,
    STACK_OF(X509_CRL)* embedded_crls = nullptr, bool rfc3161 = true);

// Offline metadata only: ordered issuer signatures are checked, but validity,
// purpose, trust and revocation are not. Status is built, partial or unavailable.
ChainResult build_certificate_chain(X509* signer, STACK_OF(X509)* untrusted,
    const Options& options);

Certificate certificate_metadata(X509* certificate);

// PKCS#7 metadata must already have been appended for this certificate record.
// Verifies each parsed signer, including nested signatures, in place.
void verify_pkcs7(const std::uint8_t* data, std::size_t size,
    std::size_t certificate_record, const std::vector<std::uint8_t>& pe,
    const Options& options, Analysis& result, bool catalog = false);

bool catalog_content_contains(const std::uint8_t* data, std::size_t size,
    const std::vector<std::uint8_t>& digest);

// Root orchestration: catalog metadata, discovery, verification and summary.
Analysis analyze_with_options(const std::vector<std::uint8_t>& bytes,
    const std::filesystem::path& file, const Options& options);

} // namespace pesign::detail
