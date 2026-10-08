#include "verification_internal.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <memory>
#include <set>
#include <system_error>
#include <utility>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <wincrypt.h>
#undef OCSP_REQUEST
#undef OCSP_RESPONSE
#elif defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace pesign::detail {
namespace {

template <typename T, void (*Free)(T*)>
using Handle = std::unique_ptr<T, decltype(Free)>;
using Cert = Handle<X509, X509_free>;
using Crl = Handle<X509_CRL, X509_CRL_free>;
using CertStack = std::unique_ptr<STACK_OF(X509), void(*)(STACK_OF(X509)*)>;
constexpr std::size_t download_limit = 16u * 1024u * 1024u;
constexpr std::size_t max_input_bytes = 64u * 1024u * 1024u;
constexpr std::size_t max_chain_depth = 16;
constexpr std::size_t max_metadata_chain_depth = 64;
constexpr std::size_t max_requests = 32;
constexpr std::size_t max_urls = 8;
constexpr long freshness_slack = 300;
constexpr long ocsp_max_age = 7 * 24 * 60 * 60;

struct RetrievalBudget {
    std::size_t requests = 0;
    std::chrono::steady_clock::time_point deadline;

    unsigned timeout() const {
        if (requests >= max_requests) return 0;
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining <= std::chrono::steady_clock::duration::zero()) return 0;
        const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(remaining).count();
        return static_cast<unsigned>((milliseconds + 999) / 1000);
    }
};

void detail(std::vector<std::string>& details, const std::string& message) {
    if (details.size() < 64) details.push_back(message);
}

std::vector<std::uint8_t> read_trust_file(const std::filesystem::path& file,
    std::size_t limit = max_input_bytes) {
    std::error_code error;
    const auto size = std::filesystem::file_size(file, error);
    if (error || size == 0 || size > limit || size > std::numeric_limits<std::size_t>::max()) return {};
    std::ifstream stream(file, std::ios::binary);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!stream || !stream.read(reinterpret_cast<char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()))) return {};
    return bytes;
}

std::string hex_digest(const std::uint8_t* data, std::size_t length) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    if (EVP_Digest(data, length, digest.data(), &size, EVP_sha256(), nullptr) != 1) return {};
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result;
    for (unsigned index = 0; index < size; ++index) {
        result.push_back(alphabet[digest[index] >> 4]);
        result.push_back(alphabet[digest[index] & 15]);
    }
    return result;
}

std::string certificate_key(X509* certificate) {
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned size = 0;
    if (X509_digest(certificate, EVP_sha256(), digest.data(), &size) != 1) return {};
    return std::string(reinterpret_cast<char*>(digest.data()), size);
}

std::filesystem::path cache_directory(const Options& options) {
    if (!options.revocation_cache.empty()) return options.revocation_cache;
#ifdef _WIN32
    if (const auto* local = _wgetenv(L"LOCALAPPDATA"))
        return std::filesystem::path(local) / L"PESignAnalyzer" / L"revocation";
#else
    if (const auto* home = std::getenv("HOME")) {
#ifdef __APPLE__
        return std::filesystem::path(home) / "Library" / "Caches" / "PESignAnalyzer" / "revocation";
#else
        if (const auto* xdg = std::getenv("XDG_CACHE_HOME"))
            if (std::filesystem::path(xdg).is_absolute())
                return std::filesystem::path(xdg) / "PESignAnalyzer" / "revocation";
        return std::filesystem::path(home) / ".cache" / "PESignAnalyzer" / "revocation";
#endif
    }
#endif
    return {};
}

std::filesystem::path cache_file(const Options& options, const std::string& identity,
    const std::string& suffix) {
    const auto directory = cache_directory(options);
    if (directory.empty()) return {};
    const auto digest = hex_digest(reinterpret_cast<const std::uint8_t*>(identity.data()), identity.size());
    return digest.empty() ? std::filesystem::path{} : directory / (digest + suffix);
}

void write_cache(const std::filesystem::path& file, const std::vector<std::uint8_t>& bytes,
    std::vector<std::string>& details) {
    if (file.empty() || bytes.empty()) return;
    std::error_code error;
    std::filesystem::create_directories(file.parent_path(), error);
    if (error) {
        detail(details, "Cannot create revocation cache: " + error.message());
        return;
    }
    std::array<unsigned char, 8> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) return;
    const auto temporary = file.parent_path() / (file.filename().string() + "." +
        hex_digest(random.data(), random.size()).substr(0, 16) + ".tmp");
    {
        std::ofstream stream(temporary, std::ios::binary | std::ios::trunc);
        if (!stream || !stream.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()))) {
            stream.close();
            std::filesystem::remove(temporary, error);
            detail(details, "Cannot write revocation cache");
            return;
        }
    }
    std::filesystem::rename(temporary, file, error);
    if (error) {
        // Windows rename cannot replace an existing cache entry.
        std::filesystem::remove(file, error);
        error.clear();
        std::filesystem::rename(temporary, file, error);
    }
    if (error) {
        std::filesystem::remove(temporary, error);
        detail(details, "Cannot update revocation cache");
    }
}

void decode_certificates(const std::vector<std::uint8_t>& bytes,
    std::vector<Cert>& certificates, bool allow_pkcs7) {
    if (bytes.empty() || bytes.size() > max_input_bytes) return;
    Handle<BIO, BIO_free_all> bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free_all);
    if (!bio) return;
    while (certificates.size() < 512) {
        X509* certificate = PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr);
        if (!certificate) break;
        certificates.emplace_back(certificate, X509_free);
    }
    ERR_clear_error();
    if (!certificates.empty()) return;
    const auto* cursor = bytes.data();
    Cert certificate(d2i_X509(nullptr, &cursor, static_cast<long>(bytes.size())), X509_free);
    if (certificate && cursor == bytes.data() + bytes.size()) {
        certificates.push_back(std::move(certificate));
        return;
    }
    ERR_clear_error();
    if (!allow_pkcs7) return;
    cursor = bytes.data();
    Handle<PKCS7, PKCS7_free> bag(d2i_PKCS7(nullptr, &cursor,
        static_cast<long>(bytes.size())), PKCS7_free);
    if (!bag || cursor != bytes.data() + bytes.size() || !PKCS7_type_is_signed(bag.get()) || !bag->d.sign) {
        ERR_clear_error();
        return;
    }
    for (int index = 0; index < sk_X509_num(bag->d.sign->cert) && certificates.size() < 512; ++index) {
        auto* embedded = sk_X509_value(bag->d.sign->cert, index);
        if (embedded && X509_up_ref(embedded) == 1) certificates.emplace_back(embedded, X509_free);
    }
}

void decode_crls(const std::vector<std::uint8_t>& bytes, std::vector<Crl>& crls) {
    if (bytes.empty() || bytes.size() > max_input_bytes) return;
    const auto initial_size = crls.size();
    Handle<BIO, BIO_free_all> bio(BIO_new_mem_buf(bytes.data(), static_cast<int>(bytes.size())), BIO_free_all);
    if (!bio) return;
    while (crls.size() < 256) {
        X509_CRL* crl = PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr);
        if (!crl) break;
        crls.emplace_back(crl, X509_CRL_free);
    }
    ERR_clear_error();
    if (crls.size() != initial_size) return;
    const auto* cursor = bytes.data();
    Crl crl(d2i_X509_CRL(nullptr, &cursor, static_cast<long>(bytes.size())), X509_CRL_free);
    if (crl && cursor == bytes.data() + bytes.size()) crls.push_back(std::move(crl));
    ERR_clear_error();
}

void add_trust(X509_STORE* store, X509* certificate) {
    // OpenSSL reports an error for duplicates; the store retains its own reference.
    X509_STORE_add_cert(store, certificate);
    ERR_clear_error();
}

CertStack certificate_stack(STACK_OF(X509)* certificates = nullptr) {
    return CertStack(certificates ? certificates : sk_X509_new_null(),
        [](STACK_OF(X509)* values) { sk_X509_pop_free(values, X509_free); });
}

bool append_candidate(STACK_OF(X509)* candidates, std::set<std::string>& seen,
    X509* certificate) {
    if (!certificate || !candidates || sk_X509_num(candidates) >= 512) return false;
    const auto key = certificate_key(certificate);
    if (key.empty() || !seen.insert(key).second) return false;
    if (X509_up_ref(certificate) != 1) return false;
    if (!sk_X509_push(candidates, certificate)) { X509_free(certificate); return false; }
    return true;
}

void load_ca_file(X509_STORE* store, const std::filesystem::path& file,
    std::vector<std::string>& details) {
    std::vector<Cert> certificates;
    decode_certificates(read_trust_file(file), certificates, false);
    if (certificates.empty()) detail(details, "Cannot read CA certificates: " + file.u8string());
    for (const auto& certificate : certificates) add_trust(store, certificate.get());
}

template <typename Consumer>
void read_directory(const std::filesystem::path& directory, std::size_t max_files,
    Consumer consume, std::vector<std::string>& details) {
    std::error_code error;
    std::filesystem::directory_iterator iterator(directory, error);
    if (error) {
        detail(details, "Cannot read certificate/CRL directory: " + directory.u8string());
        return;
    }
    std::size_t count = 0;
    const std::filesystem::directory_iterator end;
    for (; iterator != end && count < max_files; iterator.increment(error)) {
        if (error) break;
        if (iterator->is_regular_file(error)) {
            consume(iterator->path());
            ++count;
        }
    }
    if (error || count == max_files) detail(details, "Certificate/CRL directory traversal was limited");
}

#ifdef _WIN32
bool windows_usage_allowed(PCCERT_CONTEXT certificate, bool timestamp) {
    DWORD length = 0;
    SetLastError(ERROR_SUCCESS);
    if (!CertGetEnhancedKeyUsage(certificate, 0, nullptr, &length))
        return GetLastError() == CRYPT_E_NOT_FOUND;
    if (length < sizeof(CERT_ENHKEY_USAGE) || length > 1024u * 1024u) return false;
    std::vector<BYTE> bytes(length);
    auto* usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(bytes.data());
    SetLastError(ERROR_SUCCESS);
    if (!CertGetEnhancedKeyUsage(certificate, 0, usage, &length)) return false;
    if (usage->cUsageIdentifier == 0) return GetLastError() == CRYPT_E_NOT_FOUND;
    for (DWORD index = 0; index < usage->cUsageIdentifier; ++index) {
        const std::string oid = usage->rgpszUsageIdentifier[index];
        if (oid == "2.5.29.37.0" || oid == (timestamp ? "1.3.6.1.5.5.7.3.8" : "1.3.6.1.5.5.7.3.3")) return true;
    }
    return false;
}

void load_windows_intermediates(std::vector<Cert>& certificates, bool timestamp,
    std::set<std::string>& distrusted) {
    for (DWORD location : {CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}) {
        HCERTSTORE store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"CA");
        if (!store) continue;
        PCCERT_CONTEXT context = nullptr;
        while (certificates.size() < 512 &&
            (context = CertEnumCertificatesInStore(store, context)) != nullptr) {
            const unsigned char* cursor = context->pbCertEncoded;
            Cert certificate(d2i_X509(nullptr, &cursor, context->cbCertEncoded), X509_free);
            if (!certificate) continue;
            if (!windows_usage_allowed(context, timestamp))
                distrusted.insert(certificate_key(certificate.get()));
            certificates.push_back(std::move(certificate));
        }
        if (context) CertFreeCertificateContext(context); // Enumeration stopped at the bound.
        CertCloseStore(store, 0);
    }
}

void load_windows_roots(X509_STORE* store, std::vector<std::string>& details,
    std::set<std::string>& distrusted, bool metadata_only = false) {
    for (DWORD location : {CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}) {
        HCERTSTORE rejected = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"Disallowed");
        if (rejected) {
            PCCERT_CONTEXT context = nullptr;
            while ((context = CertEnumCertificatesInStore(rejected, context)) != nullptr) {
                const unsigned char* cursor = context->pbCertEncoded;
                Cert certificate(d2i_X509(nullptr, &cursor, context->cbCertEncoded), X509_free);
                if (certificate) distrusted.insert(certificate_key(certificate.get()));
            }
            CertCloseStore(rejected, 0);
        }
    }
    bool found = false;
    for (DWORD location : {CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE}) {
        HCERTSTORE roots = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
            location | CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG, L"ROOT");
        if (!roots) continue;
        found = true;
        PCCERT_CONTEXT context = nullptr;
        while ((context = CertEnumCertificatesInStore(roots, context)) != nullptr) {
            const unsigned char* cursor = context->pbCertEncoded;
            Cert certificate(d2i_X509(nullptr, &cursor, context->cbCertEncoded), X509_free);
            if (!certificate || (!metadata_only && distrusted.count(certificate_key(certificate.get())))) continue;
            if (metadata_only) {
                add_trust(store, certificate.get());
                continue;
            }
            bool code = true, timestamp = true;
            DWORD length = 0;
            SetLastError(ERROR_SUCCESS);
            if (CertGetEnhancedKeyUsage(context, 0, nullptr, &length) &&
                length >= sizeof(CERT_ENHKEY_USAGE) && length < 1024u * 1024u) {
                std::vector<BYTE> bytes(length);
                auto* usage = reinterpret_cast<PCERT_ENHKEY_USAGE>(bytes.data());
                SetLastError(ERROR_SUCCESS);
                if (CertGetEnhancedKeyUsage(context, 0, usage, &length)) {
                    const bool unrestricted = usage->cUsageIdentifier == 0 && GetLastError() == CRYPT_E_NOT_FOUND;
                    code = unrestricted;
                    timestamp = unrestricted;
                    for (DWORD index = 0; index < usage->cUsageIdentifier; ++index) {
                        const std::string oid = usage->rgpszUsageIdentifier[index];
                        code |= oid == "1.3.6.1.5.5.7.3.3" || oid == "2.5.29.37.0";
                        timestamp |= oid == "1.3.6.1.5.5.7.3.8" || oid == "2.5.29.37.0";
                    }
                    if (!code) X509_add1_reject_object(certificate.get(), OBJ_nid2obj(NID_code_sign));
                    if (!timestamp) X509_add1_reject_object(certificate.get(), OBJ_nid2obj(NID_time_stamp));
                } else {
                    continue; // A policy property we cannot decode must not grant trust.
                }
            } else if (GetLastError() != CRYPT_E_NOT_FOUND) {
                continue;
            }
            // Explicit native anchors can be cross-signed. Positive purpose
            // trust terminates their path without granting trust to bag certs.
            if (code) X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_code_sign));
            if (timestamp) X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_time_stamp));
            X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_ad_OCSP));
            add_trust(store, certificate.get());
        }
        CertCloseStore(roots, 0);
    }
    if (!found) detail(details, "Windows trusted root stores are unavailable");
}
#elif defined(__APPLE__)
bool apple_usage_applies(CFDictionaryRef settings, bool timestamp) {
    // Application/hostname constraints cannot be expressed by this PE verifier.
    if (CFDictionaryContainsKey(settings, kSecTrustSettingsApplication) ||
        CFDictionaryContainsKey(settings, kSecTrustSettingsPolicyString) ||
        CFDictionaryContainsKey(settings, kSecTrustSettingsAllowedError)) return false;
    const auto policy = static_cast<SecPolicyRef>(const_cast<void*>(CFDictionaryGetValue(settings, kSecTrustSettingsPolicy)));
    if (policy) {
        CFDictionaryRef properties = SecPolicyCopyProperties(policy);
        if (!properties) return false;
        const auto oid = static_cast<CFStringRef>(CFDictionaryGetValue(properties, kSecPolicyOid));
        const bool match = oid && (CFEqual(oid, kSecPolicyAppleX509Basic) ||
            (!timestamp && CFEqual(oid, kSecPolicyAppleCodeSigning)) ||
            (timestamp && CFEqual(oid, kSecPolicyAppleTimeStamping)));
        CFRelease(properties);
        if (!match) return false;
    }
    const auto key_usage = static_cast<CFNumberRef>(CFDictionaryGetValue(settings, kSecTrustSettingsKeyUsage));
    if (key_usage) {
        SInt32 value = 0;
        if (!CFNumberGetValue(key_usage, kCFNumberSInt32Type, &value) ||
            (value != static_cast<SInt32>(kSecTrustSettingsKeyUseAny) &&
             !(value & kSecTrustSettingsKeyUseSignature))) return false;
    }
    return true;
}

// -1 denied, 0 unspecified, 1 explicitly trusted. User settings take precedence.
int apple_setting(SecCertificateRef certificate, bool timestamp) {
    for (auto domain : {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin,
            kSecTrustSettingsDomainSystem}) {
        CFArrayRef settings = nullptr;
        const OSStatus status = SecTrustSettingsCopyTrustSettings(certificate, domain, &settings);
        if (status != errSecSuccess || !settings) continue;
        if (CFArrayGetCount(settings) == 0) {
            CFRelease(settings);
            return 1;
        }
        int decision = 0;
        bool restricted_trust = false;
        for (CFIndex index = 0; index < CFArrayGetCount(settings); ++index) {
            const auto entry = static_cast<CFDictionaryRef>(CFArrayGetValueAtIndex(settings, index));
            if (CFGetTypeID(entry) != CFDictionaryGetTypeID()) continue;
            SInt32 result = kSecTrustSettingsResultTrustRoot;
            const auto value = static_cast<CFNumberRef>(CFDictionaryGetValue(entry, kSecTrustSettingsResult));
            if (value && !CFNumberGetValue(value, kCFNumberSInt32Type, &result)) continue;
            restricted_trust |= result == kSecTrustSettingsResultTrustRoot ||
                result == kSecTrustSettingsResultTrustAsRoot;
            if (!apple_usage_applies(entry, timestamp)) continue;
            if (result == kSecTrustSettingsResultDeny) { decision = -1; break; }
            if (result == kSecTrustSettingsResultTrustRoot || result == kSecTrustSettingsResultTrustAsRoot) decision = 1;
        }
        CFRelease(settings);
        if (decision != 0) return decision;
        // A constrained trust grant is not an unrestricted anchor grant.
        if (restricted_trust) return -1;
    }
    return 0;
}

void add_apple_root(X509_STORE* store, SecCertificateRef native, bool default_anchor,
    bool requested_timestamp, std::set<std::string>& distrusted, bool metadata_only = false) {
    CFDataRef data = SecCertificateCopyData(native);
    if (!data) return;
    const unsigned char* cursor = CFDataGetBytePtr(data);
    Cert certificate(d2i_X509(nullptr, &cursor, CFDataGetLength(data)), X509_free);
    CFRelease(data);
    if (!certificate) return;
    if (metadata_only) {
        add_trust(store, certificate.get());
        return;
    }
    const int code = apple_setting(native, false), timestamp = apple_setting(native, true);
    if ((requested_timestamp ? timestamp : code) < 0)
        distrusted.insert(certificate_key(certificate.get()));
    if (!default_anchor && code != 1 && timestamp != 1) return;
    if (code < 0 || (!default_anchor && code != 1))
        X509_add1_reject_object(certificate.get(), OBJ_nid2obj(NID_code_sign));
    if (timestamp < 0 || (!default_anchor && timestamp != 1))
        X509_add1_reject_object(certificate.get(), OBJ_nid2obj(NID_time_stamp));
    if (code >= 0 && (default_anchor || code == 1))
        X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_code_sign));
    if (timestamp >= 0 && (default_anchor || timestamp == 1))
        X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_time_stamp));
    X509_add1_trust_object(certificate.get(), OBJ_nid2obj(NID_ad_OCSP));
    add_trust(store, certificate.get());
}

void load_apple_roots(X509_STORE* store, std::vector<std::string>& details,
    bool timestamp, std::set<std::string>& distrusted, bool metadata_only = false) {
    CFArrayRef anchors = nullptr;
    if (SecTrustCopyAnchorCertificates(&anchors) == errSecSuccess && anchors) {
        for (CFIndex index = 0; index < CFArrayGetCount(anchors); ++index)
            add_apple_root(store, static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(anchors, index))), true, timestamp, distrusted, metadata_only);
        CFRelease(anchors);
    } else {
        detail(details, "macOS trusted root certificates are unavailable");
    }
    for (auto domain : {kSecTrustSettingsDomainUser, kSecTrustSettingsDomainAdmin,
            kSecTrustSettingsDomainSystem}) {
        CFArrayRef certificates = nullptr;
        if (SecTrustSettingsCopyCertificates(domain, &certificates) != errSecSuccess || !certificates) continue;
        for (CFIndex index = 0; index < CFArrayGetCount(certificates); ++index)
            add_apple_root(store, static_cast<SecCertificateRef>(const_cast<void*>(CFArrayGetValueAtIndex(certificates, index))), false, timestamp, distrusted, metadata_only);
        CFRelease(certificates);
    }
}

void load_apple_intermediates(std::vector<Cert>& certificates, bool timestamp,
    std::set<std::string>& distrusted) {
    const void* keys[] = {kSecClass, kSecMatchLimit, kSecReturnRef};
    const void* values[] = {kSecClassCertificate, kSecMatchLimitAll, kCFBooleanTrue};
    CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!query) return;
    CFTypeRef result = nullptr;
    const OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status != errSecSuccess || !result) return;
    if (CFGetTypeID(result) == CFArrayGetTypeID()) {
        const auto items = static_cast<CFArrayRef>(result);
        for (CFIndex index = 0; index < CFArrayGetCount(items) && certificates.size() < 512; ++index) {
            const auto value = CFArrayGetValueAtIndex(items, index);
            if (CFGetTypeID(value) != SecCertificateGetTypeID()) continue;
            const auto native = static_cast<SecCertificateRef>(const_cast<void*>(value));
            CFDataRef data = SecCertificateCopyData(native);
            if (!data) continue;
            const unsigned char* cursor = CFDataGetBytePtr(data);
            Cert certificate(d2i_X509(nullptr, &cursor, CFDataGetLength(data)), X509_free);
            CFRelease(data);
            if (!certificate || X509_check_ca(certificate.get()) <= 0) continue;
            if (apple_setting(native, timestamp) < 0)
                distrusted.insert(certificate_key(certificate.get()));
            certificates.push_back(std::move(certificate));
        }
    }
    CFRelease(result);
}
#endif

void load_certificate_store(X509_STORE* store, const Options& options,
    std::vector<std::string>& details, std::set<std::string>& distrusted,
    bool timestamp, bool metadata_only = false) {
    if (options.use_system_roots) {
#ifdef _WIN32
        (void)timestamp;
        load_windows_roots(store, details, distrusted, metadata_only);
#elif defined(__APPLE__)
        load_apple_roots(store, details, timestamp, distrusted, metadata_only);
#else
        (void)timestamp;
        (void)metadata_only;
        (void)distrusted;
#endif
        if (X509_STORE_set_default_paths(store) != 1) {
            detail(details, "OpenSSL default trust paths are unavailable");
            ERR_clear_error();
        }
    }
    if (!options.ca_file.empty()) load_ca_file(store, options.ca_file, details);
    if (!options.ca_directory.empty()) {
        read_directory(options.ca_directory, 4096, [&](const auto& file) {
            load_ca_file(store, file, details);
        }, details);
    }
}

void load_intermediate_candidates(STACK_OF(X509)* candidates,
    std::set<std::string>& seen, const Options& options, bool timestamp,
    std::set<std::string>& distrusted) {
    if (!options.use_system_roots) return;
    std::vector<Cert> intermediates;
#ifdef _WIN32
    load_windows_intermediates(intermediates, timestamp, distrusted);
#elif defined(__APPLE__)
    load_apple_intermediates(intermediates, timestamp, distrusted);
#else
    (void)timestamp;
    (void)distrusted;
#endif
    for (const auto& certificate : intermediates)
        append_candidate(candidates, seen, certificate.get());
}

bool usage_allowed(X509* certificate, bool timestamp, bool leaf, bool rfc3161) {
    int critical = -1;
    Handle<EXTENDED_KEY_USAGE, EXTENDED_KEY_USAGE_free> eku(
        static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(certificate, NID_ext_key_usage, &critical, nullptr)),
        EXTENDED_KEY_USAGE_free);
    if (!eku && critical != -1) return false; // Duplicate or malformed extension.
    if (eku) {
        bool permitted = false;
        for (int index = 0; index < sk_ASN1_OBJECT_num(eku.get()); ++index) {
            const int nid = OBJ_obj2nid(sk_ASN1_OBJECT_value(eku.get(), index));
            permitted |= nid == (timestamp ? NID_time_stamp : NID_code_sign) ||
                (!leaf && nid == NID_anyExtendedKeyUsage) || (!timestamp && nid == NID_anyExtendedKeyUsage);
        }
        if (!permitted) return false;
    } else if (timestamp && leaf) {
        return false;
    }
    if (timestamp && leaf && rfc3161 && sk_ASN1_OBJECT_num(eku.get()) != 1) return false;
    const auto key_usage = X509_get_key_usage(certificate);
    return !leaf || key_usage == UINT32_MAX ||
        (key_usage & (KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION)) != 0;
}

std::vector<std::string> aia_urls(X509* certificate, int method) {
    std::vector<std::string> urls;
    Handle<AUTHORITY_INFO_ACCESS, AUTHORITY_INFO_ACCESS_free> aia(
        static_cast<AUTHORITY_INFO_ACCESS*>(X509_get_ext_d2i(certificate, NID_info_access, nullptr, nullptr)),
        AUTHORITY_INFO_ACCESS_free);
    if (!aia) return urls;
    for (int index = 0; index < sk_ACCESS_DESCRIPTION_num(aia.get()) && urls.size() < max_urls; ++index) {
        const auto* description = sk_ACCESS_DESCRIPTION_value(aia.get(), index);
        if (!description || OBJ_obj2nid(description->method) != method ||
            !description->location || description->location->type != GEN_URI) continue;
        const auto* uri = description->location->d.uniformResourceIdentifier;
        const int length = ASN1_STRING_length(uri);
        if (length <= 0 || length > 4096) continue;
        std::string value(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri)), static_cast<std::size_t>(length));
        if (value.find('\0') == std::string::npos) urls.push_back(std::move(value));
    }
    return urls;
}

bool issuer_matches(X509* issuer, X509* certificate) {
    if (X509_check_issued(issuer, certificate) != X509_V_OK) return false;
    auto* key = X509_get0_pubkey(issuer);
    const bool verified = key && X509_verify(certificate, key) == 1;
    ERR_clear_error();
    return verified;
}

bool metadata_issuer_matches(X509* issuer, X509* certificate) {
    // Metadata describes a cryptographic issuer relationship, including chains
    // whose certificate usage would not permit verification of code signatures.
    const auto issued = X509_check_issued(issuer, certificate);
    if (issued != X509_V_OK && issued != X509_V_ERR_KEYUSAGE_NO_CERTSIGN) return false;
    auto* key = X509_get0_pubkey(issuer);
    const bool verified = key && X509_verify(certificate, key) == 1;
    ERR_clear_error();
    return verified;
}

void append_chain_metadata(ChainResult& result, X509* certificate) {
    result.chain.push_back(certificate_metadata(certificate));
    const int size = i2d_X509(certificate, nullptr);
    if (size > 0 && size <= 1024 * 1024) {
        std::vector<std::uint8_t> encoded(static_cast<std::size_t>(size));
        auto* cursor = encoded.data();
        if (i2d_X509(certificate, &cursor) == size)
            result.encoded_chain.push_back(std::move(encoded));
    }
}

std::vector<std::string> distribution_urls(CRL_DIST_POINTS* points) {
    std::vector<std::string> urls;
    if (!points) return urls;
    for (int index = 0; index < sk_DIST_POINT_num(points) && urls.size() < max_urls; ++index) {
        auto* point = sk_DIST_POINT_value(points, index);
        if (!point || !point->distpoint || point->distpoint->type != 0 || point->CRLissuer || point->reasons) continue;
        auto* names = point->distpoint->name.fullname;
        for (int name_index = 0; name_index < sk_GENERAL_NAME_num(names) && urls.size() < max_urls; ++name_index) {
            auto* name = sk_GENERAL_NAME_value(names, name_index);
            if (!name || name->type != GEN_URI) continue;
            const int length = ASN1_STRING_length(name->d.uniformResourceIdentifier);
            if (length <= 0 || length > 4096) continue;
            std::string value(reinterpret_cast<const char*>(ASN1_STRING_get0_data(name->d.uniformResourceIdentifier)), length);
            if (value.find('\0') == std::string::npos) urls.push_back(std::move(value));
        }
    }
    return urls;
}

std::vector<std::string> crl_urls(X509* certificate, int nid = NID_crl_distribution_points) {
    Handle<CRL_DIST_POINTS, CRL_DIST_POINTS_free> points(
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(certificate, nid, nullptr, nullptr)), CRL_DIST_POINTS_free);
    return distribution_urls(points.get());
}

std::vector<std::string> freshest_urls(X509_CRL* crl) {
    Handle<CRL_DIST_POINTS, CRL_DIST_POINTS_free> points(
        static_cast<CRL_DIST_POINTS*>(X509_CRL_get_ext_d2i(crl, NID_freshest_crl, nullptr, nullptr)),
        CRL_DIST_POINTS_free);
    return distribution_urls(points.get());
}

bool crl_fresh(X509_CRL* crl, std::time_t now) {
    const auto* last = X509_CRL_get0_lastUpdate(crl);
    const auto* next = X509_CRL_get0_nextUpdate(crl);
    return last && next && ASN1_TIME_check(last) && ASN1_TIME_check(next) &&
        ASN1_TIME_compare(last, next) < 0 &&
        ASN1_TIME_cmp_time_t(last, now + freshness_slack) <= 0 &&
        ASN1_TIME_cmp_time_t(next, now - freshness_slack) >= 0;
}

bool crl_scope_matches(X509_CRL* crl, X509* certificate) {
    int critical = -1;
    Handle<ISSUING_DIST_POINT, ISSUING_DIST_POINT_free> scope(
        static_cast<ISSUING_DIST_POINT*>(X509_CRL_get_ext_d2i(crl,
            NID_issuing_distribution_point, &critical, nullptr)), ISSUING_DIST_POINT_free);
    if (!scope) return critical == -1;
    // A direct CRL with a complete reason set can prove good status. Indirect
    // CRLs and reason partitions require additional issuer/coverage state and
    // are left unknown until that state can be authenticated.
    if (scope->indirectCRL || scope->onlyattr || scope->onlysomereasons ||
        (scope->onlyuser && scope->onlyCA)) return false;
    const bool ca = X509_check_ca(certificate) > 0;
    if ((scope->onlyuser && ca) || (scope->onlyCA && !ca)) return false;
    if (!scope->distpoint) return true;
    if (scope->distpoint->type != 0) return false;
    Handle<CRL_DIST_POINTS, CRL_DIST_POINTS_free> points(
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(certificate,
            NID_crl_distribution_points, nullptr, nullptr)), CRL_DIST_POINTS_free);
    if (!points) return false;
    auto* required = scope->distpoint->name.fullname;
    for (int index = 0; index < sk_DIST_POINT_num(points.get()); ++index) {
        auto* point = sk_DIST_POINT_value(points.get(), index);
        if (!point || point->CRLissuer || point->reasons || !point->distpoint || point->distpoint->type != 0) continue;
        auto* names = point->distpoint->name.fullname;
        for (int left = 0; left < sk_GENERAL_NAME_num(required); ++left)
            for (int right = 0; right < sk_GENERAL_NAME_num(names); ++right)
                if (GENERAL_NAME_cmp(sk_GENERAL_NAME_value(required, left),
                        sk_GENERAL_NAME_value(names, right)) == 0) return true;
    }
    return false;
}

std::string check_crl(X509_CRL* crl, X509* certificate, X509* issuer,
    std::time_t verification_time, std::time_t now, bool allow_delta = false) {
    if (X509_NAME_cmp(X509_CRL_get_issuer(crl), X509_get_subject_name(issuer)) != 0 ||
        !crl_fresh(crl, now)) return "unknown";
    const auto key_usage = X509_get_key_usage(issuer);
    if (key_usage != UINT32_MAX && !(key_usage & KU_CRL_SIGN)) return "unknown";
    if (!allow_delta && X509_CRL_get_ext_by_NID(crl, NID_delta_crl, -1) >= 0) return "unknown";
    if (!crl_scope_matches(crl, certificate)) return "unknown";
    for (int index = 0; index < X509_CRL_get_ext_count(crl); ++index) {
        auto* extension = X509_CRL_get_ext(crl, index);
        if (X509_EXTENSION_get_critical(extension) &&
            OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_authority_key_identifier &&
            OBJ_obj2nid(X509_EXTENSION_get_object(extension)) != NID_issuing_distribution_point &&
            !(allow_delta && OBJ_obj2nid(X509_EXTENSION_get_object(extension)) == NID_delta_crl))
            return "unknown";
    }
    int critical = -1;
    Handle<AUTHORITY_KEYID, AUTHORITY_KEYID_free> authority(
        static_cast<AUTHORITY_KEYID*>(X509_CRL_get_ext_d2i(crl, NID_authority_key_identifier, &critical, nullptr)),
        AUTHORITY_KEYID_free);
    if ((!authority && critical != -1) || (authority && X509_check_akid(issuer, authority.get()) != X509_V_OK))
        return "unknown";
    EVP_PKEY* key = X509_get0_pubkey(issuer);
    if (!key || X509_CRL_verify(crl, key) != 1) {
        ERR_clear_error();
        return "unknown";
    }
    X509_REVOKED* revoked = nullptr;
    const int status = X509_CRL_get0_by_cert(crl, &revoked, certificate);
    if (status == 0) return "good";
    const auto* date = revoked ? X509_REVOKED_get0_revocationDate(revoked) : nullptr;
    if (!date || !ASN1_TIME_check(date)) return "unknown";
    for (int index = 0; index < X509_REVOKED_get_ext_count(revoked); ++index) {
        auto* extension = X509_REVOKED_get_ext(revoked, index);
        if (X509_EXTENSION_get_critical(extension)) return "unknown";
    }
    if (status == 2) return allow_delta && ASN1_TIME_cmp_time_t(date, verification_time) <= 0 ?
        "remove" : "unknown";
    return ASN1_TIME_cmp_time_t(date, verification_time) <= 0 ? "revoked" : "good";
}

Handle<ASN1_INTEGER, ASN1_INTEGER_free> crl_number(X509_CRL* crl, int nid) {
    if (!crl) return {nullptr, ASN1_INTEGER_free};
    int critical = -1;
    Handle<ASN1_INTEGER, ASN1_INTEGER_free> number(
        static_cast<ASN1_INTEGER*>(X509_CRL_get_ext_d2i(crl, nid, &critical, nullptr)), ASN1_INTEGER_free);
    auto zero = Handle<ASN1_INTEGER, ASN1_INTEGER_free>(ASN1_INTEGER_new(), ASN1_INTEGER_free);
    if (!number || !zero || ASN1_INTEGER_set(zero.get(), 0) != 1 ||
        ASN1_INTEGER_cmp(number.get(), zero.get()) < 0 || (nid == NID_delta_crl && critical != 1))
        number.reset();
    return number;
}

bool matching_crl_extension(X509_CRL* left, X509_CRL* right, int nid) {
    const int a = X509_CRL_get_ext_by_NID(left, nid, -1);
    const int b = X509_CRL_get_ext_by_NID(right, nid, -1);
    if (a < 0 || b < 0) return a == b;
    if (X509_CRL_get_ext_by_NID(left, nid, a) >= 0 ||
        X509_CRL_get_ext_by_NID(right, nid, b) >= 0) return false;
    return ASN1_OCTET_STRING_cmp(X509_EXTENSION_get_data(X509_CRL_get_ext(left, a)),
        X509_EXTENSION_get_data(X509_CRL_get_ext(right, b))) == 0;
}

std::string check_crl_set(const std::vector<Crl>& crls, X509* certificate,
    X509* issuer, std::time_t verification_time, std::time_t now) {
    X509_CRL* base = nullptr;
    std::string base_status = "unknown";
    // Each selected full CRL covers this certificate for all reasons. Prefer
    // the most recently issued complete list before applying its newest delta.
    for (const auto& crl : crls) {
        if (X509_CRL_get_ext_by_NID(crl.get(), NID_delta_crl, -1) >= 0) continue;
        const auto status = check_crl(crl.get(), certificate, issuer, verification_time, now);
        if (status == "unknown") continue;
        const int order = base ? ASN1_TIME_compare(X509_CRL_get0_lastUpdate(crl.get()),
            X509_CRL_get0_lastUpdate(base)) : 1;
        auto candidate_number = crl_number(crl.get(), NID_crl_number);
        auto old_number = crl_number(base, NID_crl_number);
        if (!base || order > 0 || (order == 0 && candidate_number && old_number &&
                ASN1_INTEGER_cmp(candidate_number.get(), old_number.get()) > 0)) {
            base = crl.get();
            base_status = status;
        }
    }
    auto base_number = crl_number(base, NID_crl_number);
    X509_CRL* newest_delta = nullptr;
    Handle<ASN1_INTEGER, ASN1_INTEGER_free> newest_number(nullptr, ASN1_INTEGER_free);
    bool unresolved_delta = false;
    for (const auto& crl : crls) {
        if (X509_CRL_get_ext_by_NID(crl.get(), NID_delta_crl, -1) < 0) continue;
        const auto status = check_crl(crl.get(), certificate, issuer, verification_time, now, true);
        if (status == "unknown") continue;
        auto indicator = crl_number(crl.get(), NID_delta_crl);
        auto number = crl_number(crl.get(), NID_crl_number);
        if (!base || !base_number || !indicator || !number) {
            unresolved_delta = true;
            continue;
        }
        if (ASN1_INTEGER_cmp(number.get(), base_number.get()) <= 0) continue; // Superseded by the full list.
        if (ASN1_INTEGER_cmp(indicator.get(), base_number.get()) > 0 ||
            !matching_crl_extension(crl.get(), base, NID_authority_key_identifier) ||
            !matching_crl_extension(crl.get(), base, NID_issuing_distribution_point)) {
            unresolved_delta = true;
            continue;
        }
        if (!newest_delta || ASN1_INTEGER_cmp(number.get(), newest_number.get()) > 0) {
            newest_delta = crl.get();
            newest_number = std::move(number);
        }
    }
    if (unresolved_delta) return "unknown";
    if (!base || !newest_delta) return base_status;
    X509_REVOKED* entry = nullptr;
    const int found = X509_CRL_get0_by_cert(newest_delta, &entry, certificate);
    if (!found) return base_status; // A delta omits unchanged entries.
    if (found == 2) {
        X509_REVOKED* old_entry = nullptr;
        if (X509_CRL_get0_by_cert(base, &old_entry, certificate) != 1 || !old_entry ||
            verification_time < 0 ||
            ASN1_TIME_cmp_time_t(X509_CRL_get0_lastUpdate(newest_delta), verification_time) > 0)
            return "unknown";
        int critical = -1;
        Handle<ASN1_ENUMERATED, ASN1_ENUMERATED_free> reason(
            static_cast<ASN1_ENUMERATED*>(X509_REVOKED_get_ext_d2i(old_entry,
                NID_crl_reason, &critical, nullptr)), ASN1_ENUMERATED_free);
        // removeFromCRL releases certificateHold, never a key-compromise revocation.
        return reason && critical == 0 && ASN1_ENUMERATED_get(reason.get()) == CRL_REASON_CERTIFICATE_HOLD ?
            "good" : "unknown";
    }
    const auto delta_status = check_crl(newest_delta, certificate, issuer, verification_time, now, true);
    // A later revocation date cannot erase an authenticated earlier revocation.
    return base_status == "revoked" ? "revoked" : delta_status;
}

std::string check_ocsp(const std::vector<std::uint8_t>& bytes, OCSP_CERTID* expected,
    OCSP_REQUEST* request, X509_STORE* store, STACK_OF(X509)* chain,
    std::time_t verification_time, std::time_t now) {
    if (bytes.empty() || bytes.size() > download_limit) return "unknown";
    const auto* cursor = bytes.data();
    Handle<OCSP_RESPONSE, OCSP_RESPONSE_free> response(
        d2i_OCSP_RESPONSE(nullptr, &cursor, static_cast<long>(bytes.size())), OCSP_RESPONSE_free);
    if (!response || cursor != bytes.data() + bytes.size() ||
        OCSP_response_status(response.get()) != OCSP_RESPONSE_STATUS_SUCCESSFUL) return "unknown";
    Handle<OCSP_BASICRESP, OCSP_BASICRESP_free> basic(OCSP_response_get1_basic(response.get()), OCSP_BASICRESP_free);
    if (!basic || OCSP_basic_verify(basic.get(), chain, store, 0) != 1) {
        ERR_clear_error();
        return "unknown";
    }
    if (request) {
        const int nonce = OCSP_check_nonce(request, basic.get());
        if (nonce != 1 && nonce != -1) return "unknown";
        // Responders that omit nonces are usable only with the signed freshness checks below.
    }
    for (int index = 0; index < OCSP_BASICRESP_get_ext_count(basic.get()); ++index) {
        if (X509_EXTENSION_get_critical(OCSP_BASICRESP_get_ext(basic.get(), index))) return "unknown";
    }
    int status = V_OCSP_CERTSTATUS_UNKNOWN, reason = 0;
    ASN1_GENERALIZEDTIME *revocation = nullptr, *this_update = nullptr, *next_update = nullptr;
    const int single_index = OCSP_resp_find(basic.get(), expected, -1);
    if (single_index < 0 || OCSP_resp_find(basic.get(), expected, single_index) >= 0) return "unknown";
    auto* single = OCSP_resp_get0(basic.get(), single_index);
    for (int index = 0; index < OCSP_SINGLERESP_get_ext_count(single); ++index)
        if (X509_EXTENSION_get_critical(OCSP_SINGLERESP_get_ext(single, index))) return "unknown";
    if (!OCSP_resp_find_status(basic.get(), expected, &status, &reason,
            &revocation, &this_update, &next_update) || !this_update ||
        !ASN1_TIME_check(this_update) || (next_update && !ASN1_TIME_check(next_update))) return "unknown";
    const auto* produced = OCSP_resp_get0_produced_at(basic.get());
    if (!produced || !ASN1_TIME_check(produced) ||
        ASN1_TIME_cmp_time_t(produced, now + freshness_slack) > 0 ||
        ASN1_TIME_cmp_time_t(produced, now - ocsp_max_age) < 0 ||
        ASN1_TIME_cmp_time_t(this_update, now + freshness_slack) > 0 ||
        ASN1_TIME_cmp_time_t(this_update, now - ocsp_max_age) < 0 ||
        (next_update && (ASN1_TIME_compare(this_update, next_update) > 0 ||
            ASN1_TIME_cmp_time_t(next_update, now - freshness_slack) < 0))) return "unknown";
    if (status == V_OCSP_CERTSTATUS_GOOD) return "good";
    if (status != V_OCSP_CERTSTATUS_REVOKED || !revocation || !ASN1_TIME_check(revocation)) return "unknown";
    return ASN1_TIME_cmp_time_t(revocation, verification_time) <= 0 ? "revoked" : "good";
}

std::string check_revocation(X509* certificate, X509* issuer, X509_STORE* store,
    STACK_OF(X509)* chain, const Options& options, const std::vector<Crl>& local_crls,
    std::time_t verification_time, std::time_t now, RetrievalBudget& budget,
    std::vector<std::string>& details) {
    std::vector<Crl> collected;
    for (const auto& crl : local_crls) {
        if (X509_CRL_up_ref(crl.get()) == 1) collected.emplace_back(crl.get(), X509_CRL_free);
    }
    std::vector<std::pair<std::string, bool>> urls;
    std::set<std::string> unique_urls;
    const auto add_url = [&](const std::string& url, bool delta) {
        if (urls.size() < 2 * max_urls && unique_urls.insert(url).second) urls.emplace_back(url, delta);
    };
    for (const auto& url : crl_urls(certificate)) add_url(url, false);
    for (const auto& url : crl_urls(certificate, NID_freshest_crl)) add_url(url, true);
    const auto discover_deltas = [&] {
        for (const auto& crl : collected) {
            if (check_crl(crl.get(), certificate, issuer, verification_time, now) == "unknown") continue;
            for (const auto& url : freshest_urls(crl.get())) add_url(url, true);
        }
    };
    discover_deltas();
    std::string result = check_crl_set(collected, certificate, issuer, verification_time, now);
    for (std::size_t index = 0; index < urls.size(); ++index) {
        const auto url = urls[index].first;
        const bool delta_url = urls[index].second;
        const auto file = cache_file(options, "crl:" + url, ".crl");
        std::vector<Crl> crls;
        decode_crls(file.empty() ? std::vector<std::uint8_t>{} : read_trust_file(file, download_limit), crls);
        for (const auto& crl : crls) {
            if (X509_CRL_up_ref(crl.get()) == 1) collected.emplace_back(crl.get(), X509_CRL_free);
        }
        discover_deltas();
        result = check_crl_set(collected, certificate, issuer, verification_time, now);
        const unsigned timeout = budget.timeout();
        if ((!delta_url && result != "unknown") || options.revocation != RevocationMode::online || timeout == 0) continue;
        ++budget.requests;
        const auto response = http_request(url, {}, {}, timeout, download_limit);
        if (!response.success) { detail(details, "CRL retrieval failed: " + response.error); continue; }
        crls.clear();
        decode_crls(response.body, crls);
        bool accepted = false;
        for (const auto& crl : crls) {
            const auto status = check_crl(crl.get(), certificate, issuer, verification_time, now, true);
            accepted |= status != "unknown";
            if (X509_CRL_up_ref(crl.get()) == 1) collected.emplace_back(crl.get(), X509_CRL_free);
        }
        if (accepted) write_cache(file, response.body, details);
        discover_deltas();
        result = check_crl_set(collected, certificate, issuer, verification_time, now);
    }
    if (result == "revoked") return result;
    Handle<OCSP_CERTID, OCSP_CERTID_free> id(OCSP_cert_to_id(EVP_sha1(), certificate, issuer), OCSP_CERTID_free);
    if (!id) return result;
    const int id_size = i2d_OCSP_CERTID(id.get(), nullptr);
    if (id_size <= 0) return result;
    std::vector<std::uint8_t> id_bytes(static_cast<std::size_t>(id_size));
    auto* cursor = id_bytes.data();
    if (i2d_OCSP_CERTID(id.get(), &cursor) != id_size) return result;
    const std::string identity = hex_digest(id_bytes.data(), id_bytes.size());
    for (const auto& url : aia_urls(certificate, NID_ad_OCSP)) {
        const auto file = cache_file(options, "ocsp:" + url + ":" + identity, ".ocsp");
        const auto cached = file.empty() ? std::vector<std::uint8_t>{} : read_trust_file(file, download_limit);
        const auto cached_status = check_ocsp(cached, id.get(), nullptr, store, chain, verification_time, now);
        if (cached_status == "revoked") return cached_status;
        if (cached_status == "good") result = "good";
        const unsigned timeout = budget.timeout();
        if (result == "good" || options.revocation != RevocationMode::online || timeout == 0) continue;
        Handle<OCSP_REQUEST, OCSP_REQUEST_free> request(OCSP_REQUEST_new(), OCSP_REQUEST_free);
        if (!request) continue;
        OCSP_CERTID* copy = OCSP_CERTID_dup(id.get());
        if (!copy) continue;
        if (!OCSP_request_add0_id(request.get(), copy)) { OCSP_CERTID_free(copy); continue; }
        if (OCSP_request_add1_nonce(request.get(), nullptr, 16) != 1) continue;
        const int size = i2d_OCSP_REQUEST(request.get(), nullptr);
        if (size <= 0 || size > 64 * 1024) continue;
        std::vector<std::uint8_t> request_bytes(static_cast<std::size_t>(size));
        cursor = request_bytes.data();
        if (i2d_OCSP_REQUEST(request.get(), &cursor) != size) continue;
        ++budget.requests;
        const auto response = http_request(url, request_bytes, "application/ocsp-request", timeout, download_limit);
        if (!response.success) { detail(details, "OCSP retrieval failed: " + response.error); continue; }
        const auto status = check_ocsp(response.body, id.get(), request.get(), store, chain, verification_time, now);
        if (status != "unknown") write_cache(file, response.body, details);
        if (status == "revoked") return status;
        if (status == "good") result = status;
    }
    return result;
}

} // namespace

ChainResult build_certificate_chain(X509* signer, STACK_OF(X509)* untrusted,
    const Options& options) {
    ChainResult result;
    result.status = "unavailable";
    if (!signer) {
        result.error_code = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
        detail(result.details, "Signer certificate is missing");
        return result;
    }
    Handle<X509_STORE, X509_STORE_free> store(X509_STORE_new(), X509_STORE_free);
    Handle<X509_STORE_CTX, X509_STORE_CTX_free> context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    auto candidates = certificate_stack();
    if (!store || !context || !candidates) {
        detail(result.details, "Cannot allocate OpenSSL certificate chain builder");
        return result;
    }
    std::set<std::string> distrusted, seen;
    load_certificate_store(store.get(), options, result.details, distrusted, false, true);
    for (int index = 0; index < sk_X509_num(untrusted); ++index)
        append_candidate(candidates.get(), seen, sk_X509_value(untrusted, index));
    load_intermediate_candidates(candidates.get(), seen, options, false, distrusted);
    if (X509_STORE_CTX_init(context.get(), store.get(), signer, candidates.get()) != 1) {
        detail(result.details, "Cannot initialize OpenSSL certificate chain builder");
        ERR_clear_error();
        return result;
    }

    std::vector<X509*> path;
    std::vector<Cert> best;
    std::set<std::string> path_keys, fetched;
    std::size_t visits = 0, cache_reads = 0;
    bool cycle = false, depth_limit = false, search_limit = false, cache_limit = false;
    bool allocation_failed = false, rejected_issuer = false;
    const auto remember = [&]() {
        if (path.size() <= best.size()) return;
        std::vector<Cert> saved;
        for (auto* certificate : path) {
            if (X509_up_ref(certificate) != 1) { allocation_failed = true; return; }
            saved.emplace_back(certificate, X509_free);
        }
        best = std::move(saved);
    };
    const auto walk = [&](const auto& self, X509* certificate) -> bool {
        if (visits++ >= 512) { search_limit = true; return false; }
        const auto key = certificate_key(certificate);
        if (key.empty()) return false;
        if (!path_keys.insert(key).second) { cycle = true; return false; }
        path.push_back(certificate);
        remember();
        const bool self_signed = X509_self_signed(certificate, 1) == 1;
        ERR_clear_error();
        if (self_signed) {
            // The first complete path can be shorter than a failed branch.
            best.clear();
            remember();
            path.pop_back();
            path_keys.erase(key);
            return !allocation_failed;
        }
        if (path.size() >= max_metadata_chain_depth) {
            depth_limit = true;
            path.pop_back();
            path_keys.erase(key);
            return false;
        }

        std::vector<X509*> issuers;
        std::set<std::string> offered;
        const auto offer = [&](X509* issuer) {
            if (!issuer || issuers.size() >= 512) return;
            if (X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(certificate)) != 0) return;
            if (!metadata_issuer_matches(issuer, certificate)) { rejected_issuer = true; return; }
            const auto identity = certificate_key(issuer);
            if (!identity.empty() && offered.insert(identity).second) issuers.push_back(issuer);
        };
        // get1_certs performs subject lookups as well as reading already loaded
        // objects, so OpenSSL's lazily loaded hashed CA directories also work.
        auto matches = certificate_stack(X509_STORE_CTX_get1_certs(
            context.get(), X509_get_issuer_name(certificate)));
        ERR_clear_error();
        if (matches) {
            for (int index = 0; index < sk_X509_num(matches.get()); ++index)
                offer(sk_X509_value(matches.get(), index));
        }
        for (int index = 0; index < sk_X509_num(candidates.get()); ++index)
            offer(sk_X509_value(candidates.get(), index));
        bool complete = false;
        for (auto* issuer : issuers) {
            if (self(self, issuer)) { complete = true; break; }
        }
        if (!complete && !search_limit) {
            // Cached AIA responses are additional local certificate bags. No
            // network or revocation checks are performed during metadata parsing.
            std::vector<Cert> cached;
            for (const auto& url : aia_urls(certificate, NID_ad_ca_issuers)) {
                if (!fetched.insert(url).second) continue;
                if (cache_reads >= max_requests) { cache_limit = true; break; }
                ++cache_reads;
                const auto file = cache_file(options, "issuer:" + url, ".cer");
                if (!file.empty()) decode_certificates(read_trust_file(file, download_limit), cached, true);
                for (const auto& issuer : cached) append_candidate(candidates.get(), seen, issuer.get());
                const auto start = issuers.size();
                for (const auto& issuer : cached) offer(issuer.get());
                for (std::size_t index = start; index < issuers.size(); ++index) {
                    if (self(self, issuers[index])) { complete = true; break; }
                }
                if (complete || search_limit) break;
                // Remove borrowed cache pointers before their owning bag is freed.
                issuers.resize(start);
                cached.clear();
            }
        }
        path.pop_back();
        path_keys.erase(key);
        return complete;
    };
    const bool complete = walk(walk, signer);
    for (const auto& certificate : best) append_chain_metadata(result, certificate.get());
    if (best.empty()) {
        detail(result.details, allocation_failed ? "Cannot retain certificate chain metadata" :
            "Cannot read signer certificate identity");
        return result;
    }
    result.status = complete ? "built" : "partial";
    result.error_code = complete ? X509_V_OK : X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
    detail(result.details, "Certificate chain metadata is ordered by verified issuer signatures; validity, purpose, trust and revocation were not checked");
    if (complete) {
        detail(result.details, "Chain reaches a cryptographically confirmed self-signed root; this does not establish trust");
    } else {
        detail(result.details, "Complete root chain is unavailable from embedded certificates, configured CA sources, system stores and local AIA cache; last available certificate issuer: " +
            result.chain.back().issuer);
        if (rejected_issuer) detail(result.details, "An issuer candidate failed certificate signature or authority identifier checks");
        if (cycle) detail(result.details, "Certificate issuer cycle was excluded");
        if (depth_limit) detail(result.details, "Certificate chain metadata depth was limited to 64");
        if (search_limit || sk_X509_num(candidates.get()) >= 512)
            detail(result.details, "Certificate chain metadata candidate search was limited to 512");
        if (cache_limit) detail(result.details, "Local AIA cache lookup was limited to 32 responses");
    }
    ERR_clear_error();
    return result;
}

ChainResult verify_chain(X509* signer, STACK_OF(X509)* untrusted,
    const Options& options, std::optional<std::time_t> signing_time, bool timestamp,
    STACK_OF(X509_CRL)* embedded_crls, bool rfc3161) {
    ChainResult result;
    result.revocation = options.revocation == RevocationMode::none ? "not_checked" : "unknown";
    if (!signer) {
        result.error_code = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
        detail(result.details, "Signer certificate is missing");
        return result;
    }
    Handle<X509_STORE, X509_STORE_free> store(X509_STORE_new(), X509_STORE_free);
    Handle<X509_STORE_CTX, X509_STORE_CTX_free> context(X509_STORE_CTX_new(), X509_STORE_CTX_free);
    if (!store || !context) {
        result.status = "error";
        detail(result.details, "Cannot allocate OpenSSL certificate verifier");
        return result;
    }
    std::set<std::string> distrusted;
    load_certificate_store(store.get(), options, result.details, distrusted, timestamp);
    std::vector<Crl> local_crls;
    if (options.revocation != RevocationMode::none) {
        for (int index = 0; index < sk_X509_CRL_num(embedded_crls) && local_crls.size() < 256; ++index) {
            auto* crl = sk_X509_CRL_value(embedded_crls, index);
            if (crl && X509_CRL_up_ref(crl) == 1) local_crls.emplace_back(crl, X509_CRL_free);
        }
        if (!options.crl_file.empty()) {
            decode_crls(read_trust_file(options.crl_file), local_crls);
            if (local_crls.empty()) detail(result.details, "Cannot decode configured CRL file");
        }
        if (!options.crl_directory.empty()) {
            read_directory(options.crl_directory, 256, [&](const auto& file) {
                decode_crls(read_trust_file(file), local_crls);
            }, result.details);
        }
    }
    auto candidates = certificate_stack();
    if (!candidates) {
        result.status = "error";
        return result;
    }
    std::set<std::string> seen;
    const auto append = [&](X509* certificate) {
        return append_candidate(candidates.get(), seen, certificate);
    };
    for (int index = 0; index < sk_X509_num(untrusted); ++index) append(sk_X509_value(untrusted, index));
    load_intermediate_candidates(candidates.get(), seen, options, timestamp, distrusted);
    std::time_t now = options.verification_time ? options.verification_time : std::time(nullptr);
    const auto check_time = signing_time.value_or(now);
    RetrievalBudget budget{0, std::chrono::steady_clock::now() +
        std::chrono::seconds(std::clamp(options.network_timeout_seconds, 1u, 300u))};
    std::set<std::string> fetched;
    bool trusted = false;
    for (std::size_t attempt = 0; attempt <= max_chain_depth; ++attempt) {
        X509_STORE_CTX_cleanup(context.get());
        if (X509_STORE_CTX_init(context.get(), store.get(), signer, candidates.get()) != 1) break;
        auto* parameters = X509_STORE_CTX_get0_param(context.get());
        X509_VERIFY_PARAM_set_time(parameters, check_time);
        X509_VERIFY_PARAM_set_depth(parameters, static_cast<int>(max_chain_depth));
        X509_VERIFY_PARAM_set_flags(parameters, X509_V_FLAG_TRUSTED_FIRST);
        // The code signing purpose was only added in OpenSSL 3.4. On 3.0,
        // generic chain validation is followed by explicit full-chain EKU/KU checks.
        X509_STORE_CTX_set_purpose(context.get(), X509_PURPOSE_ANY);
        X509_STORE_CTX_set_trust(context.get(), timestamp ? X509_TRUST_TSA : X509_TRUST_OBJECT_SIGN);
        trusted = X509_verify_cert(context.get()) == 1;
        result.error_code = X509_STORE_CTX_get_error(context.get());
        if (trusted) break;
        if (result.error_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT &&
            result.error_code != X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) break;
        auto* missing = X509_STORE_CTX_get_current_cert(context.get());
        if (!missing) break;
        bool added = false;
        for (const auto& url : aia_urls(missing, NID_ad_ca_issuers)) {
            if (!fetched.insert(url).second) continue;
            const auto file = cache_file(options, "issuer:" + url, ".cer");
            std::vector<Cert> certificates;
            if (options.revocation != RevocationMode::none && !file.empty())
                decode_certificates(read_trust_file(file, download_limit), certificates, true);
            for (const auto& certificate : certificates)
                if (issuer_matches(certificate.get(), missing)) added |= append(certificate.get());
            const unsigned timeout = budget.timeout();
            if (added || options.revocation != RevocationMode::online || timeout == 0) continue;
            ++budget.requests;
            const auto response = http_request(url, {}, {}, timeout, download_limit);
            if (!response.success) { detail(result.details, "AIA issuer retrieval failed: " + response.error); continue; }
            certificates.clear();
            decode_certificates(response.body, certificates, true);
            bool usable = false;
            for (const auto& certificate : certificates) {
                if (issuer_matches(certificate.get(), missing)) usable |= append(certificate.get());
            }
            if (usable) { added = true; write_cache(file, response.body, result.details); }
        }
        if (!added) break;
    }
    STACK_OF(X509)* chain = X509_STORE_CTX_get0_chain(context.get());
    if (chain) {
        for (int index = 0; index < sk_X509_num(chain); ++index) {
            X509* certificate = sk_X509_value(chain, index);
            append_chain_metadata(result, certificate);
            if (distrusted.count(certificate_key(certificate))) {
                trusted = false;
                result.error_code = X509_V_ERR_CERT_REJECTED;
                detail(result.details, "Certificate is explicitly distrusted by the operating system");
            }
            if (trusted && !usage_allowed(certificate, timestamp, index == 0, rfc3161)) {
                trusted = false;
                result.error_code = X509_V_ERR_INVALID_PURPOSE;
                detail(result.details, "Certificate key usage or extended key usage does not permit " +
                    std::string(timestamp ? "timestamp signing: " : "code signing: ") +
                    result.chain.back().subject);
            }
            if (trusted && timestamp && rfc3161 && index == 0) {
                const int eku_index = X509_get_ext_by_NID(certificate, NID_ext_key_usage, -1);
                if (eku_index >= 0 && !X509_EXTENSION_get_critical(X509_get_ext(certificate, eku_index)))
                    detail(result.details, "Noncritical sole timestamp EKU accepted by the Authenticode compatibility policy");
            }
        }
    }
    if (!trusted) {
        detail(result.details, X509_verify_cert_error_string(result.error_code));
        ERR_clear_error();
        return result;
    }
    result.status = "trusted";
    result.error_code = X509_V_OK;
    if (options.revocation == RevocationMode::none) return result;
    result.revocation = "good";
    for (int index = 0; chain && index + 1 < sk_X509_num(chain); ++index) {
        const auto status = check_revocation(sk_X509_value(chain, index), sk_X509_value(chain, index + 1),
            store.get(), chain, options, local_crls, check_time, now, budget, result.details);
        if (status == "revoked") {
            result.revocation = "revoked";
            detail(result.details, "Certificate chain contains a revoked certificate");
            break;
        }
        if (status == "unknown") result.revocation = "unknown";
    }
    if (result.revocation == "unknown")
        detail(result.details, "Fresh authenticated revocation information is unavailable for part of the chain");
    ERR_clear_error();
    return result;
}

} // namespace pesign::detail
