#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace pesign {

inline constexpr const char* version = "0.2.2";

class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Algorithm {
    std::string oid;
    std::string name;
};

struct Certificate {
    int version = 0;
    std::string subject;
    std::string issuer;
    std::string serial;
    std::string sha1_thumbprint;
    std::string sha256_thumbprint;
    std::string not_before;
    std::string not_after;
    Algorithm signature_algorithm;
    std::vector<std::string> crl_distribution_points;
};

enum class RevocationMode { none, cache, online };

struct Options {
    bool verify = false;
    bool embedded_only = false;
    bool use_system_roots = true;
    bool strict_timestamps = false; // Enforce additional Microsoft ESS path constraints.
    RevocationMode revocation = RevocationMode::none;
    std::filesystem::path catalog;
    std::vector<std::filesystem::path> catalog_directories;
    std::filesystem::path ca_file;
    std::filesystem::path ca_directory;
    std::filesystem::path crl_file;
    std::filesystem::path crl_directory;
    std::filesystem::path revocation_cache;
    unsigned network_timeout_seconds = 10;
    std::time_t verification_time = 0; // 0 means current time; library/test override.
};

struct Verification {
    std::string content_digest = "not_checked";
    std::string cms_signature = "not_checked";
    std::string certificate_chain = "not_checked";
    std::string timestamp = "not_checked";
    std::string revocation = "not_checked";
    std::string overall = "not_performed";
    int error_code = 0;
    std::string verification_time;
    std::vector<Certificate> chain;
    std::vector<std::string> details;
};

struct Timestamp {
    std::string type; // pkcs9 or rfc3161; parsed metadata, never a trust verdict.
    std::string time;
    Algorithm digest_algorithm;
    std::string message_imprint;
    std::string signer_subject;
    std::vector<Certificate> certificates;
};

struct CertificateChain {
    std::string status = "not_built"; // built, partial, unavailable; never a trust verdict.
    std::vector<Certificate> certificates; // Signer first, root last when available.
    std::vector<std::string> details;
};

struct Signer {
    int version = 0;
    Algorithm digest_algorithm;
    Algorithm signature_algorithm;
    std::string issuer;
    std::string serial;
    std::string signing_time;
    int certificate_index = -1; // Index in Signature::certificates; -1 if absent.
    std::vector<Timestamp> timestamps;
    CertificateChain certificate_chain; // Locally resolved metadata, separate from verification.
    Verification verification;
};

struct Signature {
    std::size_t certificate_record = 0;
    int parent_signature = -1; // Index in Analysis::signatures; -1 for top level.
    int parent_signer = -1;
    int version = 0;
    std::string content_type;
    Algorithm digest_algorithm; // SpcIndirectDataContent image digest algorithm.
    std::string embedded_digest; // Claimed image digest, not recomputed/verified.
    std::vector<Certificate> certificates; // Embedded bag, not a verified chain.
    std::vector<Signer> signers;
    Verification verification;
};

struct CertificateRecord {
    std::uint64_t offset = 0;
    std::uint32_t length = 0;
    std::uint16_t revision = 0;
    std::uint16_t type = 0;
};

struct Analysis {
    std::string file;
    std::string pe_format;
    std::uint16_t machine = 0;
    std::uint64_t certificate_table_offset = 0;
    std::uint32_t certificate_table_size = 0;
    std::vector<CertificateRecord> certificate_records;
    std::vector<Signature> signatures;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    std::string signature_type = "none";
    std::string catalog_file;
    Verification verification; // Summary of primary signature's first signer.
};

// Metadata fields are declarations; verification verdicts are separate and
// populated when verify, strict_timestamps, or a revocation mode requests validation.
// Invalid PE structure throws ParseError; malformed PKCS#7 records/attributes
// are reported in Analysis::errors. File and Options overloads resolve a local
// certificate chain without network or trust validation; analyze_bytes without
// Options only parses embedded metadata.
Analysis analyze_file(const std::filesystem::path& file);
Analysis analyze_bytes(const std::vector<std::uint8_t>& bytes);
Analysis analyze_file(const std::filesystem::path& file, const Options& options);
Analysis analyze_bytes(const std::vector<std::uint8_t>& bytes, const Options& options);
std::vector<std::uint8_t> authenticode_digest(
    const std::vector<std::uint8_t>& bytes, const std::string& algorithm_oid);
std::string to_json(const Analysis& analysis);
std::string to_text(const Analysis& analysis);

} // namespace pesign
