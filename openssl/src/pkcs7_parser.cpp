#include "verification_internal.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <climits>
#include <ctime>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace pesign::detail {
namespace {

constexpr const char* indirect_data_oid = "1.3.6.1.4.1.311.2.1.4";
constexpr const char* catalog_ctl_oid = "1.3.6.1.4.1.311.10.1";
constexpr const char* pe_image_data_oid = "1.3.6.1.4.1.311.2.1.15";
constexpr const char* nested_signature_oid = "1.3.6.1.4.1.311.2.4.1";
constexpr const char* rfc3161_oid = "1.3.6.1.4.1.311.3.3.1";
constexpr const char* standard_timestamp_oid = "1.2.840.113549.1.9.16.2.14";
constexpr std::size_t max_pkcs7_size = 64u * 1024u * 1024u;
constexpr std::size_t max_signatures = 64;
constexpr unsigned max_depth = 8;
constexpr int max_signers = 128;
constexpr int max_certificates = 512;
constexpr int max_attributes = 4096;
constexpr int max_timestamps = 64;
constexpr std::size_t max_crl_uris = 64;
constexpr std::size_t max_field_size = 4096;
constexpr std::size_t metadata_limit = 16u * 1024u * 1024u;
constexpr std::size_t max_diagnostics = 1024;

template <typename T, void (*Free)(T*)>
using Handle = std::unique_ptr<T, decltype(Free)>;

struct Bytes {
    const unsigned char* data = nullptr;
    std::size_t size = 0;
};

struct DerValue {
    unsigned char tag = 0;
    Bytes encoded;
    Bytes content;
};

// Only definite DER lengths are accepted here. The enclosing PKCS#7 decoder
// handles its own encoding; this reader follows the fixed SPC digest structure.
bool read_der(Bytes bytes, std::size_t& cursor, DerValue& value) {
    const std::size_t start = cursor;
    if (cursor >= bytes.size) return false;
    value.tag = bytes.data[cursor++];
    if ((value.tag & 0x1f) == 0x1f) {
        if (cursor >= bytes.size || bytes.data[cursor] == 0x80) return false;
        unsigned tag_bytes = 0;
        do {
            if (cursor >= bytes.size || ++tag_bytes > 5) return false;
        } while (bytes.data[cursor++] & 0x80);
    }
    if (cursor >= bytes.size) return false;
    const unsigned char first_length = bytes.data[cursor++];
    std::size_t length = first_length;
    if (first_length & 0x80) {
        const unsigned count = first_length & 0x7f;
        if (count == 0 || count > sizeof(std::size_t) ||
            count > bytes.size - cursor || bytes.data[cursor] == 0) return false;
        length = 0;
        for (unsigned i = 0; i < count; ++i) {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8)) return false;
            length = (length << 8) | bytes.data[cursor++];
        }
        if (length < 128) return false;
    }
    if (length > bytes.size - cursor) return false;
    value.content = {bytes.data + cursor, length};
    cursor += length;
    value.encoded = {bytes.data + start, cursor - start};
    return true;
}

bool only_zero_tail(const unsigned char* cursor, const unsigned char* end) {
    return std::all_of(cursor, end, [](unsigned char byte) { return byte == 0; });
}

std::string hex(Bytes bytes) {
    if (bytes.size > max_field_size / 2) return {};
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(bytes.size * 2);
    for (std::size_t i = 0; i < bytes.size; ++i) {
        result.push_back(digits[bytes.data[i] >> 4]);
        result.push_back(digits[bytes.data[i] & 15]);
    }
    return result;
}

Bytes string_bytes(const ASN1_STRING* value) {
    if (!value) return {};
    const int size = ASN1_STRING_length(value);
    if (size <= 0) return {};
    return {ASN1_STRING_get0_data(value), static_cast<std::size_t>(size)};
}

std::string object_oid(const ASN1_OBJECT* object) {
    if (!object) return {};
    const int size = OBJ_obj2txt(nullptr, 0, object, 1);
    if (size <= 0 || static_cast<std::size_t>(size) > max_field_size) return {};
    std::vector<char> buffer(static_cast<std::size_t>(size) + 1);
    OBJ_obj2txt(buffer.data(), static_cast<int>(buffer.size()), object, 1);
    return std::string(buffer.data(), static_cast<std::size_t>(size));
}

Algorithm algorithm(const X509_ALGOR* value) {
    Algorithm result;
    if (!value) return result;
    const ASN1_OBJECT* object = nullptr;
    X509_ALGOR_get0(&object, nullptr, nullptr, value);
    result.oid = object_oid(object);
    const int nid = object ? OBJ_obj2nid(object) : NID_undef;
    const char* name = nid == NID_undef ? nullptr : OBJ_nid2ln(nid);
    result.name = name ? name : result.oid;
    return result;
}

int integer(const ASN1_INTEGER* value) {
    std::int64_t result = 0;
    if (!value || ASN1_INTEGER_get_int64(&result, value) != 1 ||
        result < 0 || result > INT_MAX) return 0;
    return static_cast<int>(result);
}

std::string serial_number(const ASN1_INTEGER* value) {
    if (!value || string_bytes(value).size > max_field_size / 2) return {};
    Handle<BIGNUM, BN_free> number(ASN1_INTEGER_to_BN(value, nullptr), BN_free);
    if (!number) return {};
    char* text = BN_bn2hex(number.get());
    if (!text) return {};
    std::string result(text);
    OPENSSL_free(text);
    if (result.size() > max_field_size) return {};
    return result;
}

std::string distinguished_name(const X509_NAME* name) {
    if (!name) return {};
    const int encoded_size = i2d_X509_NAME(name, nullptr);
    if (encoded_size <= 0 || static_cast<std::size_t>(encoded_size) > max_field_size) return {};
    Handle<BIO, BIO_free_all> buffer(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!buffer || X509_NAME_print_ex(buffer.get(), name, 0, XN_FLAG_RFC2253) < 0)
        return {};
    char* data = nullptr;
    const long size = BIO_get_mem_data(buffer.get(), &data);
    return size > 0 && static_cast<std::size_t>(size) <= max_field_size
        ? std::string(data, static_cast<std::size_t>(size)) : std::string();
}

std::string time_string(const ASN1_TIME* value) {
    if (!value || string_bytes(value).size > max_field_size) return {};
    std::tm time{};
    if (!value || ASN1_TIME_to_tm(value, &time) != 1) return {};
    char buffer[40]{};
    const auto size = std::strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &time);
    if (!size) return {};
    std::string output(buffer, size);
    // tm has whole seconds only; RFC3161 GeneralizedTime may carry precision
    // that must be retained in a metadata report.
    const Bytes bytes = string_bytes(value);
    if (ASN1_STRING_type(value) == V_ASN1_GENERALIZEDTIME && bytes.size > 15 &&
        bytes.data[14] == '.') {
        std::size_t end = 15;
        while (end < bytes.size && bytes.data[end] >= '0' && bytes.data[end] <= '9') ++end;
        output.insert(output.size() - 1,
                      reinterpret_cast<const char*>(bytes.data + 14), end - 14);
    }
    return output.size() <= max_field_size ? output : std::string();
}

std::string openssl_error() {
    std::string message;
    for (unsigned i = 0; i < 8; ++i) {
        const unsigned long code = ERR_get_error();
        if (!code) break;
        char buffer[256]{};
        ERR_error_string_n(code, buffer, sizeof(buffer));
        if (!message.empty()) message += "; ";
        message += buffer;
    }
    ERR_clear_error();
    return message.empty() ? "invalid ASN.1 encoding" : message;
}

void error(Analysis& result, const std::string& context, const std::string& message) {
    const auto count = result.errors.size();
    if (count >= max_diagnostics) return;
    if (count + 1 == max_diagnostics) {
        result.errors.push_back("PKCS#7 diagnostic limit of 1024 reached; additional diagnostics may be omitted");
        return;
    }
    result.errors.push_back(context + ": " + message);
}

void warning(Analysis& result, const std::string& context, const std::string& message) {
    const auto count = result.warnings.size();
    if (count >= max_diagnostics) return;
    if (count + 1 == max_diagnostics) {
        result.warnings.push_back("PKCS#7 diagnostic limit of 1024 reached; additional diagnostics may be omitted");
        return;
    }
    result.warnings.push_back(context + ": " + message);
}

std::size_t add_cost(std::size_t total, std::size_t extra) {
    if (total > metadata_limit || extra > metadata_limit - total) return metadata_limit + 1;
    return total + extra;
}

// Charge for the worst JSON escaping expansion of text, as well as a fixed
// allowance per object. This also bounds repeated timestamp certificate copies.
std::size_t text_cost(const std::string& value) {
    return value.size() > metadata_limit / 6 ? metadata_limit + 1 : value.size() * 6;
}

std::size_t algorithm_cost(const Algorithm& value) {
    return add_cost(text_cost(value.oid), text_cost(value.name));
}

std::size_t certificate_cost(const Certificate& value) {
    std::size_t cost = 512;
    for (const auto* text : {&value.subject, &value.issuer, &value.serial,
             &value.sha1_thumbprint, &value.sha256_thumbprint, &value.not_before, &value.not_after})
        cost = add_cost(cost, text_cost(*text));
    cost = add_cost(cost, algorithm_cost(value.signature_algorithm));
    for (const auto& uri : value.crl_distribution_points)
        cost = add_cost(cost, add_cost(16, text_cost(uri)));
    return cost;
}

std::size_t timestamp_header_cost(const Timestamp& value) {
    std::size_t cost = 256;
    for (const auto* text : {&value.type, &value.time, &value.message_imprint, &value.signer_subject})
        cost = add_cost(cost, text_cost(*text));
    return add_cost(cost, algorithm_cost(value.digest_algorithm));
}

std::size_t timestamp_cost(const Timestamp& value) {
    std::size_t cost = timestamp_header_cost(value);
    for (const auto& cert : value.certificates) cost = add_cost(cost, certificate_cost(cert));
    return cost;
}

std::size_t signer_header_cost(const Signer& value) {
    std::size_t cost = 256;
    for (const auto* text : {&value.issuer, &value.serial, &value.signing_time})
        cost = add_cost(cost, text_cost(*text));
    cost = add_cost(cost, algorithm_cost(value.digest_algorithm));
    return add_cost(cost, algorithm_cost(value.signature_algorithm));
}

std::size_t signature_header_cost(const Signature& value) {
    return add_cost(add_cost(256, text_cost(value.content_type)),
                    add_cost(text_cost(value.embedded_digest), algorithm_cost(value.digest_algorithm)));
}

std::size_t chain_metadata_cost(const CertificateChain& value) {
    std::size_t cost = add_cost(128, text_cost(value.status));
    for (const auto& cert : value.certificates) cost = add_cost(cost, certificate_cost(cert));
    for (const auto& detail : value.details) cost = add_cost(cost, text_cost(detail));
    return cost;
}

std::size_t analysis_metadata_cost(const Analysis& analysis) {
    std::size_t cost = 0;
    for (const auto& signature : analysis.signatures) {
        cost = add_cost(cost, signature_header_cost(signature));
        for (const auto& cert : signature.certificates) cost = add_cost(cost, certificate_cost(cert));
        for (const auto& signer : signature.signers) {
            cost = add_cost(cost, signer_header_cost(signer));
            cost = add_cost(cost, chain_metadata_cost(signer.certificate_chain));
            for (const auto& timestamp : signer.timestamps) cost = add_cost(cost, timestamp_cost(timestamp));
        }
    }
    return cost;
}

class MetadataBudget {
public:
    explicit MetadataBudget(const Analysis& result) {
        const auto used = analysis_metadata_cost(result);
        remaining_ = used < metadata_limit ? metadata_limit - used : 0;
    }

    bool charge(std::size_t cost, Analysis& result, const std::string& context) {
        if (exhausted_) return false;
        if (cost > remaining_) {
            error(result, context, "metadata output exceeds the limit of 16 MiB; remaining metadata omitted");
            exhausted_ = true;
            return false;
        }
        remaining_ -= cost;
        return true;
    }

    bool active() const { return !exhausted_; }

private:
    std::size_t remaining_ = 0;
    bool exhausted_ = false;
};

Algorithm metadata_algorithm(const X509_ALGOR* value, Analysis& result,
                             const std::string& context) {
    Algorithm output = algorithm(value);
    if (value && output.oid.empty())
        warning(result, context, "algorithm OID omitted: invalid or exceeds 4 KiB field limit");
    return output;
}

Certificate certificate(X509* x509, Analysis& analysis, const std::string& context) {
    Certificate result;
    const long version = X509_get_version(x509);
    result.version = version >= 0 && version < INT_MAX ? static_cast<int>(version + 1) : 0;
    result.subject = distinguished_name(X509_get_subject_name(x509));
    result.issuer = distinguished_name(X509_get_issuer_name(x509));
    result.serial = serial_number(X509_get0_serialNumber(x509));
    if (result.subject.empty() && X509_NAME_entry_count(X509_get_subject_name(x509)) > 0)
        warning(analysis, context, "certificate subject omitted: invalid or exceeds 4 KiB field limit");
    if (result.issuer.empty() && X509_NAME_entry_count(X509_get_issuer_name(x509)) > 0)
        warning(analysis, context, "certificate issuer omitted: invalid or exceeds 4 KiB field limit");
    if (result.serial.empty())
        warning(analysis, context, "certificate serial omitted: invalid or exceeds 4 KiB field limit");
    result.not_before = time_string(X509_get0_notBefore(x509));
    result.not_after = time_string(X509_get0_notAfter(x509));
    const X509_ALGOR* signature_algorithm = nullptr;
    X509_get0_signature(nullptr, &signature_algorithm, x509);
    result.signature_algorithm = metadata_algorithm(signature_algorithm, analysis, context);
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int digest_size = 0;
    if (X509_digest(x509, EVP_sha1(), digest, &digest_size) == 1)
        result.sha1_thumbprint = hex({digest, digest_size});
    if (X509_digest(x509, EVP_sha256(), digest, &digest_size) == 1)
        result.sha256_thumbprint = hex({digest, digest_size});

    Handle<CRL_DIST_POINTS, CRL_DIST_POINTS_free> points(
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(
            x509, NID_crl_distribution_points, nullptr, nullptr)), CRL_DIST_POINTS_free);
    if (points) {
        const int count = std::min(sk_DIST_POINT_num(points.get()), max_attributes);
        for (int i = 0; i < count; ++i) {
            const DIST_POINT* point = sk_DIST_POINT_value(points.get(), i);
            if (!point || !point->distpoint || point->distpoint->type != 0) continue;
            const GENERAL_NAMES* names = point->distpoint->name.fullname;
            const int name_count = std::min(sk_GENERAL_NAME_num(names), max_attributes);
            for (int j = 0; j < name_count; ++j) {
                const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, j);
                if (!name || name->type != GEN_URI) continue;
                const Bytes bytes = string_bytes(name->d.uniformResourceIdentifier);
                if (!bytes.size) continue;
                if (bytes.size > max_field_size) {
                    warning(analysis, context, "CRL URL omitted: exceeds 4 KiB field limit");
                    continue;
                }
                std::string uri(reinterpret_cast<const char*>(bytes.data), bytes.size);
                if (std::find(result.crl_distribution_points.begin(),
                              result.crl_distribution_points.end(), uri) ==
                    result.crl_distribution_points.end()) {
                    if (result.crl_distribution_points.size() >= max_crl_uris) {
                        warning(analysis, context, "CRL distribution point URLs exceed the limit of 64");
                        ERR_clear_error();
                        return result;
                    }
                    result.crl_distribution_points.push_back(std::move(uri));
                }
            }
        }
    }
    ERR_clear_error(); // Optional extension decoding must not taint a later error.
    return result;
}

std::vector<Certificate> certificates(STACK_OF(X509)* bag, Analysis& result,
                                      const std::string& context, MetadataBudget& budget) {
    std::vector<Certificate> output;
    const int count = bag ? sk_X509_num(bag) : 0;
    if (count > max_certificates)
        error(result, context, "certificate bag exceeds the limit of 512 certificates");
    for (int i = 0; i < std::min(count, max_certificates); ++i) {
        if (!budget.active()) break;
        X509* value = sk_X509_value(bag, i);
        if (value) {
            Certificate parsed = certificate(value, result, context + ", certificate " + std::to_string(i));
            if (!budget.charge(certificate_cost(parsed), result, context)) break;
            output.push_back(std::move(parsed));
        }
        else error(result, context, "certificate bag contains a null certificate");
    }
    return output;
}

int match_certificate(PKCS7_SIGNER_INFO* signer, STACK_OF(X509)* bag,
                      Analysis& result, const std::string& context) {
    if (!signer || !signer->issuer_and_serial) {
        error(result, context, "signer has no issuer and serial number");
        return -1;
    }
    int match = -1;
    const int count = bag ? std::min(sk_X509_num(bag), max_certificates) : 0;
    for (int i = 0; i < count; ++i) {
        X509* value = sk_X509_value(bag, i);
        if (!value) continue;
        if (X509_NAME_cmp(X509_get_issuer_name(value), signer->issuer_and_serial->issuer) == 0 &&
            ASN1_INTEGER_cmp(X509_get0_serialNumber(value), signer->issuer_and_serial->serial) == 0) {
            if (match >= 0 && X509_cmp(sk_X509_value(bag, match), value) != 0) {
                warning(result, context, "multiple different certificates match signer issuer and serial");
                return -1;
            }
            if (match < 0) match = i;
        }
    }
    if (match < 0)
        warning(result, context, "signer certificate is missing from the embedded certificate bag");
    return match;
}

const ASN1_TYPE* single_signed_attribute(PKCS7_SIGNER_INFO* signer, int nid,
                                         const char* name, Analysis& result,
                                         const std::string& context) {
    const int count = signer && signer->auth_attr ? sk_X509_ATTRIBUTE_num(signer->auth_attr) : 0;
    if (count > max_attributes) {
        error(result, context, "too many signed attributes (limit 4096)");
        return nullptr;
    }
    X509_ATTRIBUTE* match = nullptr;
    for (int i = 0; i < count; ++i) {
        X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(signer->auth_attr, i);
        if (!attr || OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attr)) != nid) continue;
        if (match) {
            error(result, context, std::string("duplicate ") + name + " signed attributes");
            return nullptr;
        }
        match = attr;
    }
    if (!match) return nullptr;
    if (X509_ATTRIBUTE_count(match) != 1) {
        error(result, context, std::string(name) + " signed attribute must have exactly one value");
        return nullptr;
    }
    return X509_ATTRIBUTE_get0_type(match, 0);
}

std::string signing_time(PKCS7_SIGNER_INFO* signer, Analysis& result,
                         const std::string& context) {
    const ASN1_TYPE* value = single_signed_attribute(signer, NID_pkcs9_signingTime,
                                                    "signingTime", result, context);
    if (!value) return {};
    const ASN1_TIME* time = nullptr;
    if (value->type == V_ASN1_UTCTIME) time = value->value.utctime;
    if (value->type == V_ASN1_GENERALIZEDTIME) time = value->value.generalizedtime;
    const std::string output = time_string(time);
    if (output.empty()) error(result, context, "invalid signingTime attribute");
    return output;
}

bool attribute_bytes(const ASN1_TYPE* value, Bytes& bytes) {
    if (!value) return false;
    if (value->type == V_ASN1_SEQUENCE) bytes = string_bytes(value->value.sequence);
    else if (value->type == V_ASN1_OCTET_STRING) bytes = string_bytes(value->value.octet_string);
    else return false;
    return bytes.data && bytes.size;
}

Handle<PKCS7, PKCS7_free> decode_pkcs7(Bytes bytes, Analysis& result,
                                     const std::string& context) {
    Handle<PKCS7, PKCS7_free> output(nullptr, PKCS7_free);
    if (!bytes.data || !bytes.size || bytes.size > max_pkcs7_size || bytes.size > LONG_MAX) {
        error(result, context, "empty or oversized PKCS#7 payload (limit 64 MiB)");
        return output;
    }
    ERR_clear_error();
    const unsigned char* cursor = bytes.data;
    output.reset(d2i_PKCS7(nullptr, &cursor, static_cast<long>(bytes.size)));
    if (!output) {
        error(result, context, "cannot decode PKCS#7: " + openssl_error());
        return output;
    }
    if (!only_zero_tail(cursor, bytes.data + bytes.size)) {
        error(result, context, "nonzero data after PKCS#7 encoding");
        output.reset();
    }
    if (output && (!PKCS7_type_is_signed(output.get()) || !output->d.sign)) {
        error(result, context, "PKCS#7 content is not SignedData");
        output.reset();
    }
    return output;
}

void indirect_digest(PKCS7* content, Signature& signature, Analysis& result,
                     const std::string& context) {
    if (!content) {
        error(result, context, "SignedData has no contentInfo");
        return;
    }
    signature.content_type = object_oid(content->type);
    // Catalog SignedData contains a CTL with member digests, rather than a
    // single SpcIndirectDataContent image digest. Verification handles the CTL.
    if (signature.content_type == catalog_ctl_oid) return;
    if (signature.content_type != indirect_data_oid) {
        warning(result, context, "content type is not Authenticode SpcIndirectDataContent: " +
                signature.content_type);
        return;
    }
    Bytes bytes;
    if (!PKCS7_type_is_other(content) || !attribute_bytes(content->d.other, bytes)) {
        error(result, context, "SpcIndirectDataContent is absent or has an unsupported ASN.1 type");
        return;
    }
    DerValue outer, data, digest_info, data_type, optional_value, digest_algorithm, digest;
    std::size_t cursor = 0;
    bool valid = read_der(bytes, cursor, outer) && outer.tag == 0x30 && cursor == bytes.size;
    cursor = 0;
    valid = valid && read_der(outer.content, cursor, data) && data.tag == 0x30 &&
        read_der(outer.content, cursor, digest_info) && digest_info.tag == 0x30 &&
        cursor == outer.content.size;
    cursor = 0;
    valid = valid && read_der(data.content, cursor, data_type) && data_type.tag == 0x06;
    if (valid && cursor < data.content.size) valid = read_der(data.content, cursor, optional_value);
    valid = valid && cursor == data.content.size;
    cursor = 0;
    valid = valid && read_der(digest_info.content, cursor, digest_algorithm) &&
        digest_algorithm.tag == 0x30 && read_der(digest_info.content, cursor, digest) &&
        digest.tag == 0x04 && cursor == digest_info.content.size && digest.content.size > 0;
    if (!valid) {
        error(result, context, "malformed SpcIndirectDataContent digest structure");
        return;
    }
    if (digest.content.size > max_field_size / 2) {
        error(result, context, "embedded digest exceeds 4 KiB metadata field limit");
        return;
    }
    const unsigned char* oid_cursor = data_type.encoded.data;
    Handle<ASN1_OBJECT, ASN1_OBJECT_free> data_oid(
        d2i_ASN1_OBJECT(nullptr, &oid_cursor, static_cast<long>(data_type.encoded.size)),
        ASN1_OBJECT_free);
    const unsigned char* algorithm_cursor = digest_algorithm.encoded.data;
    Handle<X509_ALGOR, X509_ALGOR_free> parsed_algorithm(
        d2i_X509_ALGOR(nullptr, &algorithm_cursor, static_cast<long>(digest_algorithm.encoded.size)),
        X509_ALGOR_free);
    if (!data_oid || !parsed_algorithm || oid_cursor != data_type.encoded.data + data_type.encoded.size ||
        algorithm_cursor != digest_algorithm.encoded.data + digest_algorithm.encoded.size) {
        error(result, context, "invalid SpcIndirectDataContent object identifier or digest algorithm");
        ERR_clear_error();
        return;
    }
    if (object_oid(data_oid.get()) != pe_image_data_oid) {
        warning(result, context, "SpcIndirectDataContent does not describe PE image data");
        return;
    }
    signature.digest_algorithm = metadata_algorithm(parsed_algorithm.get(), result, context);
    signature.embedded_digest = hex(digest.content);
}

bool pkcs9_timestamp(Bytes bytes, STACK_OF(X509)* bag,
                     const std::vector<Certificate>& parsed_bag, Timestamp& timestamp,
                     MetadataBudget& budget, Analysis& result, const std::string& context) {
    timestamp.type = "pkcs9";
    ERR_clear_error();
    const unsigned char* cursor = bytes.data;
    Handle<PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO_free> signer(
        d2i_PKCS7_SIGNER_INFO(nullptr, &cursor, static_cast<long>(bytes.size)),
        PKCS7_SIGNER_INFO_free);
    if (!signer || !only_zero_tail(cursor, bytes.data + bytes.size)) {
        error(result, context, "cannot decode PKCS#9 countersignature: " + openssl_error());
        return budget.charge(timestamp_header_cost(timestamp), result, context);
    }
    timestamp.time = signing_time(signer.get(), result, context);
    timestamp.digest_algorithm = metadata_algorithm(signer->digest_alg, result, context);
    const ASN1_TYPE* imprint = single_signed_attribute(signer.get(), NID_pkcs9_messageDigest,
                                                      "messageDigest", result, context);
    if (imprint && imprint->type == V_ASN1_OCTET_STRING) {
        const Bytes imprint_bytes = string_bytes(imprint->value.octet_string);
        if (imprint_bytes.size > max_field_size / 2)
            error(result, context, "PKCS#9 messageDigest exceeds 4 KiB metadata field limit");
        else timestamp.message_imprint = hex(imprint_bytes);
    }
    else if (imprint) error(result, context, "invalid PKCS#9 messageDigest attribute type");
    const int index = match_certificate(signer.get(), bag, result, context);
    if (index >= 0 && static_cast<std::size_t>(index) < parsed_bag.size()) {
        const Certificate& cached = parsed_bag[static_cast<std::size_t>(index)];
        // Reserve space before copying the embedded certificate. Its metadata
        // was already extracted once for the containing signature's bag.
        const auto cost = add_cost(timestamp_header_cost(timestamp),
                                   add_cost(certificate_cost(cached), text_cost(cached.subject)));
        if (!budget.charge(cost, result, context)) return false;
        timestamp.certificates.push_back(cached);
        timestamp.signer_subject = cached.subject;
        return true;
    }
    if (index >= 0) warning(result, context, "timestamp signer certificate metadata was omitted by a limit");
    return budget.charge(timestamp_header_cost(timestamp), result, context);
}

void rfc3161_timestamp(Bytes bytes, Timestamp& timestamp, Analysis& result,
                       const std::string& context, MetadataBudget& budget) {
    timestamp.type = "rfc3161";
    ERR_clear_error();
    const unsigned char* cursor = bytes.data;
    Handle<CMS_ContentInfo, CMS_ContentInfo_free> token(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(bytes.size)), CMS_ContentInfo_free);
    if (!token) {
        error(result, context, "cannot decode RFC3161 CMS token: " + openssl_error());
        return;
    }
    if (!only_zero_tail(cursor, bytes.data + bytes.size)) {
        error(result, context, "nonzero data after RFC3161 CMS token");
        return;
    }
    if (OBJ_obj2nid(CMS_get0_type(token.get())) != NID_pkcs7_signed ||
        object_oid(CMS_get0_eContentType(token.get())) != "1.2.840.113549.1.9.16.1.4") {
        error(result, context, "RFC3161 token is not SignedData containing TSTInfo");
        return;
    }
    ASN1_OCTET_STRING** content = CMS_get0_content(token.get());
    const Bytes info_bytes = content ? string_bytes(*content) : Bytes{};
    if (!info_bytes.data || !info_bytes.size) {
        error(result, context, "RFC3161 token has no embedded TSTInfo");
        return;
    }
    cursor = info_bytes.data;
    Handle<TS_TST_INFO, TS_TST_INFO_free> info(
        d2i_TS_TST_INFO(nullptr, &cursor, static_cast<long>(info_bytes.size)), TS_TST_INFO_free);
    if (!info) {
        error(result, context, "cannot decode RFC3161 TSTInfo: " + openssl_error());
        return;
    }
    if (cursor != info_bytes.data + info_bytes.size) {
        error(result, context, "trailing data after RFC3161 TSTInfo");
        return;
    }
    timestamp.time = time_string(TS_TST_INFO_get_time(info.get()));
    if (timestamp.time.empty()) error(result, context, "invalid RFC3161 genTime");
    TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(info.get());
    if (imprint) {
        timestamp.digest_algorithm = metadata_algorithm(TS_MSG_IMPRINT_get_algo(imprint), result, context);
        const Bytes imprint_bytes = string_bytes(TS_MSG_IMPRINT_get_msg(imprint));
        if (imprint_bytes.size > max_field_size / 2)
            error(result, context, "RFC3161 message imprint exceeds 4 KiB metadata field limit");
        else timestamp.message_imprint = hex(imprint_bytes);
    }
    const auto free_bag = [](STACK_OF(X509)* bag) { sk_X509_pop_free(bag, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(free_bag)> bag(CMS_get1_certs(token.get()), free_bag);
    timestamp.certificates = certificates(bag.get(), result, context, budget);
    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(token.get());
    const int count = signers ? sk_CMS_SignerInfo_num(signers) : 0;
    if (count != 1) warning(result, context, "RFC3161 token does not contain exactly one signer");
    if (count == 1) {
        CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, 0);
        int index = -1;
        bool ambiguous = false;
        const int cert_count = bag ? std::min(sk_X509_num(bag.get()), max_certificates) : 0;
        for (int i = 0; i < cert_count; ++i) {
            X509* cert = sk_X509_value(bag.get(), i);
            if (!cert || CMS_SignerInfo_cert_cmp(signer, cert) != 0) continue;
            if (index >= 0 && X509_cmp(sk_X509_value(bag.get(), index), cert) != 0) {
                ambiguous = true;
                break;
            }
            if (index < 0) index = i;
        }
        if (ambiguous)
            warning(result, context, "multiple different certificates match RFC3161 signer identity");
        else if (index < 0)
            warning(result, context, "RFC3161 signer certificate is missing from the embedded certificate bag");
        else if (static_cast<std::size_t>(index) < timestamp.certificates.size())
            timestamp.signer_subject = timestamp.certificates[static_cast<std::size_t>(index)].subject;
    }
}

struct NestedSignature {
    Bytes bytes;
    int signer_index = -1;
};

void unsigned_attributes(PKCS7_SIGNER_INFO* signer, STACK_OF(X509)* bag,
                         const std::vector<Certificate>& parsed_bag, MetadataBudget& budget,
                         Signer& output, int signer_index,
                         std::vector<NestedSignature>& nested, Analysis& result,
                         const std::string& context) {
    const int count = signer->unauth_attr ? sk_X509_ATTRIBUTE_num(signer->unauth_attr) : 0;
    if (count > max_attributes) error(result, context, "too many unsigned attributes (limit 4096)");
    int value_count = 0;
    for (int i = 0; i < std::min(count, max_attributes); ++i) {
        if (!budget.active()) return;
        X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(signer->unauth_attr, i);
        if (!attr) continue;
        const std::string oid = object_oid(X509_ATTRIBUTE_get0_object(attr));
        const bool is_nested = oid == nested_signature_oid;
        const bool is_pkcs9 = oid == "1.2.840.113549.1.9.6";
        const bool is_rfc3161 = oid == rfc3161_oid || oid == standard_timestamp_oid;
        if (!is_nested && !is_pkcs9 && !is_rfc3161) continue;
        const int values = X509_ATTRIBUTE_count(attr);
        if (values <= 0) error(result, context, "signature or timestamp attribute has no values");
        for (int j = 0; j < values; ++j) {
            if (++value_count > max_attributes) {
                error(result, context, "too many signature or timestamp attribute values (limit 4096)");
                return;
            }
            Bytes bytes;
            if (!attribute_bytes(X509_ATTRIBUTE_get0_type(attr, j), bytes) || bytes.size > max_pkcs7_size) {
                error(result, context, "signature or timestamp attribute has an invalid ASN.1 value");
                continue;
            }
            if (is_nested) {
                if (nested.size() >= max_signatures) {
                    error(result, context, "too many nested signature values (limit 64)");
                    return;
                }
                nested.push_back({bytes, signer_index});
            } else {
                if (output.timestamps.size() >= static_cast<std::size_t>(max_timestamps)) {
                    error(result, context, "too many timestamps (limit 64 per signer)");
                    return;
                }
                Timestamp timestamp;
                const std::string timestamp_context = context + ", timestamp " +
                    std::to_string(output.timestamps.size());
                if (is_pkcs9) {
                    if (!pkcs9_timestamp(bytes, bag, parsed_bag, timestamp, budget, result, timestamp_context))
                        return;
                } else {
                    MetadataBudget temporary_budget = budget;
                    rfc3161_timestamp(bytes, timestamp, result, timestamp_context, temporary_budget);
                    if (!budget.charge(timestamp_cost(timestamp), result, timestamp_context)) return;
                }
                output.timestamps.push_back(std::move(timestamp));
            }
        }
    }
}

void parse_signature(Bytes bytes, std::size_t record, int parent, int parent_signer,
                     unsigned depth, Analysis& result, MetadataBudget& budget,
                     const Options* chain_options) {
    const std::string context = "certificate record " + std::to_string(record) +
        (parent >= 0 ? ", nested under signature " + std::to_string(parent) : std::string());
    if (!budget.active()) return;
    if (depth > max_depth) {
        error(result, context, "nested signature depth exceeds the limit of 8");
        return;
    }
    if (result.signatures.size() >= max_signatures) {
        error(result, context, "signature count exceeds the limit of 64");
        return;
    }
    auto p7 = decode_pkcs7(bytes, result, context);
    if (!p7) return;
    Signature signature;
    signature.certificate_record = record;
    signature.parent_signature = parent;
    signature.parent_signer = parent_signer;
    signature.version = integer(p7->d.sign->version);
    indirect_digest(p7->d.sign->contents, signature, result, context);
    if (!budget.charge(signature_header_cost(signature), result, context)) return;
    signature.certificates = certificates(p7->d.sign->cert, result, context, budget);

    std::vector<NestedSignature> nested;
    STACK_OF(PKCS7_SIGNER_INFO)* signers = PKCS7_get_signer_info(p7.get());
    const int count = signers ? sk_PKCS7_SIGNER_INFO_num(signers) : 0;
    if (count == 0) error(result, context, "SignedData has no signers");
    if (count > max_signers) error(result, context, "signer count exceeds the limit of 128");
    for (int i = 0; i < std::min(count, max_signers); ++i) {
        if (!budget.active()) break;
        PKCS7_SIGNER_INFO* signer = sk_PKCS7_SIGNER_INFO_value(signers, i);
        if (!signer) {
            error(result, context, "SignedData contains a null signer");
            continue;
        }
        const std::string signer_context = context + ", signer " + std::to_string(i);
        Signer output;
        output.version = integer(signer->version);
        output.digest_algorithm = metadata_algorithm(signer->digest_alg, result, signer_context);
        output.signature_algorithm = metadata_algorithm(signer->digest_enc_alg, result, signer_context);
        if (signer->issuer_and_serial) {
            output.issuer = distinguished_name(signer->issuer_and_serial->issuer);
            output.serial = serial_number(signer->issuer_and_serial->serial);
            if (output.issuer.empty() && X509_NAME_entry_count(signer->issuer_and_serial->issuer) > 0)
                warning(result, signer_context, "signer issuer omitted: invalid or exceeds 4 KiB field limit");
            if (output.serial.empty())
                warning(result, signer_context, "signer serial omitted: invalid or exceeds 4 KiB field limit");
        }
        output.signing_time = signing_time(signer, result, signer_context);
        output.certificate_index = match_certificate(signer, p7->d.sign->cert, result, signer_context);
        if (!budget.charge(signer_header_cost(output), result, signer_context)) break;
        unsigned_attributes(signer, p7->d.sign->cert, signature.certificates, budget,
                            output, i, nested, result, signer_context);
        if (chain_options && budget.active()) {
            X509* leaf = output.certificate_index >= 0 ?
                sk_X509_value(p7->d.sign->cert, output.certificate_index) : nullptr;
            auto chain = build_certificate_chain(leaf, p7->d.sign->cert, *chain_options);
            output.certificate_chain.status = std::move(chain.status);
            output.certificate_chain.certificates = std::move(chain.chain);
            output.certificate_chain.details = std::move(chain.details);
        }
        if (!budget.charge(chain_metadata_cost(output.certificate_chain), result, signer_context)) break;
        signature.signers.push_back(std::move(output));
    }
    const int signature_index = static_cast<int>(result.signatures.size());
    result.signatures.push_back(std::move(signature));
    for (const auto& child : nested) {
        parse_signature(child.bytes, record, signature_index, child.signer_index, depth + 1, result, budget,
                        chain_options);
    }
}

} // namespace

Certificate certificate_metadata(X509* value) {
    Analysis diagnostics;
    return certificate(value, diagnostics, "certificate chain");
}

void parse_pkcs7(const std::uint8_t* data, std::size_t size,
                 std::size_t certificate_record, Analysis& result, const Options* chain_options) {
    MetadataBudget budget(result);
    parse_signature({data, size}, certificate_record, -1, -1, 0, result, budget, chain_options);
}

} // namespace pesign::detail
