#include "verification_internal.h"

#include <openssl/asn1.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/rsa.h>
#include <openssl/ts.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <climits>
#include <limits>
#include <memory>
#include <optional>
#include <utility>

namespace pesign::detail {
namespace {

constexpr const char* spc_oid = "1.3.6.1.4.1.311.2.1.4";
constexpr const char* ctl_oid = "1.3.6.1.4.1.311.10.1";
constexpr const char* nested_oid = "1.3.6.1.4.1.311.2.4.1";
constexpr const char* microsoft_timestamp_oid = "1.3.6.1.4.1.311.3.3.1";
constexpr const char* standard_timestamp_oid = "1.2.840.113549.1.9.16.2.14";
constexpr const char* tst_info_oid = "1.2.840.113549.1.9.16.1.4";
constexpr std::size_t max_payload = 64u * 1024u * 1024u;
constexpr int max_attributes = 4096;
constexpr int max_certificates = 512;
constexpr int max_timestamps = 64;

template <typename T, void (*Free)(T*)>
using Handle = std::unique_ptr<T, decltype(Free)>;

struct Bytes { const unsigned char* data = nullptr; std::size_t size = 0; };

void detail(Verification& verification, const std::string& text) {
    if (verification.details.size() < 128) verification.details.push_back(text);
}

std::string errors() {
    std::string result;
    for (unsigned i = 0; i < 8; ++i) {
        const unsigned long code = ERR_get_error();
        if (!code) break;
        char message[256]{};
        ERR_error_string_n(code, message, sizeof(message));
        if (!result.empty()) result += "; ";
        result += message;
    }
    ERR_clear_error();
    return result;
}

Bytes bytes(const ASN1_STRING* value) {
    const int size = value ? ASN1_STRING_length(value) : 0;
    return size > 0 ? Bytes{ASN1_STRING_get0_data(value), static_cast<std::size_t>(size)} : Bytes{};
}

std::string oid(const ASN1_OBJECT* value) {
    if (!value) return {};
    char text[128]{};
    const int size = OBJ_obj2txt(text, sizeof(text), value, 1);
    return size > 0 && size < static_cast<int>(sizeof(text)) ? std::string(text, size) : std::string();
}

bool zero_tail(const unsigned char* start, const unsigned char* end) {
    return std::all_of(start, end, [](unsigned char byte) { return byte == 0; });
}

Handle<PKCS7, PKCS7_free> decode(Bytes value) {
    Handle<PKCS7, PKCS7_free> result(nullptr, PKCS7_free);
    if (!value.data || !value.size || value.size > max_payload || value.size > LONG_MAX) return result;
    const auto* cursor = value.data;
    result.reset(d2i_PKCS7(nullptr, &cursor, static_cast<long>(value.size)));
    if (!result || !zero_tail(cursor, value.data + value.size) ||
        !PKCS7_type_is_signed(result.get()) || !result->d.sign) result.reset();
    return result;
}

Bytes attribute_bytes(const ASN1_TYPE* value) {
    if (!value) return {};
    if (value->type == V_ASN1_SEQUENCE) return bytes(value->value.sequence);
    if (value->type == V_ASN1_OCTET_STRING) return bytes(value->value.octet_string);
    return {};
}

// PKCS#7 hashes the contents octets of a custom ASN.1 SEQUENCE. Authenticode's
// SPC and Microsoft's CTL use that form; CMS TSTInfo uses an OCTET STRING and
// its complete embedded DER value is hashed instead.
bool sequence_prefix(Bytes input, Bytes& encoded, Bytes& output) {
    if (input.size < 2 || input.data[0] != 0x30) return false;
    std::size_t cursor = 2, length = input.data[1];
    if (length & 0x80) {
        const std::size_t count = length & 0x7f;
        if (!count || count > sizeof(std::size_t) || count > input.size - cursor || input.data[cursor] == 0)
            return false;
        length = 0;
        for (std::size_t i = 0; i < count; ++i) {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8)) return false;
            length = (length << 8) | input.data[cursor++];
        }
        if (length < 128) return false;
    }
    if (length > input.size - cursor) return false;
    encoded = {input.data, cursor + length};
    output = {input.data + cursor, length};
    return true;
}

bool sequence_body(Bytes input, Bytes& output) {
    Bytes encoded;
    return sequence_prefix(input, encoded, output) && encoded.size == input.size;
}

std::vector<unsigned char> wrap_sequence(Bytes value) {
    std::vector<unsigned char> encoded{0x30};
    if (value.size < 128) encoded.push_back(static_cast<unsigned char>(value.size));
    else {
        unsigned char length[sizeof(std::size_t)]{};
        std::size_t count = 0, remaining = value.size;
        while (remaining) { length[count++] = static_cast<unsigned char>(remaining & 0xff); remaining >>= 8; }
        encoded.push_back(static_cast<unsigned char>(0x80 | count));
        while (count) encoded.push_back(length[--count]);
    }
    encoded.insert(encoded.end(), value.data, value.data + value.size);
    return encoded;
}

// Keep the complete first ESSCertID, including hash algorithm and issuerSerial.
// The original attribute is decoded before this projection, so malformed extra
// entries cannot acquire validity through the Microsoft compatibility profile.
std::vector<unsigned char> first_ess_certificate(Bytes value) {
    Bytes outer, certificates, first, content;
    if (!sequence_body(value, outer) || !sequence_prefix(outer, certificates, content) ||
        !sequence_prefix(content, first, certificates)) return {};
    const auto certs = wrap_sequence(first);
    return wrap_sequence({certs.data(), certs.size()});
}

bool signed_content(PKCS7* p7, Bytes& encoded, Bytes& content) {
    PKCS7* inner = p7 && p7->d.sign ? p7->d.sign->contents : nullptr;
    if (!inner) return false;
    if (PKCS7_type_is_data(inner)) {
        encoded = content = bytes(inner->d.data);
        return encoded.data != nullptr;
    }
    if (!PKCS7_type_is_other(inner) || !inner->d.other) return false;
    encoded = attribute_bytes(inner->d.other);
    if (!encoded.data || encoded.size > max_payload) return false;
    if (inner->d.other->type == V_ASN1_SEQUENCE) return sequence_body(encoded, content);
    if (inner->d.other->type == V_ASN1_OCTET_STRING) { content = encoded; return true; }
    return false;
}

const ASN1_TYPE* single_attribute(STACK_OF(X509_ATTRIBUTE)* attributes, int nid, bool& valid) {
    const int count = attributes ? sk_X509_ATTRIBUTE_num(attributes) : 0;
    if (count > max_attributes) { valid = false; return nullptr; }
    X509_ATTRIBUTE* match = nullptr;
    for (int i = 0; i < count; ++i) {
        X509_ATTRIBUTE* value = sk_X509_ATTRIBUTE_value(attributes, i);
        if (!value || OBJ_obj2nid(X509_ATTRIBUTE_get0_object(value)) != nid) continue;
        if (match) { valid = false; return nullptr; }
        match = value;
    }
    if (!match) return nullptr;
    if (X509_ATTRIBUTE_count(match) != 1) { valid = false; return nullptr; }
    return X509_ATTRIBUTE_get0_type(match, 0);
}

X509* signer_certificate(PKCS7_SIGNER_INFO* signer, STACK_OF(X509)* bag) {
    if (!signer || !signer->issuer_and_serial || !signer->issuer_and_serial->issuer ||
        !signer->issuer_and_serial->serial || !bag || sk_X509_num(bag) > max_certificates) return nullptr;
    X509* found = nullptr;
    for (int i = 0; i < sk_X509_num(bag); ++i) {
        X509* value = sk_X509_value(bag, i);
        if (!value || X509_NAME_cmp(X509_get_issuer_name(value), signer->issuer_and_serial->issuer) ||
            ASN1_INTEGER_cmp(X509_get0_serialNumber(value), signer->issuer_and_serial->serial)) continue;
        if (found && X509_cmp(found, value)) return nullptr;
        found = value;
    }
    return found;
}

bool null_parameters(const X509_ALGOR* algorithm) {
    if (!algorithm) return false;
    int type = V_ASN1_UNDEF;
    X509_ALGOR_get0(nullptr, &type, nullptr, algorithm);
    return type == V_ASN1_UNDEF || type == V_ASN1_NULL;
}

const EVP_MD* digest_algorithm(const X509_ALGOR* algorithm) {
    if (!null_parameters(algorithm)) return nullptr;
    const ASN1_OBJECT* object = nullptr;
    X509_ALGOR_get0(&object, nullptr, nullptr, algorithm);
    const EVP_MD* result = object ? EVP_get_digestbyobj(object) : nullptr;
    return result && EVP_MD_get_size(result) > 0 && EVP_MD_get_size(result) <= EVP_MAX_MD_SIZE ? result : nullptr;
}

bool digest_matches(const EVP_MD* md, Bytes content, Bytes expected) {
    unsigned char actual[EVP_MAX_MD_SIZE]{};
    unsigned int length = 0;
    return md && content.data && EVP_Digest(content.data, content.size, actual, &length, md, nullptr) == 1 &&
        expected.size == length && expected.data && CRYPTO_memcmp(actual, expected.data, length) == 0;
}

bool pss_parameters(EVP_PKEY_CTX* context, const X509_ALGOR* algorithm, const EVP_MD* md) {
    int type = V_ASN1_UNDEF;
    const void* raw = nullptr;
    X509_ALGOR_get0(nullptr, &type, &raw, algorithm);
    if (type != V_ASN1_SEQUENCE || !raw) return false;
    const Bytes encoded = bytes(static_cast<const ASN1_STRING*>(raw));
    if (!encoded.data || encoded.size > 4096) return false;
    const auto* cursor = encoded.data;
    Handle<RSA_PSS_PARAMS, RSA_PSS_PARAMS_free> params(
        d2i_RSA_PSS_PARAMS(nullptr, &cursor, static_cast<long>(encoded.size)), RSA_PSS_PARAMS_free);
    if (!params || cursor != encoded.data + encoded.size) return false;
    const EVP_MD* pss_md = params->hashAlgorithm ? digest_algorithm(params->hashAlgorithm) : EVP_sha1();
    const EVP_MD* mask_md = EVP_sha1();
    if (!pss_md || EVP_MD_get_type(pss_md) != EVP_MD_get_type(md)) return false;
    if (params->maskGenAlgorithm) {
        const ASN1_OBJECT* mask_object = nullptr;
        X509_ALGOR_get0(&mask_object, &type, &raw, params->maskGenAlgorithm);
        if (!mask_object || OBJ_obj2nid(mask_object) != NID_mgf1 || type != V_ASN1_SEQUENCE || !raw) return false;
        const Bytes mask_bytes = bytes(static_cast<const ASN1_STRING*>(raw));
        cursor = mask_bytes.data;
        Handle<X509_ALGOR, X509_ALGOR_free> mask(
            mask_bytes.data ? d2i_X509_ALGOR(nullptr, &cursor, static_cast<long>(mask_bytes.size)) : nullptr,
            X509_ALGOR_free);
        if (!mask || cursor != mask_bytes.data + mask_bytes.size || !(mask_md = digest_algorithm(mask.get()))) return false;
    }
    std::int64_t salt = 20, trailer = 1;
    if ((params->saltLength && !ASN1_INTEGER_get_int64(&salt, params->saltLength)) ||
        (params->trailerField && !ASN1_INTEGER_get_int64(&trailer, params->trailerField)) ||
        salt < 0 || salt > INT_MAX || trailer != 1) return false;
    return EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, mask_md) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(context, static_cast<int>(salt)) > 0;
}

bool verify_signature_value(PKCS7_SIGNER_INFO* signer, X509* certificate,
                            const EVP_MD* md, Bytes content) {
    if (!signer || !certificate || !signer->digest_enc_alg || !md) return false;
    const Bytes signature = bytes(signer->enc_digest);
    if (!signature.data || signature.size > 16384) return false;
    Handle<EVP_PKEY, EVP_PKEY_free> key(X509_get_pubkey(certificate), EVP_PKEY_free);
    Handle<EVP_MD_CTX, EVP_MD_CTX_free> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!key || !context) return false;
    const ASN1_OBJECT* algorithm = nullptr;
    X509_ALGOR_get0(&algorithm, nullptr, nullptr, signer->digest_enc_alg);
    const int nid = algorithm ? OBJ_obj2nid(algorithm) : NID_undef;
    const int key_type = EVP_PKEY_base_id(key.get());
    const bool pss = nid == NID_rsassaPss;
    int signature_digest = NID_undef, signature_key = NID_undef;
    if (nid == NID_rsaEncryption) {
        if (key_type != EVP_PKEY_RSA || !null_parameters(signer->digest_enc_alg)) return false;
    } else if (pss) {
        if (key_type != EVP_PKEY_RSA && key_type != EVP_PKEY_RSA_PSS) return false;
    } else {
        if (!OBJ_find_sigid_algs(nid, &signature_digest, &signature_key) ||
            signature_digest != EVP_MD_get_type(md) || signature_key != key_type ||
            !null_parameters(signer->digest_enc_alg)) return false;
    }
    EVP_PKEY_CTX* key_context = nullptr;
    if (EVP_DigestVerifyInit(context.get(), &key_context, md, nullptr, key.get()) <= 0 ||
        (pss && !pss_parameters(key_context, signer->digest_enc_alg, md))) return false;
    return EVP_DigestVerify(context.get(), signature.data, signature.size, content.data, content.size) == 1;
}

bool verify_signer(PKCS7_SIGNER_INFO* signer, X509* certificate, Bytes content,
                   const ASN1_OBJECT* content_type, bool countersignature, Verification& verification) {
    if (!signer || !certificate || !content.data) {
        detail(verification, "Signer certificate or signed content is missing or ambiguous");
        return false;
    }
    const EVP_MD* md = digest_algorithm(signer->digest_alg);
    if (!md) { detail(verification, "Unsupported or malformed signer digest algorithm"); return false; }
    const int count = signer->auth_attr ? sk_X509_ATTRIBUTE_num(signer->auth_attr) : 0;
    if (count > max_attributes || ((countersignature || content_type) && count == 0)) {
        detail(verification, "Signed attributes are missing or exceed their resource limit"); return false;
    }
    std::vector<unsigned char> encoded_attributes;
    if (count) {
        bool valid = true;
        const ASN1_TYPE* imprint = single_attribute(signer->auth_attr, NID_pkcs9_messageDigest, valid);
        const ASN1_TYPE* type = single_attribute(signer->auth_attr, NID_pkcs9_contentType, valid);
        if (!valid || !imprint || imprint->type != V_ASN1_OCTET_STRING ||
            !digest_matches(md, content, bytes(imprint->value.octet_string)) ||
            // Legacy Microsoft timestamp services include contentType=data in
            // countersignatures, although RFC 5652 countersignatures omit it.
            // The messageDigest still has to bind the parent's signature bytes.
            (countersignature && type && (type->type != V_ASN1_OBJECT ||
                OBJ_obj2nid(type->value.object) != NID_pkcs7_data)) ||
            (!countersignature && (!type || type->type != V_ASN1_OBJECT ||
                !content_type || OBJ_cmp(type->value.object, content_type)))) {
            detail(verification, "Signed messageDigest or contentType does not match the signed content");
            return false;
        }
        const int length = ASN1_item_i2d(reinterpret_cast<ASN1_VALUE*>(signer->auth_attr), nullptr,
                                         ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY));
        if (length <= 0 || static_cast<std::size_t>(length) > max_payload) return false;
        encoded_attributes.resize(static_cast<std::size_t>(length));
        auto* cursor = encoded_attributes.data();
        if (ASN1_item_i2d(reinterpret_cast<ASN1_VALUE*>(signer->auth_attr), &cursor,
                          ASN1_ITEM_rptr(PKCS7_ATTR_VERIFY)) != length) return false;
        content = {encoded_attributes.data(), encoded_attributes.size()};
    }
    ERR_clear_error();
    const bool valid = verify_signature_value(signer, certificate, md, content);
    if (!valid) {
        const std::string error = errors();
        detail(verification, "Signature value verification failed" + (error.empty() ? std::string() : ": " + error));
    }
    ERR_clear_error();
    return valid;
}

std::optional<std::time_t> timestamp_time(const ASN1_TIME* value) {
    if (!value || ASN1_TIME_check(value) != 1) return std::nullopt;
    Handle<ASN1_TIME, ASN1_TIME_free> epoch(ASN1_TIME_set(nullptr, 0), ASN1_TIME_free);
    int days = 0, seconds = 0;
    if (!epoch || !ASN1_TIME_diff(&days, &seconds, epoch.get(), value)) return std::nullopt;
    const std::int64_t time = static_cast<std::int64_t>(days) * 86400 + seconds;
    if (time < static_cast<std::int64_t>(std::numeric_limits<std::time_t>::min()) ||
        time > static_cast<std::int64_t>(std::numeric_limits<std::time_t>::max())) return std::nullopt;
    return static_cast<std::time_t>(time);
}

std::string format_time(std::time_t value) {
    Handle<ASN1_TIME, ASN1_TIME_free> time(ASN1_TIME_set(nullptr, value), ASN1_TIME_free);
    std::tm parsed{};
    char output[40]{};
    if (!time || !ASN1_TIME_to_tm(time.get(), &parsed) ||
        !std::strftime(output, sizeof(output), "%Y-%m-%dT%H:%M:%SZ", &parsed)) return {};
    return output;
}

void merge_revocation(std::string& target, const std::string& source) {
    if (target == "revoked" || source == "revoked") target = "revoked";
    else if (target == "unknown" || source == "unknown") target = "unknown";
    else if (target == "good" || source == "good") target = "good";
    else target = "not_checked";
}

struct TimestampResult {
    std::string status = "invalid";
    std::string revocation = "not_checked";
    std::optional<std::time_t> time;
    std::vector<std::string> details;
};

bool tsa_name_matches(GENERAL_NAME* name, X509* certificate) {
    if (!name) return true;
    if (name->type == GEN_DIRNAME && !X509_NAME_cmp(name->d.dirn, X509_get_subject_name(certificate))) return true;
    Handle<GENERAL_NAMES, GENERAL_NAMES_free> names(
        static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(certificate, NID_subject_alt_name, nullptr, nullptr)),
        GENERAL_NAMES_free);
    if (!names) return false;
    for (int i = 0; i < sk_GENERAL_NAME_num(names.get()); ++i)
        if (!GENERAL_NAME_cmp(name, sk_GENERAL_NAME_value(names.get(), i))) return true;
    return false;
}

bool check_ess(CMS_SignerInfo* signer, const ChainResult& verified_chain, bool only_signer) {
    const auto get = [signer](int nid, bool& valid) -> const ASN1_TYPE* {
        const int index = CMS_signed_get_attr_by_NID(signer, nid, -1);
        if (index < 0) return nullptr;
        if (CMS_signed_get_attr_by_NID(signer, nid, index) >= 0) { valid = false; return nullptr; }
        X509_ATTRIBUTE* attribute = CMS_signed_get_attr(signer, index);
        if (!attribute || X509_ATTRIBUTE_count(attribute) != 1) { valid = false; return nullptr; }
        return X509_ATTRIBUTE_get0_type(attribute, 0);
    };
    bool valid = true;
    const ASN1_TYPE* v1 = get(NID_id_smime_aa_signingCertificate, valid);
    const ASN1_TYPE* v2 = get(NID_id_smime_aa_signingCertificateV2, valid);
    Handle<ESS_SIGNING_CERT, ESS_SIGNING_CERT_free> first(nullptr, ESS_SIGNING_CERT_free);
    Handle<ESS_SIGNING_CERT_V2, ESS_SIGNING_CERT_V2_free> second(nullptr, ESS_SIGNING_CERT_V2_free);
    if (!valid || (!v1 && !v2)) return false;
    for (const auto* attr : {v1, v2}) {
        if (!attr) continue;
        const Bytes data = attribute_bytes(attr);
        if (attr->type != V_ASN1_SEQUENCE || !data.data || data.size > max_payload) return false;
        const auto* cursor = data.data;
        if (attr == v1) first.reset(d2i_ESS_SIGNING_CERT(nullptr, &cursor, static_cast<long>(data.size)));
        else second.reset(d2i_ESS_SIGNING_CERT_V2(nullptr, &cursor, static_cast<long>(data.size)));
        if (cursor != data.data + data.size || (attr == v1 ? !first : !second)) return false;
        if (only_signer) {
            const auto projected = first_ess_certificate(data);
            if (projected.empty()) return false;
            cursor = projected.data();
            if (attr == v1) first.reset(d2i_ESS_SIGNING_CERT(nullptr, &cursor, static_cast<long>(projected.size())));
            else second.reset(d2i_ESS_SIGNING_CERT_V2(nullptr, &cursor, static_cast<long>(projected.size())));
            if (cursor != projected.data() + projected.size() || (attr == v1 ? !first : !second)) return false;
        }
    }
    const auto free_stack = [](STACK_OF(X509)* value) { sk_X509_pop_free(value, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(free_stack)> candidates(sk_X509_new_null(), free_stack);
    if (!candidates || verified_chain.encoded_chain.empty()) return false;
    for (const auto& encoded : verified_chain.encoded_chain) {
        if (encoded.empty() || encoded.size() > max_payload || encoded.size() > LONG_MAX) return false;
        const auto* cursor = encoded.data();
        Handle<X509, X509_free> certificate(d2i_X509(nullptr, &cursor, static_cast<long>(encoded.size())), X509_free);
        if (!certificate || cursor != encoded.data() + encoded.size() ||
            !sk_X509_push(candidates.get(), certificate.get())) return false;
        certificate.release();
    }
    return OSSL_ESS_check_signing_certs(first.get(), second.get(), candidates.get(), 1) == 1;
}

TimestampResult rfc3161(Bytes raw, Bytes original_signature, STACK_OF(X509)* additional_certificates,
                        const Options& options, bool enforce_all_ess) {
    TimestampResult result;
    const auto fail = [&result](const char* message) { result.details.push_back(message); return result; };
    if (!raw.data || !raw.size || raw.size > max_payload || raw.size > LONG_MAX) return fail("Invalid RFC3161 token payload");
    const auto* cursor = raw.data;
    Handle<CMS_ContentInfo, CMS_ContentInfo_free> token(
        d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(raw.size)), CMS_ContentInfo_free);
    if (!token || !zero_tail(cursor, raw.data + raw.size) ||
        OBJ_obj2nid(CMS_get0_type(token.get())) != NID_pkcs7_signed ||
        oid(CMS_get0_eContentType(token.get())) != tst_info_oid) return fail("RFC3161 token must contain CMS SignedData with TSTInfo");
    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(token.get());
    if (!signers || sk_CMS_SignerInfo_num(signers) != 1) return fail("RFC3161 requires exactly one signer");
    ASN1_OCTET_STRING** content = CMS_get0_content(token.get());
    const Bytes data = content ? bytes(*content) : Bytes{};
    if (!data.data || data.size > max_payload) return fail("RFC3161 has no TSTInfo content");
    cursor = data.data;
    Handle<TS_TST_INFO, TS_TST_INFO_free> info(
        d2i_TS_TST_INFO(nullptr, &cursor, static_cast<long>(data.size)), TS_TST_INFO_free);
    if (!info || cursor != data.data + data.size || TS_TST_INFO_get_version(info.get()) != 1)
        return fail("Invalid RFC3161 TSTInfo encoding or version");
    const int extension_count = TS_TST_INFO_get_ext_count(info.get());
    if (extension_count > max_attributes) return fail("RFC3161 extension count exceeds its resource limit");
    for (int i = 0; i < extension_count; ++i) {
        X509_EXTENSION* extension = TS_TST_INFO_get_ext(info.get(), i);
        if (!extension || X509_EXTENSION_get_critical(extension))
            return fail("RFC3161 contains an unsupported critical TSTInfo extension");
    }
    const Bytes generalized_time = bytes(TS_TST_INFO_get_time(info.get()));
    if (generalized_time.size < 15 || generalized_time.data[generalized_time.size - 1] != 'Z' ||
        !std::all_of(generalized_time.data, generalized_time.data + 14,
                     [](unsigned char digit) { return digit >= '0' && digit <= '9'; }))
        return fail("RFC3161 genTime must include seconds and use UTC");
    result.time = timestamp_time(TS_TST_INFO_get_time(info.get()));
    const std::time_t now = options.verification_time ? options.verification_time : std::time(nullptr);
    if (!result.time || *result.time > now) return fail("RFC3161 genTime is invalid or lies in the future");
    TS_MSG_IMPRINT* imprint = TS_TST_INFO_get_msg_imprint(info.get());
    if (!imprint || !digest_matches(digest_algorithm(TS_MSG_IMPRINT_get_algo(imprint)), original_signature,
                                    bytes(TS_MSG_IMPRINT_get_msg(imprint))))
        return fail("RFC3161 messageImprint does not bind the original signature value");
    const auto free_bag = [](STACK_OF(X509)* value) { sk_X509_pop_free(value, X509_free); };
    std::unique_ptr<STACK_OF(X509), decltype(free_bag)> bag(CMS_get1_certs(token.get()), free_bag);
    if (!bag) bag.reset(sk_X509_new_null());
    if (!bag || sk_X509_num(bag.get()) > max_certificates)
        return fail("RFC3161 certificate bag exceeds its resource limit");
    // Windows accepts timestamp signer/intermediates from the containing
    // signature's additional store as well as from the timestamp token itself.
    for (int i = 0; additional_certificates && i < sk_X509_num(additional_certificates); ++i) {
        X509* value = sk_X509_value(additional_certificates, i);
        if (!value) continue;
        bool duplicate = false;
        for (int j = 0; j < sk_X509_num(bag.get()); ++j)
            if (!X509_cmp(value, sk_X509_value(bag.get(), j))) { duplicate = true; break; }
        if (duplicate) continue;
        if (sk_X509_num(bag.get()) >= max_certificates || X509_up_ref(value) != 1)
            return fail("Combined RFC3161 certificate bag exceeds its resource limit");
        if (!sk_X509_push(bag.get(), value)) { X509_free(value); return fail("Cannot allocate RFC3161 certificate bag"); }
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, 0);
    X509* certificate = nullptr;
    for (int i = 0; i < sk_X509_num(bag.get()); ++i) {
        X509* value = sk_X509_value(bag.get(), i);
        if (!value || CMS_SignerInfo_cert_cmp(signer, value)) continue;
        if (certificate && X509_cmp(certificate, value)) return fail("Ambiguous RFC3161 signer certificate");
        certificate = value;
    }
    if (!certificate || !tsa_name_matches(TS_TST_INFO_get_tsa(info.get()), certificate))
        return fail("RFC3161 signer identity or TSA name is invalid");
    ERR_clear_error();
    if (CMS_verify(token.get(), bag.get(), nullptr, nullptr, nullptr,
                   CMS_BINARY | CMS_NO_SIGNER_CERT_VERIFY | CMS_NOINTERN) != 1) {
        result.details.push_back("RFC3161 CMS signature is invalid: " + errors());
        return result;
    }
    const auto free_crls = [](STACK_OF(X509_CRL)* value) { sk_X509_CRL_pop_free(value, X509_CRL_free); };
    std::unique_ptr<STACK_OF(X509_CRL), decltype(free_crls)> crls(CMS_get1_crls(token.get()), free_crls);
    const ChainResult chain = verify_chain(certificate, bag.get(), options, result.time, true, crls.get());
    result.details = chain.details;
    ERR_clear_error();
    if (!check_ess(signer, chain, true)) {
        result.details.push_back("RFC3161 first ESS certificate binding does not match the TSA signer: " + errors());
        return result;
    }
    ERR_clear_error();
    if (!check_ess(signer, chain, false)) {
        const std::string error = errors();
        if (enforce_all_ess) {
            result.details.push_back("Strict RFC3161 ESS verification cannot validate additional certificate or attribute-certificate references: " + error);
            return result;
        }
        result.details.push_back("Microsoft Authenticode compatibility: the first ESS certificate hash and issuerSerial are verified; additional ESS certificate or attribute-certificate references could not be validated and are ignored: " + error);
    }
    result.revocation = chain.revocation;
    result.status = chain.status == "trusted" && chain.revocation != "revoked" ? "valid" : "untrusted";
    return result;
}

TimestampResult legacy(Bytes raw, Bytes original_signature, STACK_OF(X509)* bag, const Options& options,
                       STACK_OF(X509_CRL)* crls) {
    TimestampResult result;
    if (!raw.data || !raw.size || raw.size > max_payload || raw.size > LONG_MAX) return result;
    const auto* cursor = raw.data;
    Handle<PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO_free> signer(
        d2i_PKCS7_SIGNER_INFO(nullptr, &cursor, static_cast<long>(raw.size)), PKCS7_SIGNER_INFO_free);
    if (!signer || !zero_tail(cursor, raw.data + raw.size)) return result;
    bool valid = true;
    const ASN1_TYPE* signed_time = single_attribute(signer->auth_attr, NID_pkcs9_signingTime, valid);
    const ASN1_TIME* time = nullptr;
    if (signed_time && signed_time->type == V_ASN1_UTCTIME) time = signed_time->value.utctime;
    if (signed_time && signed_time->type == V_ASN1_GENERALIZEDTIME) time = signed_time->value.generalizedtime;
    result.time = valid ? timestamp_time(time) : std::nullopt;
    const std::time_t now = options.verification_time ? options.verification_time : std::time(nullptr);
    if (!result.time || *result.time > now) { result.details.push_back("PKCS9 signingTime is missing, malformed or in the future"); return result; }
    X509* certificate = signer_certificate(signer.get(), bag);
    Verification verification;
    if (!verify_signer(signer.get(), certificate, original_signature, nullptr, true, verification)) {
        result.details = std::move(verification.details);
        return result;
    }
    const ChainResult chain = verify_chain(certificate, bag, options, result.time, true, crls, false);
    result.revocation = chain.revocation;
    result.details = chain.details;
    result.status = chain.status == "trusted" && chain.revocation != "revoked" ? "valid" : "untrusted";
    return result;
}

std::optional<std::time_t> verify_timestamps(PKCS7_SIGNER_INFO* signer, STACK_OF(X509)* bag,
                                           const Options& options, Verification& verification,
                                           STACK_OF(X509_CRL)* crls) {
    verification.timestamp = "absent";
    const int count = signer->unauth_attr ? sk_X509_ATTRIBUTE_num(signer->unauth_attr) : 0;
    if (count > max_attributes) { verification.timestamp = "invalid"; return std::nullopt; }
    bool has_rfc3161 = false;
    for (int i = 0; i < count; ++i) {
        X509_ATTRIBUTE* value = sk_X509_ATTRIBUTE_value(signer->unauth_attr, i);
        if (!value) continue;
        const std::string id = oid(X509_ATTRIBUTE_get0_object(value));
        if (id == microsoft_timestamp_oid || id == standard_timestamp_oid) has_rfc3161 = true;
    }
    std::optional<std::time_t> trusted_time;
    int timestamp_count = 0;
    for (int i = 0; i < count; ++i) {
        X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(signer->unauth_attr, i);
        if (!attr) continue;
        const std::string id = oid(X509_ATTRIBUTE_get0_object(attr));
        const bool rfc = id == microsoft_timestamp_oid || id == standard_timestamp_oid;
        const bool pkcs9 = id == "1.2.840.113549.1.9.6";
        if ((has_rfc3161 && !rfc) || (!has_rfc3161 && !pkcs9)) continue;
        if (verification.timestamp == "absent") verification.timestamp = "invalid";
        const int values = X509_ATTRIBUTE_count(attr);
        if (values <= 0) detail(verification, "Timestamp attribute has no values");
        for (int j = 0; j < values; ++j) {
            if (++timestamp_count > max_timestamps) {
                detail(verification, "Timestamp count exceeds the limit of 64");
                verification.timestamp = "invalid";
                return std::nullopt;
            }
            const Bytes raw = attribute_bytes(X509_ATTRIBUTE_get0_type(attr, j));
            const TimestampResult timestamp = rfc ? rfc3161(raw, bytes(signer->enc_digest), bag, options,
                options.strict_timestamps || id == standard_timestamp_oid) :
                legacy(raw, bytes(signer->enc_digest), bag, options, crls);
            for (const auto& text : timestamp.details)
                detail(verification, "Timestamp " + std::to_string(timestamp_count - 1) + ": " + text);
            merge_revocation(verification.revocation, timestamp.revocation);
            if (timestamp.status == "valid") {
                verification.timestamp = "valid";
                if (!trusted_time) trusted_time = timestamp.time;
            } else if (verification.timestamp != "valid" && timestamp.status == "untrusted") {
                verification.timestamp = "untrusted";
            }
        }
    }
    return trusted_time;
}

void finalize(Verification& verification) {
    const bool timestamp = verification.timestamp == "valid" || verification.timestamp == "absent";
    const bool valid = verification.content_digest == "valid" && verification.cms_signature == "valid" &&
        verification.certificate_chain == "trusted" && timestamp && verification.revocation != "revoked";
    verification.overall = !valid ? "invalid" : verification.revocation == "unknown" ? "indeterminate" : "valid";
}

std::vector<std::uint8_t> unhex(const std::string& value) {
    if (value.empty() || value.size() % 2 || value.size() > 2 * EVP_MAX_MD_SIZE) return {};
    const auto digit = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> output;
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const int high = digit(value[i]), low = digit(value[i + 1]);
        if (high < 0 || low < 0) return {};
        output.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return output;
}

std::string content_verification(PKCS7* p7, const Signature& signature, Bytes encoded,
                                  const std::vector<std::uint8_t>& pe, bool catalog, Verification& output) {
    if (catalog) {
        if (signature.content_type != ctl_oid) { detail(output, "Catalog content type is not Microsoft CTL"); return "invalid"; }
        static constexpr const char* algorithms[] = {"2.16.840.1.101.3.4.2.1", "1.3.14.3.2.26",
            "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"};
        for (const char* algorithm : algorithms) {
            try {
                const auto digest = authenticode_digest(pe, algorithm);
                if (catalog_content_contains(encoded.data, encoded.size, digest)) return "valid";
            } catch (const ParseError& error) { detail(output, error.what()); }
        }
        detail(output, "The PE Authenticode digest is absent from the catalog members");
        return "invalid";
    }
    if (!p7 || signature.content_type != spc_oid || signature.digest_algorithm.oid.empty()) return "error";
    const auto expected = unhex(signature.embedded_digest);
    if (expected.empty()) return "error";
    try {
        const auto actual = authenticode_digest(pe, signature.digest_algorithm.oid);
        if (actual.size() == expected.size() && CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0)
            return "valid";
        detail(output, "The embedded image digest does not match the PE Authenticode digest");
        return "invalid";
    } catch (const ParseError& error) { detail(output, error.what()); return "error"; }
}

void verify_decoded(PKCS7* p7, std::size_t index, const std::vector<std::uint8_t>& pe,
                    const Options& options, Analysis& analysis, bool catalog, unsigned depth) {
    if (index >= analysis.signatures.size() || depth > 8) return;
    Signature& signature = analysis.signatures[index];
    Bytes encoded, content;
    const bool has_content = signed_content(p7, encoded, content);
    Verification image;
    image.content_digest = has_content ? content_verification(p7, signature, encoded, pe, catalog, image) : "error";
    STACK_OF(PKCS7_SIGNER_INFO)* signers = PKCS7_get_signer_info(p7);
    const int count = signers ? std::min(sk_PKCS7_SIGNER_INFO_num(signers), 128) : 0;
    std::size_t metadata_signer = 0;
    struct Nested { Bytes data; int signer; };
    std::vector<Nested> nested;
    for (int i = 0; i < count; ++i) {
        PKCS7_SIGNER_INFO* signer = sk_PKCS7_SIGNER_INFO_value(signers, i);
        if (!signer) continue;
        if (metadata_signer >= signature.signers.size()) break;
        Verification& verification = signature.signers[metadata_signer++].verification;
        verification = image;
        verification.cms_signature = "invalid";
        verification.certificate_chain = "untrusted";
        verification.revocation = "not_checked";
        verification.overall = "invalid";
        X509* certificate = signer_certificate(signer, p7->d.sign->cert);
        const ASN1_OBJECT* content_type = p7->d.sign->contents ? p7->d.sign->contents->type : nullptr;
        if (has_content && verify_signer(signer, certificate, content, content_type, false, verification))
            verification.cms_signature = "valid";
        const auto time = verify_timestamps(signer, p7->d.sign->cert, options, verification, p7->d.sign->crl);
        const ChainResult chain = verify_chain(certificate, p7->d.sign->cert, options, time, false, p7->d.sign->crl);
        verification.certificate_chain = chain.status;
        verification.error_code = chain.error_code;
        verification.chain = chain.chain;
        for (const auto& text : chain.details) detail(verification, text);
        merge_revocation(verification.revocation, chain.revocation);
        verification.verification_time = format_time(time.value_or(options.verification_time ?
            options.verification_time : std::time(nullptr)));
        finalize(verification);
        const int attributes = signer->unauth_attr ? std::min(sk_X509_ATTRIBUTE_num(signer->unauth_attr), max_attributes) : 0;
        for (int j = 0; j < attributes; ++j) {
            X509_ATTRIBUTE* attr = sk_X509_ATTRIBUTE_value(signer->unauth_attr, j);
            if (!attr || oid(X509_ATTRIBUTE_get0_object(attr)) != nested_oid) continue;
            for (int k = 0; k < X509_ATTRIBUTE_count(attr) && nested.size() < 64; ++k)
                nested.push_back({attribute_bytes(X509_ATTRIBUTE_get0_type(attr, k)), i});
        }
    }
    if (!signature.signers.empty()) signature.verification = signature.signers.front().verification;
    else { signature.verification = image; signature.verification.cms_signature = "invalid"; finalize(signature.verification); }
    std::vector<std::size_t> children;
    for (std::size_t i = index + 1; i < analysis.signatures.size(); ++i)
        if (analysis.signatures[i].parent_signature == static_cast<int>(index)) children.push_back(i);
    std::size_t child = 0;
    for (const auto& raw : nested) {
        auto parsed = decode(raw.data);
        if (!parsed) { ERR_clear_error(); continue; }
        while (child < children.size() && analysis.signatures[children[child]].parent_signer != raw.signer) ++child;
        if (child >= children.size()) break;
        verify_decoded(parsed.get(), children[child++], pe, options, analysis, false, depth + 1);
    }
}

} // namespace

void verify_pkcs7(const std::uint8_t* data, std::size_t size, std::size_t certificate_record,
                  const std::vector<std::uint8_t>& pe, const Options& options, Analysis& result, bool catalog) {
    ERR_clear_error();
    auto p7 = decode({data, size});
    if (!p7) { ERR_clear_error(); return; }
    for (std::size_t i = 0; i < result.signatures.size(); ++i) {
        Signature& signature = result.signatures[i];
        if (signature.certificate_record == certificate_record && signature.parent_signature == -1 &&
            signature.verification.overall == "not_performed") {
            verify_decoded(p7.get(), i, pe, options, result, catalog, 0);
            break;
        }
    }
    ERR_clear_error();
}

} // namespace pesign::detail
