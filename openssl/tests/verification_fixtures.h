#pragma once

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/ess.h>
#include <openssl/evp.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace verification_fixture {

using Bytes = std::vector<std::uint8_t>;
constexpr const char* spc_oid = "1.3.6.1.4.1.311.2.1.4";
constexpr const char* tst_oid = "1.2.840.113549.1.9.16.1.4";
constexpr const char* timestamp_oid = "1.3.6.1.4.1.311.3.3.1";

inline void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}
inline void ssl_check(bool condition, const char* operation) {
    if (condition) return;
    std::string message(operation);
    for (auto error = ERR_get_error(); error; error = ERR_get_error()) {
        char buffer[256]{};
        ERR_error_string_n(error, buffer, sizeof(buffer));
        message += std::string("; ") + buffer;
    }
    throw std::runtime_error(message);
}
template<typename T, void (*Free)(T*)>
using Ptr = std::unique_ptr<T, decltype(Free)>;
template<typename T, void (*Free)(T*)>
Ptr<T, Free> own(T* value, const char* operation) {
    ssl_check(value != nullptr, operation);
    return Ptr<T, Free>(value, Free);
}
using Key = Ptr<EVP_PKEY, EVP_PKEY_free>;
using Cert = Ptr<X509, X509_free>;
using P7 = Ptr<PKCS7, PKCS7_free>;

template<typename T, typename Encoder>
Bytes der(T* value, Encoder encode) {
    const int size = encode(value, nullptr);
    ssl_check(size > 0, "measure DER");
    Bytes bytes(static_cast<std::size_t>(size));
    auto* cursor = bytes.data();
    ssl_check(encode(value, &cursor) == size, "encode DER");
    return bytes;
}
inline Bytes tlv(std::uint8_t tag, const Bytes& contents) {
    Bytes result{tag};
    if (contents.size() < 128) {
        result.push_back(static_cast<std::uint8_t>(contents.size()));
    } else {
        Bytes length;
        for (auto size = contents.size(); size; size >>= 8)
            length.insert(length.begin(), static_cast<std::uint8_t>(size & 255));
        result.push_back(static_cast<std::uint8_t>(0x80 | length.size()));
        result.insert(result.end(), length.begin(), length.end());
    }
    result.insert(result.end(), contents.begin(), contents.end());
    return result;
}
inline Bytes concat(Bytes first, const Bytes& second) {
    first.insert(first.end(), second.begin(), second.end());
    return first;
}
inline Bytes oid(const char* text) {
    auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(text, 1), "OID");
    return der(object.get(), i2d_ASN1_OBJECT);
}
inline Bytes content_bytes(const Bytes& encoded) {
    const unsigned char* cursor = encoded.data();
    long length = 0;
    int tag = 0, value_class = 0;
    const int flags = ASN1_get_object(&cursor, &length, &tag, &value_class,
                                      static_cast<long>(encoded.size()));
    require((flags & 0x81) == 0 && length >= 0 &&
                length == encoded.data() + encoded.size() - cursor, "fixture DER wrapper");
    return Bytes(cursor, cursor + length);
}
inline Bytes hash(const Bytes& bytes, const EVP_MD* md = EVP_sha256()) {
    Bytes result(EVP_MAX_MD_SIZE);
    unsigned int size = 0;
    ssl_check(EVP_Digest(bytes.data(), bytes.size(), result.data(), &size, md, nullptr) == 1,
              "digest fixture");
    result.resize(size);
    return result;
}
inline std::string hex(const Bytes& bytes) {
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (auto byte : bytes) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}
inline std::filesystem::path ocsp_cache_path(const std::filesystem::path& directory,
                                            X509* leaf, X509* issuer) {
    auto id = own<OCSP_CERTID, OCSP_CERTID_free>(OCSP_cert_to_id(EVP_sha1(), leaf, issuer), "OCSP cache ID");
    const auto identity = hex(hash(der(id.get(), i2d_OCSP_CERTID)));
    const auto text = std::string("ocsp:http://127.0.0.1:1/offline.ocsp:") + identity;
    return directory / (hex(hash(Bytes(text.begin(), text.end()))) + ".ocsp");
}
inline Key make_key() {
    auto context = own<EVP_PKEY_CTX, EVP_PKEY_CTX_free>(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), "RSA context");
    ssl_check(EVP_PKEY_keygen_init(context.get()) == 1, "keygen init");
    ssl_check(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1, "RSA size");
    EVP_PKEY* key = nullptr;
    ssl_check(EVP_PKEY_generate(context.get(), &key) == 1, "keygen");
    return own<EVP_PKEY, EVP_PKEY_free>(key, "generated key");
}
inline void extension(X509* certificate, X509* issuer, int nid, const std::string& value) {
    X509V3_CTX context{};
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    auto ext = own<X509_EXTENSION, X509_EXTENSION_free>(
        X509V3_EXT_conf_nid(nullptr, &context, nid, const_cast<char*>(value.c_str())),
        "certificate extension");
    ssl_check(X509_add_ext(certificate, ext.get(), -1) == 1, "add extension");
}
inline Cert certificate(EVP_PKEY* key, long serial, const char* name,
                        X509* issuer = nullptr, EVP_PKEY* issuer_key = nullptr,
                        const char* eku = nullptr, bool ca = false,
                        const char* before = "20200101000000Z",
                        const char* after = "20400101000000Z",
                        const std::string& crl_uri = "http://127.0.0.1:1/offline.crl",
                        const std::string& ocsp_uri = "http://127.0.0.1:1/offline.ocsp",
                        const std::string& ca_uri = "") {
    auto cert = own<X509, X509_free>(X509_new(), "certificate");
    ssl_check(X509_set_version(cert.get(), 2) == 1, "version");
    ssl_check(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial) == 1, "serial");
    ssl_check(ASN1_TIME_set_string_X509(X509_getm_notBefore(cert.get()), before) == 1, "notBefore");
    ssl_check(ASN1_TIME_set_string_X509(X509_getm_notAfter(cert.get()), after) == 1, "notAfter");
    auto* subject = X509_get_subject_name(cert.get());
    ssl_check(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(name), -1, -1, 0) == 1, "subject");
    ssl_check(X509_set_issuer_name(cert.get(), issuer ? X509_get_subject_name(issuer) : subject) == 1,
              "issuer");
    ssl_check(X509_set_pubkey(cert.get(), key) == 1, "public key");
    X509* extension_issuer = issuer ? issuer : cert.get();
    extension(cert.get(), extension_issuer, NID_basic_constraints,
              ca ? "critical,CA:TRUE,pathlen:2" : "critical,CA:FALSE");
    extension(cert.get(), extension_issuer, NID_key_usage,
              ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    extension(cert.get(), extension_issuer, NID_subject_key_identifier, "hash");
    extension(cert.get(), extension_issuer, NID_authority_key_identifier, "keyid:always");
    if (eku) extension(cert.get(), extension_issuer, NID_ext_key_usage, std::string("critical,") + eku);
    if (!crl_uri.empty()) extension(cert.get(), extension_issuer, NID_crl_distribution_points,
                                    "URI:" + crl_uri);
    if (!ocsp_uri.empty() || !ca_uri.empty()) {
        std::string access;
        if (!ocsp_uri.empty()) access = "OCSP;URI:" + ocsp_uri;
        if (!ca_uri.empty()) access += (access.empty() ? "" : ",") + std::string("caIssuers;URI:") + ca_uri;
        extension(cert.get(), extension_issuer, NID_info_access, access);
    }
    ssl_check(X509_sign(cert.get(), issuer_key ? issuer_key : key, EVP_sha256()) > 0,
              "sign certificate");
    return cert;
}

inline void put16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value);
    bytes.at(offset + 1) = static_cast<std::uint8_t>(value >> 8);
}
inline void put32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned int i = 0; i < 4; ++i)
        bytes.at(offset + i) = static_cast<std::uint8_t>(value >> (8 * i));
}
inline std::size_t security(bool plus) { return 0x98 + (plus ? 112 : 96) + 32; }
inline Bytes image(bool plus = false) {
    Bytes bytes(0x400, 0);
    put16(bytes, 0, 0x5a4d);
    put32(bytes, 0x3c, 0x80);
    put32(bytes, 0x80, 0x4550);
    put16(bytes, 0x84, plus ? 0x8664 : 0x14c);
    put16(bytes, 0x86, 1);
    put16(bytes, 0x94, plus ? 240 : 224);
    put16(bytes, 0x98, plus ? 0x20b : 0x10b);
    put32(bytes, 0x98 + 60, 0x200); // SizeOfHeaders.
    put32(bytes, 0x98 + (plus ? 108 : 92), 16);
    const auto section = 0x98 + (plus ? 240 : 224);
    put32(bytes, section + 8, 0x200);
    put32(bytes, section + 12, 0x1000);
    put32(bytes, section + 16, 0x200);
    put32(bytes, section + 20, 0x200);
    for (std::size_t i = 0x200; i < bytes.size(); ++i)
        bytes[i] = static_cast<std::uint8_t>(i * 37 + 19);
    return bytes;
}
// Independent fixture hash for the single-section contiguous PE above.
inline Bytes image_hash(const Bytes& bytes, bool plus = false, const EVP_MD* md = EVP_sha256()) {
    constexpr std::size_t checksum = 0x98 + 64;
    const auto entry = security(plus);
    Bytes authenticated(bytes.begin(), bytes.begin() + checksum);
    authenticated.insert(authenticated.end(), bytes.begin() + checksum + 4, bytes.begin() + entry);
    authenticated.insert(authenticated.end(), bytes.begin() + entry + 8, bytes.end());
    return hash(authenticated, md);
}
inline Bytes indirect_data(const Bytes& digest, int algorithm_nid = NID_sha256) {
    auto info = own<X509_SIG, X509_SIG_free>(X509_SIG_new(), "DigestInfo");
    X509_ALGOR* algorithm = nullptr;
    ASN1_OCTET_STRING* value = nullptr;
    X509_SIG_getm(info.get(), &algorithm, &value);
    X509_ALGOR_set0(algorithm, OBJ_dup(OBJ_nid2obj(algorithm_nid)), V_ASN1_NULL, nullptr);
    ssl_check(ASN1_OCTET_STRING_set(value, digest.data(), static_cast<int>(digest.size())) == 1,
              "image digest");
    const Bytes attribute = tlv(0x30, concat(oid("1.3.6.1.4.1.311.2.1.15"),
                                            tlv(0x30, Bytes{0x03, 0x01, 0x00})));
    return tlv(0x30, concat(attribute, der(info.get(), i2d_X509_SIG)));
}
inline P7 signed_data(const Bytes& content, const char* content_oid = spc_oid,
                      int type = V_ASN1_SEQUENCE) {
    auto p7 = own<PKCS7, PKCS7_free>(PKCS7_new(), "SignedData");
    ssl_check(PKCS7_set_type(p7.get(), NID_pkcs7_signed) == 1, "SignedData type");
    auto inner = own<PKCS7, PKCS7_free>(PKCS7_new(), "content");
    ASN1_OBJECT_free(inner->type);
    inner->type = OBJ_txt2obj(content_oid, 1);
    ssl_check(inner->type != nullptr, "content OID");
    inner->d.other = ASN1_TYPE_new();
    ssl_check(inner->d.other != nullptr, "content ANY");
    auto value = own<ASN1_STRING, ASN1_STRING_free>(ASN1_STRING_type_new(type), "content string");
    ssl_check(ASN1_STRING_set(value.get(), content.data(), static_cast<int>(content.size())) == 1,
              "content bytes");
    ASN1_TYPE_set(inner->d.other, type, value.release());
    ssl_check(PKCS7_set_content(p7.get(), inner.get()) == 1, "set content");
    inner.release();
    return p7;
}
inline PKCS7_SIGNER_INFO* signer(PKCS7* p7, X509* cert, EVP_PKEY* key,
                                const Bytes& authenticated_content,
                                const char* content_oid = spc_oid,
                                const char* signing_time = "260102030405Z",
                                const EVP_MD* digest_algorithm = EVP_sha256()) {
    auto* info = PKCS7_add_signature(p7, cert, key, digest_algorithm);
    ssl_check(info != nullptr, "add signature");
    ssl_check(PKCS7_add_certificate(p7, cert) == 1, "include signer cert");
    if (content_oid) {
        auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(content_oid, 1), "contentType");
        ssl_check(PKCS7_add_signed_attribute(info, NID_pkcs9_contentType,
                                            V_ASN1_OBJECT, object.get()) == 1, "contentType attr");
        object.release();
    }
    if (signing_time) {
        auto time = own<ASN1_UTCTIME, ASN1_UTCTIME_free>(ASN1_UTCTIME_new(), "signingTime");
        ssl_check(ASN1_UTCTIME_set_string(time.get(), signing_time) == 1, "signingTime value");
        ssl_check(PKCS7_add_signed_attribute(info, NID_pkcs9_signingTime,
                                            V_ASN1_UTCTIME, time.get()) == 1, "signingTime attr");
        time.release();
    }
    auto digest = own<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>(ASN1_OCTET_STRING_new(), "messageDigest");
    const auto bytes = hash(authenticated_content, digest_algorithm);
    ssl_check(ASN1_OCTET_STRING_set(digest.get(), bytes.data(), static_cast<int>(bytes.size())) == 1,
              "messageDigest value");
    ssl_check(PKCS7_add_signed_attribute(info, NID_pkcs9_messageDigest,
                                        V_ASN1_OCTET_STRING, digest.get()) == 1, "messageDigest attr");
    digest.release();
    ssl_check(PKCS7_SIGNER_INFO_sign(info) == 1, "sign attrs");
    return info;
}
inline void unsigned_attribute(PKCS7_SIGNER_INFO* signer_info, const char* object, const Bytes& value) {
    auto oid_value = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(object, 1), "unsigned OID");
    auto attr = own<X509_ATTRIBUTE, X509_ATTRIBUTE_free>(X509_ATTRIBUTE_create_by_OBJ(
        nullptr, oid_value.get(), V_ASN1_SEQUENCE, value.data(), static_cast<int>(value.size())), "unsigned attr");
    if (!signer_info->unauth_attr) signer_info->unauth_attr = sk_X509_ATTRIBUTE_new_null();
    ssl_check(signer_info->unauth_attr && sk_X509_ATTRIBUTE_push(signer_info->unauth_attr, attr.get()) > 0,
              "append unsigned attr");
    attr.release();
}
inline Bytes signature_bytes(PKCS7_SIGNER_INFO* info) {
    return Bytes(ASN1_STRING_get0_data(info->enc_digest),
                 ASN1_STRING_get0_data(info->enc_digest) + ASN1_STRING_length(info->enc_digest));
}
inline Bytes attach(const Bytes& unsigned_image, PKCS7* p7, bool plus = false) {
    Bytes bytes = unsigned_image;
    const auto payload = der(p7, i2d_PKCS7);
    const auto offset = bytes.size();
    const auto actual = payload.size() + 8;
    const auto aligned = (actual + 7) & ~std::size_t{7};
    bytes.resize(offset + aligned, 0);
    put32(bytes, security(plus), static_cast<std::uint32_t>(offset));
    put32(bytes, security(plus) + 4, static_cast<std::uint32_t>(aligned));
    put32(bytes, offset, static_cast<std::uint32_t>(actual));
    put16(bytes, offset + 4, 0x200);
    put16(bytes, offset + 6, 2);
    std::copy(payload.begin(), payload.end(), bytes.begin() + offset + 8);
    return bytes;
}
inline Bytes timestamp_info(const Bytes& signature, const char* time = "20260102030405Z") {
    auto info = own<TS_TST_INFO, TS_TST_INFO_free>(TS_TST_INFO_new(), "TSTInfo");
    ssl_check(TS_TST_INFO_set_version(info.get(), 1) == 1, "TST version");
    auto policy = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj("1.2.3.4.5", 1), "TST policy");
    ssl_check(TS_TST_INFO_set_policy_id(info.get(), policy.get()) == 1, "TST policy ID");
    auto imprint = own<TS_MSG_IMPRINT, TS_MSG_IMPRINT_free>(TS_MSG_IMPRINT_new(), "TST imprint");
    auto algorithm = own<X509_ALGOR, X509_ALGOR_free>(X509_ALGOR_new(), "TST algorithm");
    X509_ALGOR_set0(algorithm.get(), OBJ_dup(OBJ_nid2obj(NID_sha256)), V_ASN1_NULL, nullptr);
    ssl_check(TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm.get()) == 1, "TST imprint alg");
    auto digest = hash(signature);
    ssl_check(TS_MSG_IMPRINT_set_msg(imprint.get(), digest.data(), static_cast<int>(digest.size())) == 1,
              "TST imprint digest");
    ssl_check(TS_TST_INFO_set_msg_imprint(info.get(), imprint.get()) == 1, "TST imprint value");
    auto serial = own<ASN1_INTEGER, ASN1_INTEGER_free>(ASN1_INTEGER_new(), "TST serial");
    ssl_check(ASN1_INTEGER_set(serial.get(), 7) == 1, "TST serial value");
    ssl_check(TS_TST_INFO_set_serial(info.get(), serial.get()) == 1, "TST serial attr");
    auto when = own<ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_free>(ASN1_GENERALIZEDTIME_new(), "TST time");
    ssl_check(ASN1_GENERALIZEDTIME_set_string(when.get(), time) == 1, "TST time value");
    ssl_check(TS_TST_INFO_set_time(info.get(), when.get()) == 1, "TST generation time");
    return der(info.get(), i2d_TS_TST_INFO);
}
inline Bytes timestamp(X509* cert, EVP_PKEY* key, X509* intermediate, const Bytes& signature,
                       const char* time = "20260102030405Z", bool key_id = false,
                       X509* bound_cert = nullptr, X509* extra_reference = nullptr,
                       bool wrong_issuer_serial = false) {
    const auto content = timestamp_info(signature, time);
    auto cms = own<CMS_ContentInfo, CMS_ContentInfo_free>(
        CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_PARTIAL | CMS_BINARY), "CMS timestamp");
    auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(tst_oid, 1), "CMS content OID");
    ssl_check(CMS_set1_eContentType(cms.get(), object.get()) == 1, "CMS contentType");
    auto* cms_signer = CMS_add1_signer(cms.get(), cert, key, EVP_sha256(),
                                      CMS_BINARY | (key_id ? CMS_USE_KEYID : 0));
    ssl_check(cms_signer != nullptr, "CMS signer");
    const auto free_references = [](STACK_OF(X509)* value) { sk_X509_free(value); };
    std::unique_ptr<STACK_OF(X509), decltype(free_references)> references(
        extra_reference ? sk_X509_new_null() : nullptr, free_references);
    if (extra_reference)
        ssl_check(references && sk_X509_push(references.get(), extra_reference) > 0, "ESS extra reference");
    auto ess = own<ESS_SIGNING_CERT_V2, ESS_SIGNING_CERT_V2_free>(
        OSSL_ESS_signing_cert_v2_new_init(EVP_sha256(), bound_cert ? bound_cert : cert, references.get(), 1), "ESS binding");
    auto ess_bytes = der(ess.get(), i2d_ESS_SIGNING_CERT_V2);
    if (wrong_issuer_serial) {
        require(!extra_reference && ess_bytes.size() >= 3 &&
            ess_bytes[ess_bytes.size() - 3] == 0x02 && ess_bytes[ess_bytes.size() - 2] == 0x01,
            "ESS fixture does not end in a one-byte issuerSerial");
        ess_bytes.back() ^= 1; // Keep certHash exact, change only the referenced serial number.
    }
    ssl_check(CMS_signed_add1_attr_by_NID(cms_signer, NID_id_smime_aa_signingCertificateV2,
        V_ASN1_SEQUENCE, ess_bytes.data(), static_cast<int>(ess_bytes.size())) == 1, "ESS attribute");
    if (intermediate) ssl_check(CMS_add1_cert(cms.get(), intermediate) == 1, "CMS intermediate");
    auto input = own<BIO, BIO_free_all>(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())),
                                      "CMS input");
    ssl_check(CMS_final(cms.get(), input.get(), nullptr, CMS_BINARY) == 1, "CMS final");
    ssl_check(CMS_verify(cms.get(), nullptr, nullptr, nullptr, nullptr,
                         CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) == 1, "fixture CMS self-check");
    return der(cms.get(), i2d_CMS_ContentInfo);
}
inline Bytes crl(X509* issuer, EVP_PKEY* key, X509* revoked = nullptr,
                 const char* this_update = "20200101000000Z",
                 const char* next_update = "20400101000000Z", const std::string& idp_uri = "",
                 int crl_number = -1, int delta_base = -1, int reason = -1) {
    auto list = own<X509_CRL, X509_CRL_free>(X509_CRL_new(), "CRL");
    ssl_check(X509_CRL_set_version(list.get(), 1) == 1, "CRL version");
    ssl_check(X509_CRL_set_issuer_name(list.get(), X509_get_subject_name(issuer)) == 1, "CRL issuer");
    auto before = own<ASN1_TIME, ASN1_TIME_free>(ASN1_TIME_new(), "CRL thisUpdate");
    auto after = own<ASN1_TIME, ASN1_TIME_free>(ASN1_TIME_new(), "CRL nextUpdate");
    ssl_check(ASN1_TIME_set_string_X509(before.get(), this_update) == 1, "CRL thisUpdate value");
    ssl_check(ASN1_TIME_set_string_X509(after.get(), next_update) == 1, "CRL nextUpdate value");
    ssl_check(X509_CRL_set1_lastUpdate(list.get(), before.get()) == 1, "CRL lastUpdate");
    ssl_check(X509_CRL_set1_nextUpdate(list.get(), after.get()) == 1, "CRL nextUpdate");
    for (const auto& number : {std::pair<int, int>{NID_crl_number, crl_number}, {NID_delta_crl, delta_base}}) {
        if (number.second < 0) continue;
        auto value = own<ASN1_INTEGER, ASN1_INTEGER_free>(ASN1_INTEGER_new(), "CRL number");
        ssl_check(ASN1_INTEGER_set(value.get(), number.second) == 1, "CRL number value");
        ssl_check(X509_CRL_add1_ext_i2d(list.get(), number.first, value.get(), number.first == NID_delta_crl, 0) == 1,
                  "CRL number extension");
    }
    if (!idp_uri.empty()) {
        auto scope = own<ISSUING_DIST_POINT, ISSUING_DIST_POINT_free>(ISSUING_DIST_POINT_new(), "CRL scope");
        scope->distpoint = DIST_POINT_NAME_new();
        ssl_check(scope->distpoint != nullptr, "CRL fullName");
        scope->distpoint->type = 0;
        scope->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
        ssl_check(scope->distpoint->name.fullname != nullptr, "CRL fullName list");
        auto name = own<GENERAL_NAME, GENERAL_NAME_free>(GENERAL_NAME_new(), "CRL URI name");
        auto uri = own<ASN1_IA5STRING, ASN1_IA5STRING_free>(ASN1_IA5STRING_new(), "CRL URI");
        ssl_check(ASN1_STRING_set(uri.get(), idp_uri.data(), static_cast<int>(idp_uri.size())) == 1, "CRL URI value");
        GENERAL_NAME_set0_value(name.get(), GEN_URI, uri.release());
        ssl_check(sk_GENERAL_NAME_push(scope->distpoint->name.fullname, name.get()) > 0, "CRL URI append");
        name.release();
        ssl_check(X509_CRL_add1_ext_i2d(list.get(), NID_issuing_distribution_point, scope.get(), 1, 0) == 1,
                  "CRL issuingDistributionPoint");
    }
    if (revoked) {
        auto entry = own<X509_REVOKED, X509_REVOKED_free>(X509_REVOKED_new(), "revoked cert");
        ssl_check(X509_REVOKED_set_serialNumber(entry.get(), X509_get_serialNumber(revoked)) == 1,
                  "revoked serial");
        ssl_check(X509_REVOKED_set_revocationDate(entry.get(), before.get()) == 1, "revocation date");
        if (reason >= 0) {
            auto value = own<ASN1_ENUMERATED, ASN1_ENUMERATED_free>(ASN1_ENUMERATED_new(), "CRL reason");
            ssl_check(ASN1_ENUMERATED_set(value.get(), reason) == 1, "CRL reason value");
            ssl_check(X509_REVOKED_add1_ext_i2d(entry.get(), NID_crl_reason, value.get(), 0, 0) == 1, "CRL reason extension");
        }
        ssl_check(X509_CRL_add0_revoked(list.get(), entry.get()) == 1, "revoked entry");
        entry.release();
    }
    ssl_check(X509_CRL_sort(list.get()) == 1, "CRL sort");
    ssl_check(X509_CRL_sign(list.get(), key, EVP_sha256()) > 0, "CRL signature");
    return der(list.get(), i2d_X509_CRL);
}
inline Bytes ocsp(X509* leaf, X509* issuer, EVP_PKEY* key,
                  int status = V_OCSP_CERTSTATUS_GOOD, bool tamper = false) {
    auto basic = own<OCSP_BASICRESP, OCSP_BASICRESP_free>(OCSP_BASICRESP_new(), "OCSP basic");
    auto id = own<OCSP_CERTID, OCSP_CERTID_free>(OCSP_cert_to_id(EVP_sha1(), leaf, issuer), "OCSP ID");
    auto before = own<ASN1_TIME, ASN1_TIME_free>(ASN1_TIME_new(), "OCSP thisUpdate");
    auto after = own<ASN1_TIME, ASN1_TIME_free>(ASN1_TIME_new(), "OCSP nextUpdate");
    const auto now = std::time(nullptr);
    ssl_check(ASN1_TIME_set(before.get(), now - 3600) != nullptr, "OCSP before");
    ssl_check(ASN1_TIME_set(after.get(), now + 86400) != nullptr, "OCSP after");
    ssl_check(OCSP_basic_add1_status(basic.get(), id.get(), status, OCSP_REVOKED_STATUS_KEYCOMPROMISE,
                                    status == V_OCSP_CERTSTATUS_REVOKED ? before.get() : nullptr,
                                    before.get(), after.get()) != nullptr, "OCSP status");
    ssl_check(OCSP_basic_sign(basic.get(), issuer, key, EVP_sha256(), nullptr, 0) == 1, "OCSP signature");
    if (tamper) {
        auto* signature = const_cast<ASN1_OCTET_STRING*>(OCSP_resp_get0_signature(basic.get()));
        require(signature && signature->length > 0, "OCSP signature missing");
        signature->data[0] ^= 1;
    }
    auto response = own<OCSP_RESPONSE, OCSP_RESPONSE_free>(
        OCSP_response_create(OCSP_RESPONSE_STATUS_SUCCESSFUL, basic.get()), "OCSP response");
    return der(response.get(), i2d_OCSP_RESPONSE);
}

inline void write(const std::filesystem::path& path, const Bytes& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    require(out.good(), "write test fixture " + path.u8string());
}
inline void pem(const std::filesystem::path& path, X509* cert) {
    auto output = own<BIO, BIO_free_all>(BIO_new(BIO_s_mem()), "PEM output");
    ssl_check(PEM_write_bio_X509(output.get(), cert) == 1, "write PEM");
    char* data = nullptr;
    const auto size = BIO_get_mem_data(output.get(), &data);
    require(size > 0, "PEM size");
    write(path, Bytes(data, data + size));
}
struct Fixtures {
    Key root_key = make_key(), intermediate_key = make_key(), signer_key = make_key(), tsa_key = make_key();
    Cert root = certificate(root_key.get(), 1, "Offline test root", nullptr, nullptr, nullptr, true);
    Cert intermediate = certificate(intermediate_key.get(), 2, "Offline test intermediate",
                                    root.get(), root_key.get(), nullptr, true);
    Cert code = certificate(signer_key.get(), 3, "Offline code signer", intermediate.get(),
                            intermediate_key.get(), "codeSigning");
    Cert tsa = certificate(tsa_key.get(), 4, "Offline timestamp authority", intermediate.get(),
                           intermediate_key.get(), "timeStamping");
    Cert expired = certificate(signer_key.get(), 5, "Expired code signer", intermediate.get(),
                               intermediate_key.get(), "codeSigning", false,
                               "20200101000000Z", "20260201000000Z");
    Cert wrong_purpose = certificate(signer_key.get(), 6, "Server purpose signer", intermediate.get(),
                                     intermediate_key.get(), "serverAuth");
    Cert bad_tsa = certificate(tsa_key.get(), 7, "Wrong purpose timestamp", intermediate.get(),
                               intermediate_key.get(), "codeSigning");
    std::filesystem::path directory;
    Fixtures() {
        const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
        directory = std::filesystem::temp_directory_path() / ("pesign-verification-" + std::to_string(nonce));
        require(std::filesystem::create_directory(directory), "create temporary fixture directory");
        pem(directory / "root.pem", root.get());
    }
    ~Fixtures() {
        std::error_code error;
        std::filesystem::remove_all(directory, error);
    }
    Fixtures(const Fixtures&) = delete;
    Fixtures& operator=(const Fixtures&) = delete;
    P7 signature(X509* cert = nullptr, bool plus = false, bool include_intermediate = true,
                  const char* when = "260102030405Z") const {
        const auto content = indirect_data(image_hash(image(plus), plus));
        auto p7 = signed_data(content);
        signer(p7.get(), cert ? cert : code.get(), signer_key.get(), content_bytes(content), spc_oid, when);
        if (include_intermediate) ssl_check(PKCS7_add_certificate(p7.get(), intermediate.get()) == 1,
                                          "include intermediate");
        return p7;
    }
};

} // namespace verification_fixture
