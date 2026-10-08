#include "pesign/analyzer.h"
#include "../src/internal.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>
#include <openssl/rsa.h>
#include <openssl/ts.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdint>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;
constexpr const char* spc_content_oid = "1.3.6.1.4.1.311.2.1.4";
constexpr const char* catalog_content_oid = "1.3.6.1.4.1.311.10.1";
constexpr const char* pe_image_oid = "1.3.6.1.4.1.311.2.1.15";
constexpr const char* sha256_oid = "2.16.840.1.101.3.4.2.1";
constexpr const char* nested_oid = "1.3.6.1.4.1.311.2.4.1";
constexpr const char* microsoft_timestamp_oid = "1.3.6.1.4.1.311.3.3.1";
constexpr const char* rfc3161_timestamp_oid = "1.2.840.113549.1.9.16.2.14";
constexpr const char* tst_info_oid = "1.2.840.113549.1.9.16.1.4";

void check(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void openssl_check(bool condition, const char* operation) {
    if (condition) {
        return;
    }
    std::string message(operation);
    for (unsigned long error = ERR_get_error(); error != 0; error = ERR_get_error()) {
        char buffer[256]{};
        ERR_error_string_n(error, buffer, sizeof(buffer));
        message += std::string("; ") + buffer;
    }
    throw std::runtime_error(message);
}

template <typename T, void (*Free)(T*)>
using OpenSslPtr = std::unique_ptr<T, decltype(Free)>;

template <typename T, void (*Free)(T*)>
OpenSslPtr<T, Free> own(T* value, const char* operation) {
    openssl_check(value != nullptr, operation);
    return OpenSslPtr<T, Free>(value, Free);
}

using Key = OpenSslPtr<EVP_PKEY, EVP_PKEY_free>;
using Cert = OpenSslPtr<X509, X509_free>;
using P7 = OpenSslPtr<PKCS7, PKCS7_free>;

template <typename T, typename Encoder>
Bytes der(T* value, Encoder encode) {
    const int size = encode(value, nullptr);
    openssl_check(size > 0, "measure DER");
    Bytes bytes(static_cast<std::size_t>(size));
    auto* cursor = bytes.data();
    openssl_check(encode(value, &cursor) == size, "encode DER");
    check(cursor == bytes.data() + bytes.size(), "DER encoder length mismatch");
    return bytes;
}

// Fixture DER encodes the documented ASN.1 schema, independently of the parser.
Bytes tlv(std::uint8_t tag, const Bytes& contents) {
    Bytes result{tag};
    if (contents.size() < 128) {
        result.push_back(static_cast<std::uint8_t>(contents.size()));
    } else {
        Bytes length;
        for (std::size_t size = contents.size(); size != 0; size >>= 8) {
            length.insert(length.begin(), static_cast<std::uint8_t>(size & 0xff));
        }
        result.push_back(static_cast<std::uint8_t>(0x80 | length.size()));
        result.insert(result.end(), length.begin(), length.end());
    }
    result.insert(result.end(), contents.begin(), contents.end());
    return result;
}

Bytes concat(Bytes first, const Bytes& second) {
    first.insert(first.end(), second.begin(), second.end());
    return first;
}

Bytes object_der(const char* oid) {
    auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(oid, 1), "create OID");
    return der(object.get(), i2d_ASN1_OBJECT);
}

Bytes indirect_data(const char* image_oid = pe_image_oid,
                    const char* algorithm_oid = sha256_oid) {
    auto digest_info = own<X509_SIG, X509_SIG_free>(X509_SIG_new(), "create DigestInfo");
    X509_ALGOR* algorithm = nullptr;
    ASN1_OCTET_STRING* digest = nullptr;
    X509_SIG_getm(digest_info.get(), &algorithm, &digest);
    auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(
        OBJ_txt2obj(algorithm_oid, 1), "create image digest OID");
    X509_ALGOR_set0(algorithm, object.release(), V_ASN1_NULL, nullptr);
    const Bytes image_digest(32, 0x42);
    openssl_check(ASN1_OCTET_STRING_set(digest, image_digest.data(),
                                      static_cast<int>(image_digest.size())) == 1,
                  "set image digest");
    // SpcPeImageData contains flags BIT STRING; its optional file link is omitted.
    const Bytes pe_image_data = tlv(0x30, Bytes{0x03, 0x01, 0x00});
    const Bytes attribute = tlv(0x30, concat(object_der(image_oid), pe_image_data));
    return tlv(0x30, concat(attribute, der(digest_info.get(), i2d_X509_SIG)));
}

Bytes catalog_data() {
    const Bytes usage = tlv(0x30, object_der("1.3.6.1.4.1.311.12.1.1"));
    const Bytes time = tlv(0x17, Bytes{'2','6','0','1','0','2','0','3','0','4','0','5','Z'});
    const Bytes algorithm = tlv(0x30, concat(object_der(sha256_oid), Bytes{0x05, 0x00}));
    const Bytes member = tlv(0x30, concat(tlv(0x04, Bytes(32, 0x42)), tlv(0x31, {})));
    return tlv(0x30, concat(concat(concat(usage, time), algorithm), tlv(0x30, member)));
}

Key make_key() {
    auto context = own<EVP_PKEY_CTX, EVP_PKEY_CTX_free>(
        EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), "create RSA context");
    openssl_check(EVP_PKEY_keygen_init(context.get()) == 1, "initialize keygen");
    openssl_check(EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), 2048) == 1,
                  "set RSA size");
    EVP_PKEY* key = nullptr;
    openssl_check(EVP_PKEY_generate(context.get(), &key) == 1, "generate RSA key");
    return own<EVP_PKEY, EVP_PKEY_free>(key, "generated key");
}

Cert make_certificate(EVP_PKEY* key, long serial, const char* common_name,
                      const std::string& crl_uri = "https://example.invalid/test.crl") {
    auto certificate = own<X509, X509_free>(X509_new(), "create certificate");
    openssl_check(X509_set_version(certificate.get(), 2) == 1, "set X509 version");
    openssl_check(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1,
                  "set serial");
    openssl_check(ASN1_TIME_set_string_X509(X509_getm_notBefore(certificate.get()),
                                         "20260101000000Z") == 1,
                  "set notBefore");
    openssl_check(ASN1_TIME_set_string_X509(X509_getm_notAfter(certificate.get()),
                                         "20360101000000Z") == 1,
                  "set notAfter");
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    openssl_check(X509_NAME_add_entry_by_txt(
                      subject, "CN", MBSTRING_ASC,
                      reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) == 1,
                  "set subject");
    openssl_check(X509_set_issuer_name(certificate.get(), subject) == 1, "set issuer");
    openssl_check(X509_set_pubkey(certificate.get(), key) == 1, "set public key");
    X509V3_CTX extension_context{};
    X509V3_set_ctx(&extension_context, certificate.get(), certificate.get(),
                   nullptr, nullptr, 0);
    auto ski = own<X509_EXTENSION, X509_EXTENSION_free>(
        X509V3_EXT_conf_nid(nullptr, &extension_context, NID_subject_key_identifier,
                           const_cast<char*>("hash")), "create SKI extension");
    openssl_check(X509_add_ext(certificate.get(), ski.get(), -1) == 1,
                  "add SKI extension");
    const std::string crl_configuration = "URI:" + crl_uri;
    auto crl = own<X509_EXTENSION, X509_EXTENSION_free>(
        X509V3_EXT_conf_nid(nullptr, nullptr, NID_crl_distribution_points,
                           const_cast<char*>(crl_configuration.c_str())),
        "create CRL extension");
    openssl_check(X509_add_ext(certificate.get(), crl.get(), -1) == 1,
                  "add CRL extension");
    openssl_check(X509_sign(certificate.get(), key, EVP_sha256()) > 0,
                  "sign certificate");
    return certificate;
}

P7 make_signed_data(const Bytes& content, const char* oid = spc_content_oid,
                    int value_type = V_ASN1_SEQUENCE) {
    auto outer = own<PKCS7, PKCS7_free>(PKCS7_new(), "create SignedData");
    openssl_check(PKCS7_set_type(outer.get(), NID_pkcs7_signed) == 1,
                  "initialize SignedData");
    auto inner = own<PKCS7, PKCS7_free>(PKCS7_new(), "create content");
    ASN1_OBJECT_free(inner->type);
    inner->type = OBJ_txt2obj(oid, 1);
    openssl_check(inner->type != nullptr, "set content OID");
    inner->d.other = ASN1_TYPE_new();
    openssl_check(inner->d.other != nullptr, "create ANY content");
    auto value = own<ASN1_STRING, ASN1_STRING_free>(
        ASN1_STRING_type_new(value_type), "create content value");
    openssl_check(ASN1_STRING_set(value.get(), content.data(),
                                 static_cast<int>(content.size())) == 1,
                  "set content value");
    ASN1_TYPE_set(inner->d.other, value_type, value.release());
    openssl_check(PKCS7_set_content(outer.get(), inner.get()) == 1,
                  "set SignedData content");
    inner.release();
    return outer;
}

Bytes sha256(const unsigned char* data, std::size_t size) {
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int length = 0;
    openssl_check(EVP_Digest(data, size, digest.data(), &length, EVP_sha256(), nullptr) == 1,
                  "hash fixture content");
    digest.resize(length);
    return digest;
}

PKCS7_SIGNER_INFO* add_signer(PKCS7* p7, X509* cert, EVP_PKEY* key,
                              const Bytes& content, const char* content_oid,
                              bool include_certificate = true) {
    PKCS7_SIGNER_INFO* signer = PKCS7_add_signature(p7, cert, key, EVP_sha256());
    openssl_check(signer != nullptr, "add signer");
    if (include_certificate) {
        openssl_check(PKCS7_add_certificate(p7, cert) == 1, "add certificate");
    }
    if (content_oid != nullptr) {
        auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(
            OBJ_txt2obj(content_oid, 1), "create signer content type");
        openssl_check(PKCS7_add_signed_attribute(signer, NID_pkcs9_contentType,
                                               V_ASN1_OBJECT, object.get()) == 1,
                      "add contentType attribute");
        object.release();
    }
    auto time = own<ASN1_UTCTIME, ASN1_UTCTIME_free>(ASN1_UTCTIME_new(), "create time");
    openssl_check(ASN1_UTCTIME_set_string(time.get(), "260102030405Z") == 1,
                  "set signing time");
    openssl_check(PKCS7_add_signed_attribute(signer, NID_pkcs9_signingTime,
                                           V_ASN1_UTCTIME, time.get()) == 1,
                  "add signingTime attribute");
    time.release();
    const Bytes content_digest = sha256(content.data(), content.size());
    auto digest = own<ASN1_OCTET_STRING, ASN1_OCTET_STRING_free>(
        ASN1_OCTET_STRING_new(), "create signed content digest");
    openssl_check(ASN1_OCTET_STRING_set(digest.get(), content_digest.data(),
                                      static_cast<int>(content_digest.size())) == 1,
                  "set signed content digest");
    openssl_check(PKCS7_add_signed_attribute(signer, NID_pkcs9_messageDigest,
                                           V_ASN1_OCTET_STRING, digest.get()) == 1,
                  "add messageDigest attribute");
    digest.release();
    openssl_check(PKCS7_SIGNER_INFO_sign(signer) == 1, "sign signed attributes");
    return signer;
}

void add_unsigned_der(PKCS7_SIGNER_INFO* signer, const char* oid, const Bytes& value) {
    auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj(oid, 1), "create attr OID");
    auto attribute = own<X509_ATTRIBUTE, X509_ATTRIBUTE_free>(
        X509_ATTRIBUTE_create_by_OBJ(nullptr, object.get(), V_ASN1_SEQUENCE,
                                     value.data(), static_cast<int>(value.size())),
        "create unsigned attribute");
    if (signer->unauth_attr == nullptr) {
        signer->unauth_attr = sk_X509_ATTRIBUTE_new_null();
        openssl_check(signer->unauth_attr != nullptr, "create unsigned attributes");
    }
    openssl_check(sk_X509_ATTRIBUTE_push(signer->unauth_attr, attribute.get()) > 0,
                  "append unsigned attribute");
    attribute.release();
}

pesign::Analysis parse(const Bytes& bytes, std::size_t record = 3) {
    pesign::Analysis result;
    pesign::detail::parse_pkcs7(bytes.data(), bytes.size(), record, result);
    return result;
}

P7 fixture(X509* cert, EVP_PKEY* key, bool include_certificate = true,
           const Bytes& content = indirect_data()) {
    auto p7 = make_signed_data(content);
    add_signer(p7.get(), cert, key, content, spc_content_oid, include_certificate);
    return p7;
}

const pesign::Signature& sole_signature(const pesign::Analysis& result) {
    check(result.errors.empty(), result.errors.empty() ? "" : result.errors.front());
    check(result.signatures.size() == 1, "expected exactly one signature");
    return result.signatures.front();
}

void check_signer_certificate(const pesign::Signature& signature,
                              const pesign::Signer& signer) {
    check(signer.certificate_index >= 0, "signer certificate was not resolved");
    const auto index = static_cast<std::size_t>(signer.certificate_index);
    check(index < signature.certificates.size(), "signer certificate index out of range");
    const auto& certificate = signature.certificates[index];
    check(certificate.issuer == signer.issuer && certificate.serial == signer.serial,
          "signer certificate must match both issuer and serial");
}

Bytes timestamp_info(const Bytes& signature_value,
                     const char* gen_time = "20260102030405Z") {
    auto info = own<TS_TST_INFO, TS_TST_INFO_free>(TS_TST_INFO_new(), "create TSTInfo");
    openssl_check(TS_TST_INFO_set_version(info.get(), 1) == 1, "set timestamp version");
    auto policy = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj("1.2.3.4.1", 1),
                                                 "create timestamp policy");
    openssl_check(TS_TST_INFO_set_policy_id(info.get(), policy.get()) == 1,
                  "set timestamp policy");
    auto imprint = own<TS_MSG_IMPRINT, TS_MSG_IMPRINT_free>(
        TS_MSG_IMPRINT_new(), "create timestamp imprint");
    auto algorithm = own<X509_ALGOR, X509_ALGOR_free>(X509_ALGOR_new(), "create imprint alg");
    X509_ALGOR_set0(algorithm.get(), OBJ_dup(OBJ_nid2obj(NID_sha256)), V_ASN1_NULL, nullptr);
    openssl_check(TS_MSG_IMPRINT_set_algo(imprint.get(), algorithm.get()) == 1,
                  "set imprint algorithm");
    Bytes digest = sha256(signature_value.data(), signature_value.size());
    openssl_check(TS_MSG_IMPRINT_set_msg(imprint.get(), digest.data(),
                                       static_cast<int>(digest.size())) == 1,
                  "set imprint value");
    openssl_check(TS_TST_INFO_set_msg_imprint(info.get(), imprint.get()) == 1,
                  "set timestamp imprint");
    auto serial = own<ASN1_INTEGER, ASN1_INTEGER_free>(ASN1_INTEGER_new(), "create TS serial");
    openssl_check(ASN1_INTEGER_set(serial.get(), 7) == 1, "set TS serial");
    openssl_check(TS_TST_INFO_set_serial(info.get(), serial.get()) == 1, "set TSTInfo serial");
    auto time = own<ASN1_GENERALIZEDTIME, ASN1_GENERALIZEDTIME_free>(
        ASN1_GENERALIZEDTIME_new(), "create TS time");
    openssl_check(ASN1_GENERALIZEDTIME_set_string(time.get(), gen_time) == 1,
                  "set TS time");
    openssl_check(TS_TST_INFO_set_time(info.get(), time.get()) == 1, "set TSTInfo time");
    return der(info.get(), i2d_TS_TST_INFO);
}

Bytes timestamp_token(X509* cert, EVP_PKEY* key, const Bytes& signature_value,
                      const char* gen_time = "20260102030405Z") {
    const Bytes content = timestamp_info(signature_value, gen_time);
    auto token = make_signed_data(content, tst_info_oid, V_ASN1_OCTET_STRING);
    add_signer(token.get(), cert, key, content, tst_info_oid);
    return der(token.get(), i2d_PKCS7);
}

// RFC3161 tokens are CMS ContentInfo. A CMS SignerIdentifier may carry an SKI
// instead of issuerAndSerialNumber, which the older PKCS#7 decoder cannot read.
Bytes cms_timestamp_token(X509* cert, EVP_PKEY* key,
                          const Bytes& signature_value, bool use_key_id = true) {
    const Bytes content = timestamp_info(signature_value);
    auto token = own<CMS_ContentInfo, CMS_ContentInfo_free>(
        CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_PARTIAL | CMS_BINARY),
        "create partial CMS token");
    auto content_type = own<ASN1_OBJECT, ASN1_OBJECT_free>(
        OBJ_txt2obj(tst_info_oid, 1), "create CMS TSTInfo content type");
    openssl_check(CMS_set1_eContentType(token.get(), content_type.get()) == 1,
                  "set CMS timestamp content type");
    auto* signer = CMS_add1_signer(token.get(), cert, key, EVP_sha256(),
                                   CMS_BINARY | (use_key_id ? CMS_USE_KEYID : 0));
    openssl_check(signer != nullptr, "add CMS key-id signer");
    ASN1_OCTET_STRING* key_id = nullptr;
    X509_NAME* issuer = nullptr;
    ASN1_INTEGER* serial = nullptr;
    openssl_check(CMS_SignerInfo_get0_signer_id(signer, &key_id, &issuer, &serial) == 1,
                  "read CMS signer identifier");
    if (use_key_id) {
        check(key_id != nullptr && issuer == nullptr && serial == nullptr,
              "CMS regression fixture does not use a subjectKeyIdentifier");
    } else {
        check(key_id == nullptr && issuer != nullptr && serial != nullptr,
              "CMS regression fixture does not use issuerAndSerialNumber");
    }
    auto input = own<BIO, BIO_free_all>(
        BIO_new_mem_buf(content.data(), static_cast<int>(content.size())),
        "create timestamp content BIO");
    openssl_check(CMS_final(token.get(), input.get(), nullptr, CMS_BINARY) == 1,
                  "sign CMS timestamp token");
    // This is a local cryptographic fixture check, with trust checking disabled;
    // the product reports parsed metadata and performs no verification.
    openssl_check(CMS_verify(token.get(), nullptr, nullptr, nullptr, nullptr,
                             CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) == 1,
                  "verify generated CMS token signature");
    return der(token.get(), i2d_CMS_ContentInfo);
}

Bytes der_contents(const Bytes& encoded) {
    const unsigned char* cursor = encoded.data();
    long length = 0;
    int tag = 0;
    int value_class = 0;
    const int flags = ASN1_get_object(&cursor, &length, &tag, &value_class,
                                      static_cast<long>(encoded.size()));
    check((flags & 0x81) == 0 && length >= 0 &&
              static_cast<std::size_t>(length) ==
                  static_cast<std::size_t>(encoded.data() + encoded.size() - cursor),
          "invalid fixture DER wrapper");
    return Bytes(cursor, cursor + length);
}

std::vector<Bytes> der_fields(const Bytes& contents) {
    std::vector<Bytes> fields;
    const unsigned char* cursor = contents.data();
    const unsigned char* end = contents.data() + contents.size();
    while (cursor < end) {
        const unsigned char* start = cursor;
        long length = 0;
        int tag = 0;
        int value_class = 0;
        const int flags = ASN1_get_object(&cursor, &length, &tag, &value_class,
                                          static_cast<long>(end - start));
        check((flags & 0x81) == 0 && length >= 0 && length <= end - cursor,
              "invalid fixture DER field");
        cursor += length;
        fields.emplace_back(start, cursor);
    }
    return fields;
}

Bytes joined(const std::vector<Bytes>& fields) {
    Bytes result;
    for (const Bytes& field : fields) {
        result.insert(result.end(), field.begin(), field.end());
    }
    return result;
}

Bytes add_other_certificate_choice(const Bytes& token) {
    auto content_info = der_fields(der_contents(token));
    check(content_info.size() == 2 && content_info[1].front() == 0xa0,
          "fixture CMS ContentInfo shape changed");
    auto signed_data = der_fields(der_contents(der_contents(content_info[1])));
    check(signed_data.size() == 5 && signed_data[3].front() == 0xa0,
          "fixture CMS SignedData certificate field missing");
    // RFC5652 OtherCertificateFormat is OID + ANY. This private format has a
    // NULL payload; it is a valid CMS certificate choice, not an X509 object.
    // [3] is IMPLICIT, so its body contains the SEQUENCE fields directly.
    const Bytes other_certificate = tlv(0xa3, concat(object_der("1.2.3.4.777"),
                                                     tlv(0x05, Bytes{})));
    signed_data[3] = tlv(0xa0, concat(der_contents(signed_data[3]), other_certificate));
    // RFC5652 requires SignedData version 5 when an "other" certificate exists.
    signed_data[0] = Bytes{0x02, 0x01, 0x05};
    content_info[1] = tlv(0xa0, tlv(0x30, joined(signed_data)));
    return tlv(0x30, joined(content_info));
}

void put16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value);
    bytes.at(offset + 1) = static_cast<std::uint8_t>(value >> 8);
}

void put32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (unsigned int index = 0; index != 4; ++index) {
        bytes.at(offset + index) = static_cast<std::uint8_t>(value >> (8 * index));
    }
}

Bytes pe_with_signature(const Bytes& payload, bool pe32_plus) {
    constexpr std::size_t nt_offset = 0x80;
    constexpr std::size_t optional_offset = nt_offset + 24;
    constexpr std::size_t certificate_offset = 0x200;
    const auto record_size = static_cast<std::uint32_t>(payload.size() + 8);
    const auto table_size = (record_size + 7u) & ~7u;
    Bytes bytes(certificate_offset + table_size, 0);
    put16(bytes, 0, 0x5a4d);
    put32(bytes, 0x3c, static_cast<std::uint32_t>(nt_offset));
    put32(bytes, nt_offset, 0x00004550);
    put16(bytes, nt_offset + 4, pe32_plus ? 0x8664 : 0x014c);
    put16(bytes, nt_offset + 20, pe32_plus ? 240 : 224);
    put16(bytes, optional_offset, pe32_plus ? 0x020b : 0x010b);
    put32(bytes, optional_offset + 60, static_cast<std::uint32_t>(certificate_offset));
    const std::size_t count_offset = optional_offset + (pe32_plus ? 108 : 92);
    const std::size_t directory_offset = optional_offset + (pe32_plus ? 112 : 96) + 8 * 4;
    put32(bytes, count_offset, 16);
    put32(bytes, directory_offset, static_cast<std::uint32_t>(certificate_offset));
    put32(bytes, directory_offset + 4, table_size);
    put32(bytes, certificate_offset, record_size);
    put16(bytes, certificate_offset + 4, 0x0200);
    put16(bytes, certificate_offset + 6, 0x0002);
    std::copy(payload.begin(), payload.end(), bytes.begin() + certificate_offset + 8);
    return bytes;
}

struct Fixtures {
    Key first_key = make_key();
    Key second_key = make_key();
    Cert first = make_certificate(first_key.get(), 1, "First test signer");
    Cert second = make_certificate(second_key.get(), 2, "Timestamp test signer");
};

} // namespace

int main() {
    try {
        Fixtures keys;
        const std::vector<std::pair<const char*, std::function<void()>>> tests{
            {"Authenticode content and certificate metadata", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.certificate_record == 3, "record provenance lost");
                 check(signature.parent_signature == -1 && signature.parent_signer == -1,
                       "outer signature has a parent");
                 check(signature.content_type == spc_content_oid, "wrong content OID");
                 check(signature.digest_algorithm.oid == sha256_oid, "wrong image digest alg");
                 check(signature.embedded_digest ==
                           "4242424242424242424242424242424242424242424242424242424242424242",
                       "wrong embedded image digest");
                 const std::string text = pesign::to_text(result);
                 check(text.find("imageDigestAlgorithm: sha256 (" + std::string(sha256_oid) + ")") !=
                           std::string::npos &&
                           text.find("embeddedDigest: " + signature.embedded_digest) != std::string::npos,
                       "Authenticode text report omitted its image digest");
                 check(signature.signers.size() == 1 && signature.certificates.size() == 1,
                       "signer or certificate missing");
                 const auto& signer = signature.signers.front();
                 check(signer.digest_algorithm.oid == sha256_oid, "wrong signer digest alg");
                 check(signer.signing_time == "2026-01-02T03:04:05Z",
                       "signingTime was not normalized to UTC");
                 check_signer_certificate(signature, signer);
                 const auto& certificate = signature.certificates.front();
                 check(certificate.version == 3, "wrong certificate version");
                 check(certificate.subject.find("First test signer") != std::string::npos,
                       "wrong subject");
                 check(certificate.sha1_thumbprint.size() == 40 &&
                           certificate.sha256_thumbprint.size() == 64,
                       "wrong thumbprint lengths");
                 check(!certificate.not_before.empty() && !certificate.not_after.empty(),
                       "certificate validity missing");
                 check(std::find(certificate.crl_distribution_points.begin(),
                                 certificate.crl_distribution_points.end(),
                                 "https://example.invalid/test.crl") !=
                           certificate.crl_distribution_points.end(), "CRL URI missing");
             }},
            {"multiple signers resolve by issuer and serial", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 add_signer(p7.get(), keys.second.get(), keys.second_key.get(),
                            indirect_data(), spc_content_oid);
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.signers.size() == 2 && signature.certificates.size() == 2,
                       "multiple signer metadata lost");
                 for (const auto& signer : signature.signers) {
                     check_signer_certificate(signature, signer);
                 }
                 check(signature.signers[0].certificate_index !=
                           signature.signers[1].certificate_index,
                       "different signers incorrectly share a certificate");
             }},
            {"signer without embedded certificate", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get(), false);
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.certificates.empty(), "unexpected certificate");
                 check(signature.signers.size() == 1 &&
                           signature.signers.front().certificate_index == -1,
                       "certificate absence was not preserved");
             }},
            {"ambiguous issuer and serial never selects arbitrary certificate", [&] {
                 auto collision = make_certificate(keys.second_key.get(), 1, "First test signer");
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 openssl_check(PKCS7_add_certificate(p7.get(), collision.get()) == 1,
                               "add colliding certificate");
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.certificates.size() == 2, "colliding certificate was lost");
                 check(signature.signers.front().certificate_index == -1,
                       "ambiguous signer identity selected a certificate");
                 check(!result.warnings.empty(), "ambiguous identity needs a warning");
             }},
            {"nested signature provenance", [&] {
                 auto nested = fixture(keys.second.get(), keys.second_key.get());
                 auto outer = fixture(keys.first.get(), keys.first_key.get());
                 add_unsigned_der(sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0),
                                  nested_oid, der(nested.get(), i2d_PKCS7));
                 pesign::Analysis result;
                 const Bytes first_bytes = der(nested.get(), i2d_PKCS7);
                 pesign::detail::parse_pkcs7(first_bytes.data(), first_bytes.size(), 0, result);
                 const Bytes outer_bytes = der(outer.get(), i2d_PKCS7);
                 pesign::detail::parse_pkcs7(outer_bytes.data(), outer_bytes.size(), 7, result);
                 check(result.errors.empty() && result.signatures.size() == 3,
                       "nested signature was not expanded");
                 check(result.signatures[2].parent_signature == 1 &&
                           result.signatures[2].parent_signer == 0 &&
                           result.signatures[2].certificate_record == 7,
                       "nested signature uses local rather than Analysis-wide parent indices");
             }},
            {"PKCS9 countersignature metadata", [&] {
                 auto outer = fixture(keys.first.get(), keys.first_key.get());
                 auto* signer = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                 const Bytes signature_value(ASN1_STRING_get0_data(signer->enc_digest),
                                             ASN1_STRING_get0_data(signer->enc_digest) +
                                                 ASN1_STRING_length(signer->enc_digest));
                 auto countersignature = make_signed_data(indirect_data());
                 auto* counter = add_signer(countersignature.get(), keys.second.get(),
                                            keys.second_key.get(), signature_value, nullptr);
                 openssl_check(PKCS7_add_certificate(outer.get(), keys.second.get()) == 1,
                               "add countersigner certificate");
                 add_unsigned_der(signer, "1.2.840.113549.1.9.6",
                                  der(counter, i2d_PKCS7_SIGNER_INFO));
                 const auto result = parse(der(outer.get(), i2d_PKCS7));
                 const auto& timestamps = sole_signature(result).signers.front().timestamps;
                 check(timestamps.size() == 1 && timestamps.front().type == "pkcs9",
                       "counterSignature was not parsed");
                 check(!timestamps.front().time.empty(), "counterSignature time missing");
                 check(timestamps.front().digest_algorithm.oid == sha256_oid,
                       "counterSignature algorithm missing");
                 check(timestamps.front().signer_subject.find("Timestamp test signer") !=
                           std::string::npos, "counterSignature certificate not resolved");
             }},
            {"RFC3161 and Microsoft timestamp token metadata", [&] {
                 for (const char* oid : {microsoft_timestamp_oid, rfc3161_timestamp_oid}) {
                     auto outer = fixture(keys.first.get(), keys.first_key.get());
                     auto* signer = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                     const Bytes signature_value(ASN1_STRING_get0_data(signer->enc_digest),
                                                 ASN1_STRING_get0_data(signer->enc_digest) +
                                                     ASN1_STRING_length(signer->enc_digest));
                     const Bytes token = timestamp_token(keys.second.get(),
                                                          keys.second_key.get(), signature_value);
                     add_unsigned_der(signer, oid, token);
                     const auto result = parse(der(outer.get(), i2d_PKCS7));
                     const auto& timestamps = sole_signature(result).signers.front().timestamps;
                     check(timestamps.size() == 1 && timestamps.front().type == "rfc3161",
                           "timestamp token was not parsed");
                     const auto& timestamp = timestamps.front();
                     check(!timestamp.time.empty(), "RFC3161 genTime missing");
                     check(timestamp.digest_algorithm.oid == sha256_oid &&
                               timestamp.message_imprint.size() == 64,
                           "RFC3161 message imprint missing");
                     check(timestamp.certificates.size() == 1 &&
                               timestamp.signer_subject.find("Timestamp test signer") !=
                                   std::string::npos,
                           "RFC3161 certificate metadata missing");
                 }
             }},
            {"RFC3161 fractional seconds are preserved", [&] {
                 auto outer = fixture(keys.first.get(), keys.first_key.get());
                 auto* signer = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                 const Bytes signature_value(ASN1_STRING_get0_data(signer->enc_digest),
                                             ASN1_STRING_get0_data(signer->enc_digest) +
                                                 ASN1_STRING_length(signer->enc_digest));
                 add_unsigned_der(signer, microsoft_timestamp_oid,
                                  timestamp_token(keys.second.get(), keys.second_key.get(),
                                                  signature_value, "20260102030405.123Z"));
                 const auto result = parse(der(outer.get(), i2d_PKCS7));
                 const auto& timestamps = sole_signature(result).signers.front().timestamps;
                 check(timestamps.size() == 1 &&
                           timestamps.front().time == "2026-01-02T03:04:05.123Z",
                       "fractional RFC3161 genTime was rounded or dropped");
             }},
            {"RFC3161 CMS subjectKeyIdentifier signer regression", [&] {
                 auto outer = fixture(keys.first.get(), keys.first_key.get());
                 auto* signer = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                 const Bytes signature_value(ASN1_STRING_get0_data(signer->enc_digest),
                                             ASN1_STRING_get0_data(signer->enc_digest) +
                                                 ASN1_STRING_length(signer->enc_digest));
                 const Bytes token = cms_timestamp_token(
                     keys.second.get(), keys.second_key.get(), signature_value);
                 const unsigned char* cursor = token.data();
                 const P7 legacy(d2i_PKCS7(nullptr, &cursor, static_cast<long>(token.size())),
                                 PKCS7_free);
                 check(legacy == nullptr,
                       "regression fixture is still accepted by the legacy PKCS#7 decoder");
                 ERR_clear_error();
                 add_unsigned_der(signer, microsoft_timestamp_oid, token);
                 const auto result = parse(der(outer.get(), i2d_PKCS7));
                 const auto& timestamps = sole_signature(result).signers.front().timestamps;
                 check(timestamps.size() == 1 && timestamps.front().type == "rfc3161" &&
                           timestamps.front().time == "2026-01-02T03:04:05Z",
                       "CMS timestamp genTime was not parsed");
                 check(timestamps.front().digest_algorithm.oid == sha256_oid &&
                           timestamps.front().message_imprint.size() == 64,
                       "CMS timestamp imprint was lost");
                 check(timestamps.front().certificates.size() == 1 &&
                           timestamps.front().signer_subject.find("Timestamp test signer") !=
                               std::string::npos,
                       "CMS SKI signer was not matched to its embedded certificate");
             }},
            {"RFC3161 CMS non-X509 certificate choice regression", [&] {
                 auto outer = fixture(keys.first.get(), keys.first_key.get());
                 auto* signer = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                 const Bytes signature_value(ASN1_STRING_get0_data(signer->enc_digest),
                                             ASN1_STRING_get0_data(signer->enc_digest) +
                                                 ASN1_STRING_length(signer->enc_digest));
                 const Bytes plain_token = cms_timestamp_token(
                     keys.second.get(), keys.second_key.get(), signature_value, false);
                 const unsigned char* cursor = plain_token.data();
                 const P7 plain_legacy(d2i_PKCS7(nullptr, &cursor,
                                               static_cast<long>(plain_token.size())),
                                       PKCS7_free);
                 check(plain_legacy != nullptr,
                       "issuerAndSerialNumber CMS fixture must be PKCS#7-compatible before mutation");
                 const Bytes token = add_other_certificate_choice(plain_token);
                 cursor = token.data();
                 const P7 legacy(d2i_PKCS7(nullptr, &cursor, static_cast<long>(token.size())),
                                 PKCS7_free);
                 check(legacy == nullptr,
                       "PKCS#7 decoder unexpectedly accepted a non-X509 certificate choice");
                 ERR_clear_error();
                 cursor = token.data();
                 auto decoded = own<CMS_ContentInfo, CMS_ContentInfo_free>(
                     d2i_CMS_ContentInfo(nullptr, &cursor, static_cast<long>(token.size())),
                     "decode CMS OtherCertificateFormat fixture");
                 check(cursor == token.data() + token.size(), "CMS fixture was not fully decoded");
                 STACK_OF(X509)* certificates = CMS_get1_certs(decoded.get());
                 openssl_check(certificates != nullptr, "get ordinary CMS certificates");
                 const int certificate_count = sk_X509_num(certificates);
                 sk_X509_pop_free(certificates, X509_free);
                 check(certificate_count == 1, "CMS must retain only the ordinary X509 certificate");
                 openssl_check(CMS_verify(decoded.get(), nullptr, nullptr, nullptr, nullptr,
                                          CMS_NO_SIGNER_CERT_VERIFY | CMS_BINARY) == 1,
                               "verify modified CMS token signature");
                 add_unsigned_der(signer, microsoft_timestamp_oid, token);
                 const auto result = parse(der(outer.get(), i2d_PKCS7));
                 const auto& timestamps = sole_signature(result).signers.front().timestamps;
                 check(timestamps.size() == 1 && timestamps.front().type == "rfc3161" &&
                           timestamps.front().time == "2026-01-02T03:04:05Z",
                       "non-X509 CMS certificate choice prevented timestamp parsing");
                 check(timestamps.front().certificates.size() == 1 &&
                           timestamps.front().signer_subject.find("Timestamp test signer") !=
                               std::string::npos,
                       "non-X509 CMS certificate choice prevented ordinary TSA certificate matching");
             }},
            {"duplicate signingTime does not select an arbitrary value", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 auto* signer = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
                 auto attribute = own<X509_ATTRIBUTE, X509_ATTRIBUTE_free>(
                     X509_ATTRIBUTE_create_by_NID(nullptr, NID_pkcs9_signingTime,
                                                  V_ASN1_UTCTIME, "260102040506Z", 13),
                     "create duplicate signingTime attribute");
                 openssl_check(sk_X509_ATTRIBUTE_push(signer->auth_attr, attribute.get()) > 0,
                               "append duplicate signingTime");
                 attribute.release();
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 check(!result.errors.empty() && result.signatures.size() == 1,
                       "duplicate signingTime was not reported as an attribute error");
                 check(result.signatures.front().signers.size() == 1 &&
                           result.signatures.front().signers.front().signing_time.empty(),
                       "ambiguous signingTime produced a chosen time");
             }},
            {"DER alignment padding and nonzero tail", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 Bytes bytes = der(p7.get(), i2d_PKCS7);
                 bytes.insert(bytes.end(), 7, 0);
                 sole_signature(parse(bytes));
                 bytes.back() = 0xff;
                 check(!parse(bytes).errors.empty(), "nonzero trailing bytes were accepted");
             }},
            {"malformed DER is a record error", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 Bytes truncated = der(p7.get(), i2d_PKCS7);
                 truncated.pop_back();
                 check(!parse(truncated).errors.empty(), "truncated DER accepted");
                 check(!parse(Bytes{0x30, 0x80, 0xff, 0, 0}).errors.empty(),
                       "invalid BER accepted");
                 check(!parse(Bytes{}).errors.empty(), "empty record accepted");
             }},
            {"invalid indirect-data structure cannot masquerade as image digest", [&] {
                 const Bytes hidden_digest = tlv(0x30, tlv(0x04, Bytes(32, 0x42)));
                 auto p7 = fixture(keys.first.get(), keys.first_key.get(), true, hidden_digest);
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 check(!result.errors.empty(), "malformed SpcIndirectDataContent accepted");
                 for (const auto& signature : result.signatures) {
                     check(signature.embedded_digest.empty(), "unstructured OCTET STRING used as digest");
                 }
             }},
            {"non-PE indirect-data and unknown algorithm", [&] {
                 auto non_pe = fixture(keys.first.get(), keys.first_key.get(), true,
                                       indirect_data("1.2.3.4.5"));
                 const auto non_pe_result = parse(der(non_pe.get(), i2d_PKCS7));
                 check(sole_signature(non_pe_result).embedded_digest.empty(),
                       "non-PE indirect data reported as image digest");
                 auto unknown = fixture(keys.first.get(), keys.first_key.get(), true,
                                        indirect_data(pe_image_oid, "1.2.3.4.999"));
                 const auto unknown_result = parse(der(unknown.get(), i2d_PKCS7));
                 check(sole_signature(unknown_result).digest_algorithm.oid == "1.2.3.4.999",
                       "unknown algorithm OID was lost");
             }},
            {"catalog ContentInfo has no direct PE image digest or unexpected-type warning", [&] {
                 const Bytes content = catalog_data();
                 for (const int value_type : {V_ASN1_SEQUENCE, V_ASN1_OCTET_STRING}) {
                     auto p7 = make_signed_data(content, catalog_content_oid, value_type);
                     add_signer(p7.get(), keys.first.get(), keys.first_key.get(),
                                content, catalog_content_oid);
                     auto result = parse(der(p7.get(), i2d_PKCS7));
                     result.signature_type = "cataloged";
                     const auto& signature = sole_signature(result);
                     check(signature.content_type == catalog_content_oid,
                           "Catalog content type was lost");
                     check(result.warnings.empty(), "normal Catalog produced a parser warning");
                     check(signature.embedded_digest.empty() &&
                               signature.digest_algorithm.oid.empty() &&
                               signature.digest_algorithm.name.empty(),
                           "Catalog member digest was exposed as a direct PE image digest");
                     check(signature.signers.size() == 1 && signature.certificates.size() == 1 &&
                               signature.signers.front().digest_algorithm.oid == sha256_oid,
                           "Catalog signer metadata was lost");
                     check_signer_certificate(signature, signature.signers.front());
                     const std::string text = pesign::to_text(result);
                     check(text.find("imageDigestAlgorithm:") == std::string::npos &&
                               text.find("embeddedDigest:") == std::string::npos,
                           "Catalog text report displayed inapplicable direct image digest fields");
                     check(text.find("verification: not_performed") != std::string::npos,
                           "Catalog parsing unexpectedly implied verification");
                     const std::string json = pesign::to_json(result);
                     check(json.find("\"digestAlgorithm\":{\"oid\":\"\",\"name\":\"\"}") !=
                               std::string::npos &&
                               json.find("\"embeddedDigest\":\"\"") != std::string::npos,
                           "Catalog JSON changed the empty direct image digest schema");
                 }
             }},
            {"unknown ContentInfo does not expose a claimed PE image digest", [&] {
                 const Bytes content = indirect_data();
                 constexpr const char* unknown_content_oid = "1.2.3.4.888";
                 auto p7 = make_signed_data(content, unknown_content_oid);
                 add_signer(p7.get(), keys.first.get(), keys.first_key.get(),
                            content, unknown_content_oid);
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.content_type == unknown_content_oid &&
                           signature.embedded_digest.empty() &&
                           signature.digest_algorithm.oid.empty(),
                       "unknown ContentInfo was treated as Authenticode");
                 check(std::any_of(result.warnings.begin(), result.warnings.end(),
                                   [&](const std::string& message) {
                                       return message.find("content type is not Authenticode SpcIndirectDataContent: " +
                                                           std::string(unknown_content_oid)) != std::string::npos;
                                   }), "unknown content type needs its diagnostic warning");
             }},
            {"nested depth and aggregate signature limits", [&] {
                 auto leaf = fixture(keys.first.get(), keys.first_key.get());
                 Bytes bytes = der(leaf.get(), i2d_PKCS7);
                 for (int depth = 0; depth != 10; ++depth) {
                     auto parent = fixture(keys.first.get(), keys.first_key.get());
                     add_unsigned_der(sk_PKCS7_SIGNER_INFO_value(parent->d.sign->signer_info, 0),
                                      nested_oid, bytes);
                     bytes = der(parent.get(), i2d_PKCS7);
                 }
                 const auto deep = parse(bytes);
                 check(!deep.errors.empty() && deep.signatures.size() <= 9,
                       "nested depth limit not enforced");
                 bytes = der(leaf.get(), i2d_PKCS7);
                 pesign::Analysis aggregate;
                 for (std::size_t record = 0; record != 65; ++record) {
                     pesign::detail::parse_pkcs7(bytes.data(), bytes.size(), record, aggregate);
                 }
                 check(!aggregate.errors.empty() && aggregate.signatures.size() <= 64,
                       "Analysis-wide signature limit not enforced");
             }},
            {"signer count limit", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 const Bytes signer_der = der(sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0),
                                               i2d_PKCS7_SIGNER_INFO);
                 for (int index = 1; index != 129; ++index) {
                     const unsigned char* cursor = signer_der.data();
                     auto copy = own<PKCS7_SIGNER_INFO, PKCS7_SIGNER_INFO_free>(
                         d2i_PKCS7_SIGNER_INFO(nullptr, &cursor,
                                              static_cast<long>(signer_der.size())),
                         "copy signer fixture");
                     openssl_check(sk_PKCS7_SIGNER_INFO_push(p7->d.sign->signer_info,
                                                            copy.get()) > 0,
                                   "append signer fixture");
                     copy.release();
                 }
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 check(!result.errors.empty(), "129 signers accepted without a limit error");
                 for (const auto& signature : result.signatures) {
                     check(signature.signers.size() <= 128, "signer count limit not enforced");
                 }
             }},
            {"oversized CRL URI is omitted without losing ordinary certificate metadata", [&] {
                 const std::string uri = "https://example.invalid/" + std::string(4096, 'a');
                 auto cert = make_certificate(keys.first_key.get(), 17,
                                               "Long URI test signer", uri);
                 auto p7 = fixture(cert.get(), keys.first_key.get());
                 const auto result = parse(der(p7.get(), i2d_PKCS7));
                 const auto& signature = sole_signature(result);
                 check(signature.certificates.size() == 1 && signature.signers.size() == 1,
                       "oversized optional URI discarded the ordinary signature metadata");
                 const auto& certificate = signature.certificates.front();
                 check(certificate.subject.find("Long URI test signer") != std::string::npos &&
                           certificate.sha256_thumbprint.size() == 64,
                       "oversized URI discarded ordinary certificate metadata");
                 check(certificate.crl_distribution_points.empty() && !result.warnings.empty(),
                       "oversized URI was emitted or silently omitted");
                 check_signer_certificate(signature, signature.signers.front());
             }},
            {"aggregate metadata budget prevents repeated record amplification", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 const Bytes bytes = der(p7.get(), i2d_PKCS7);
                 pesign::Analysis result;
                 // A prior Analysis is accepted by parse_pkcs7 so separate
                 // WIN_CERTIFICATE records share one output budget. These 3 MiB
                 // of text would expand past 16 MiB when serialized as JSON.
                 result.signatures.resize(2);
                 for (auto& signature : result.signatures) {
                     signature.certificates.resize(384);
                     for (auto& certificate : signature.certificates) {
                         certificate.subject.assign(4096, '\x01');
                     }
                 }
                 pesign::detail::parse_pkcs7(bytes.data(), bytes.size(), 2, result);
                 check(result.signatures.size() == 2,
                       "another record bypassed the aggregate metadata budget");
                 check(std::any_of(result.errors.begin(), result.errors.end(),
                                   [](const std::string& error) {
                                       return error.find("metadata") != std::string::npos &&
                                           error.find("16 MiB") != std::string::npos;
                                   }), "metadata output budget exhaustion was not reported");
             }},
            {"PE32 and PE32+ public analysis path", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 const Bytes payload = der(p7.get(), i2d_PKCS7);
                 for (const bool pe32_plus : {false, true}) {
                     const auto result = pesign::analyze_bytes(pe_with_signature(payload, pe32_plus));
                     const auto& signature = sole_signature(result);
                     check(result.pe_format == (pe32_plus ? "PE32+" : "PE32"),
                           "PE format missing");
                     check(result.certificate_records.size() == 1 &&
                               result.certificate_records.front().offset == 0x200 &&
                               signature.certificate_record == 0,
                           "PE certificate record provenance incorrect");
                 }
             }},
            {"JSON metadata escaping and verification status", [&] {
                 auto p7 = fixture(keys.first.get(), keys.first_key.get());
                 auto result = parse(der(p7.get(), i2d_PKCS7));
                 const std::string clean_json = pesign::to_json(result);
                 check(clean_json.find("\"verification\":\"not_performed\"") !=
                           std::string::npos &&
                           clean_json.find("\"parseStatus\":\"ok\"") != std::string::npos &&
                           clean_json.find("\"signatureType\":\"embedded\"") != std::string::npos,
                       "successful parsing was incorrectly reported as signature verification");
                 check(clean_json.find("\"certificateRecord\":3") != std::string::npos &&
                           clean_json.find("\"parentSignature\":-1") != std::string::npos &&
                           clean_json.find("\"certificateIndex\":0") != std::string::npos &&
                           clean_json.find("\"signingTime\":\"2026-01-02T03:04:05Z\"") !=
                               std::string::npos,
                       "JSON lost signature provenance or signer metadata");

                 const std::string raw = std::string("path\"\\\b\f\n\r\t") +
                     static_cast<char>(1) + static_cast<char>(31) + u8"中文.exe";
                 const std::string escaped =
                     std::string("path\\\"\\\\\\b\\f\\n\\r\\t\\u0001\\u001f") + u8"中文.exe";
                 result.file = raw;
                 result.signatures.front().certificates.front().subject = raw;
                 result.warnings.push_back("warning\n\"quoted\"");
                 result.errors.push_back("failure\t\\");
                 const std::string json = pesign::to_json(result);
                 check(json.find("\"file\":\"" + escaped + "\"") != std::string::npos &&
                           json.find("\"subject\":\"" + escaped + "\"") != std::string::npos,
                       "path or certificate metadata was not correctly JSON escaped");
                 check(json.find("\"warnings\":[\"warning\\n\\\"quoted\\\"\"]") !=
                           std::string::npos &&
                           json.find("\"errors\":[\"failure\\t\\\\\"]") != std::string::npos,
                       "JSON diagnostic array escaping failed");
                 check(std::none_of(json.begin(), json.end(), [](unsigned char byte) {
                           return byte < 0x20;
                       }), "JSON contains an unescaped control character");
                 check(json.find("\"parseStatus\":\"partial\"") != std::string::npos &&
                           json.find("\"verification\":\"not_performed\"") != std::string::npos,
                       "partial parsing changed the verification status");
                 const std::vector<std::string> invalid_utf8 = {
                     std::string("\x80", 1),             // Isolated continuation.
                     std::string("\xc0\xaf", 2),        // Overlong two-byte sequence.
                     std::string("\xe0\x80\x80", 3),   // Overlong three-byte sequence.
                     std::string("\xf0\x80\x80\x80", 4), // Overlong four-byte sequence.
                     std::string("\xed\xa0\x80", 3),   // Surrogate U+D800.
                     std::string("\xf4\x90\x80\x80", 4), // Beyond U+10FFFF.
                     std::string("\xe4\xb8", 2),        // Truncated sequence.
                     std::string("\xff", 1)             // Invalid leading byte.
                 };
                 for (const auto& invalid : invalid_utf8) {
                     result.file = invalid;
                     std::string replacement;
                     for (std::size_t index = 0; index < invalid.size(); ++index)
                         replacement += "\\ufffd";
                     const std::string safe_json = pesign::to_json(result);
                     check(safe_json.find("\"file\":\"" + replacement + "\"") !=
                               std::string::npos, "invalid UTF-8 was emitted in JSON");
                 }
                 result.file = std::string("\xe4", 1) + "A" + std::string("\x80", 1);
                 check(pesign::to_json(result).find("\"file\":\"\\ufffdA\\ufffd\"") !=
                           std::string::npos, "invalid UTF-8 swallowed adjacent ASCII");
                 const std::string valid_utf8 = std::string("\xc2\x80", 2) +
                     std::string("\xe0\xa0\x80", 3) + std::string("\xed\x9f\xbf", 3) +
                     std::string("\xf0\x90\x80\x80", 4) + std::string("\xf4\x8f\xbf\xbf", 4);
                 result.file = valid_utf8;
                 check(pesign::to_json(result).find("\"file\":\"" + valid_utf8 + "\"") !=
                           std::string::npos, "valid UTF-8 scalar boundaries were not retained");
                 check(pesign::to_text(result).find("verification: not_performed") !=
                           std::string::npos, "text report omitted unverified status");
                 const std::string empty_json = pesign::to_json(pesign::Analysis{});
                 check(empty_json.find("\"signatureType\":\"none\"") != std::string::npos &&
                           empty_json.find("\"signatures\":[]") != std::string::npos &&
                           empty_json.find("\"verification\":\"not_performed\"") !=
                               std::string::npos,
                       "unsigned report incorrectly implied signature verification");
             }},
        };
        std::size_t failures = 0;
        for (const auto& test : tests) {
            try {
                test.second();
                std::cout << "PASS " << test.first << '\n';
            } catch (const std::exception& error) {
                std::cerr << "FAIL " << test.first << ": " << error.what() << '\n';
                ++failures;
            }
        }
        std::cout << tests.size() - failures << '/' << tests.size()
                  << " PKCS#7 tests passed\n";
        return failures == 0 ? 0 : 1;
    } catch (const std::exception& error) {
        std::cerr << "Fixture setup failed: " << error.what() << '\n';
        return 1;
    }
}
