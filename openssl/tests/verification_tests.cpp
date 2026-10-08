#include "pesign/analyzer.h"
#include "verification_fixtures.h"

#include <functional>
#include <iostream>
#include <utility>

namespace {

using namespace verification_fixture;
constexpr std::time_t verification_time = 1800000000; // January 2027, independent of the host clock.

pesign::Options options(const Fixtures& fixtures) {
    pesign::Options result;
    result.verify = true;
    result.use_system_roots = false;
    result.ca_file = fixtures.directory / "root.pem";
    result.verification_time = verification_time;
    return result;
}
const pesign::Verification& first(const pesign::Analysis& result) {
    require(result.errors.empty(), result.errors.empty() ? "analysis errors" : result.errors.front());
    require(!result.signatures.empty(), "missing parsed signature");
    require(!result.signatures.front().signers.empty(), "missing parsed signer");
    return result.signatures.front().signers.front().verification;
}
void valid(const pesign::Analysis& result, const char* context) {
    const auto& verification = first(result);
    require(verification.cms_signature == "valid", std::string(context) + ": CMS signature " + verification.cms_signature);
    require(verification.content_digest == "valid", std::string(context) + ": content digest " + verification.content_digest);
    require(verification.certificate_chain == "trusted", std::string(context) + ": chain " + verification.certificate_chain);
    require(verification.overall == "valid", std::string(context) + ": overall " + verification.overall);
}
pesign::Options metadata_options(const Fixtures& fixtures) {
    auto result = options(fixtures);
    result.verify = false;
    return result;
}
std::string thumbprint(X509* certificate, const EVP_MD* algorithm) {
    constexpr char digits[] = "0123456789ABCDEF";
    const auto digest = hash(der(certificate, i2d_X509), algorithm);
    std::string result;
    for (auto byte : digest) {
        result.push_back(digits[byte >> 4]);
        result.push_back(digits[byte & 15]);
    }
    return result;
}
void complete_metadata_chain(const pesign::Signer& signer, const Fixtures& fixtures, const char* context) {
    const auto& chain = signer.certificate_chain;
    require(chain.status == "built", std::string(context) + ": metadata chain " + chain.status);
    require(chain.certificates.size() == 3, std::string(context) + ": missing issuer or root certificate");
    require(chain.certificates.front().serial == signer.serial,
            std::string(context) + ": chain does not start with this signer's certificate");
    require(chain.certificates[1].serial == "02", std::string(context) + ": intermediate order");
    const auto& root = chain.certificates.back();
    require(root.subject == "CN=Offline test root" && root.issuer == root.subject,
            std::string(context) + ": wrong root subject or issuer");
    require(root.version == 3 && root.serial == "01", std::string(context) + ": root identity metadata");
    require(root.sha1_thumbprint == thumbprint(fixtures.root.get(), EVP_sha1()) &&
                root.sha256_thumbprint == thumbprint(fixtures.root.get(), EVP_sha256()),
            std::string(context) + ": root thumbprints differ from the CA certificate");
    require(root.not_before == "2020-01-01T00:00:00Z" && root.not_after == "2040-01-01T00:00:00Z",
            std::string(context) + ": root validity metadata missing");
    require(root.signature_algorithm.name == "sha256WithRSAEncryption",
            std::string(context) + ": root signature algorithm missing");
    require(root.crl_distribution_points == std::vector<std::string>{"http://127.0.0.1:1/offline.crl"},
            std::string(context) + ": root CRL metadata missing");
}
Bytes ctl(const Bytes& digest) {
    const auto usage = tlv(0x30, oid("1.3.6.1.4.1.311.12.1.1"));
    const auto time = tlv(0x17, Bytes{'2','6','0','1','0','2','0','3','0','4','0','5','Z'});
    const auto algorithm = tlv(0x30, concat(oid("2.16.840.1.101.3.4.2.1"), Bytes{0x05,0x00}));
    const auto member = tlv(0x30, concat(tlv(0x04, digest), tlv(0x31, {})));
    return tlv(0x30, concat(concat(concat(usage, time), algorithm), tlv(0x30, member)));
}
P7 catalog(const Fixtures& fixtures, const Bytes& member) {
    constexpr const char* catalog_oid = "1.3.6.1.4.1.311.10.1";
    const auto content = ctl(member);
    auto p7 = signed_data(content, catalog_oid);
    signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content), catalog_oid);
    ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "catalog intermediate");
    return p7;
}
Bytes microsoft_ctl(const std::vector<Bytes>& members, bool v2, const Bytes& attributes = {}) {
    const auto usage = tlv(0x30, oid("1.3.6.1.4.1.311.12.1.1"));
    const auto list_identifier = tlv(0x04, Bytes(16, 0x37));
    const Bytes sequence_number{0x02,0x01,0x01};
    const auto time = tlv(0x17, Bytes{'2','6','0','1','0','2','0','3','0','4','0','5','Z'});
    const auto algorithm = tlv(0x30, concat(oid(v2 ? "1.3.6.1.4.1.311.12.1.3" : "1.3.6.1.4.1.311.12.1.2"),
                                           Bytes{0x05,0x00}));
    Bytes entries;
    for (const auto& member : members)
        entries = concat(std::move(entries), tlv(0x30, concat(tlv(0x04, member), tlv(0x31, attributes))));
    return tlv(0x30, concat(concat(concat(concat(concat(usage, list_identifier), sequence_number), time), algorithm),
                           tlv(0x30, entries)));
}
P7 signed_catalog(const Fixtures& fixtures, const Bytes& content) {
    constexpr const char* catalog_oid = "1.3.6.1.4.1.311.10.1";
    auto p7 = signed_data(content, catalog_oid);
    signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content), catalog_oid);
    ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "Microsoft catalog intermediate");
    return p7;
}
void attach_timestamp(PKCS7* p7, const Fixtures& fixtures, X509* tsa = nullptr,
                      bool mismatch = false, bool key_id = false,
                      const char* time = "20260102030405Z") {
    auto* primary = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
    auto signature_value = signature_bytes(primary);
    if (mismatch) signature_value.front() ^= 1;
    const auto token = timestamp(tsa ? tsa : fixtures.tsa.get(), fixtures.tsa_key.get(),
                                  fixtures.intermediate.get(), signature_value, time, key_id);
    unsigned_attribute(primary, timestamp_oid, token);
}
void attach_counter(PKCS7* p7, const Fixtures& fixtures, bool mismatch = false, X509* tsa = nullptr,
                     const char* content_type = nullptr) {
    auto* primary = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
    auto value = signature_bytes(primary);
    if (mismatch) value.front() ^= 1;
    auto temporary = signed_data({0x30, 0x00});
    X509* certificate = tsa ? tsa : fixtures.tsa.get();
    auto* counter = signer(temporary.get(), certificate, fixtures.tsa_key.get(), value, content_type);
    unsigned_attribute(primary, "1.2.840.113549.1.9.6", der(counter, i2d_PKCS7_SIGNER_INFO));
    ssl_check(PKCS7_add_certificate(p7, certificate) == 1, "counter TSA certificate");
}
void export_online(const std::filesystem::path& directory, const std::string& base_url) {
    Fixtures fixtures;
    std::filesystem::create_directories(directory);
    auto intermediate = certificate(fixtures.intermediate_key.get(), 20, "Online intermediate",
        fixtures.root.get(), fixtures.root_key.get(), nullptr, true, "20200101000000Z", "20400101000000Z",
        base_url + "/root.crl", base_url + "/ocsp/root");
    auto leaf = certificate(fixtures.signer_key.get(), 21, "Online code signer", intermediate.get(),
        fixtures.intermediate_key.get(), "codeSigning", false, "20200101000000Z", "20400101000000Z",
        base_url + "/issuer.crl", base_url + "/ocsp/issuer", base_url + "/intermediate.der");
    const auto content = indirect_data(image_hash(image()));
    auto p7 = signed_data(content);
    signer(p7.get(), leaf.get(), fixtures.signer_key.get(), content_bytes(content));
    write(directory / "missing-issuer.exe", attach(image(), p7.get()));
    ssl_check(PKCS7_add_certificate(p7.get(), intermediate.get()) == 1, "online intermediate");
    pem(directory / "root.pem", fixtures.root.get());
    write(directory / "signed.exe", attach(image(), p7.get()));
    write(directory / "intermediate.der", der(intermediate.get(), i2d_X509));
    auto wrong_issuer = own<X509, X509_free>(X509_dup(intermediate.get()), "wrong cached AIA issuer");
    // Retain the issuer DN and SKI matching the child's AKI, but replace only
    // its public key. DN/AKI matching alone cannot detect this forged binding.
    ssl_check(X509_set_pubkey(wrong_issuer.get(), fixtures.tsa_key.get()) == 1, "wrong AIA public key");
    ssl_check(X509_sign(wrong_issuer.get(), fixtures.root_key.get(), EVP_sha256()) > 0, "sign wrong AIA issuer");
    write(directory / "wrong-intermediate.der", der(wrong_issuer.get(), i2d_X509));
    write(directory / "root.crl", crl(fixtures.root.get(), fixtures.root_key.get()));
    write(directory / "issuer.crl", crl(intermediate.get(), fixtures.intermediate_key.get()));
    write(directory / "revoked.crl", crl(intermediate.get(), fixtures.intermediate_key.get(), leaf.get()));
    write(directory / "root.ocsp", ocsp(intermediate.get(), fixtures.root.get(), fixtures.root_key.get()));
    write(directory / "issuer.ocsp", ocsp(leaf.get(), intermediate.get(), fixtures.intermediate_key.get()));
    write(directory / "revoked.ocsp", ocsp(leaf.get(), intermediate.get(), fixtures.intermediate_key.get(),
                                           V_OCSP_CERTSTATUS_REVOKED));
}

} // namespace

template <typename Char>
int run(int argc, Char** argv) {
    try {
        if (argc == 4 && std::filesystem::path(argv[1]).u8string() == "--export-online") {
            export_online(std::filesystem::path(argv[2]), std::filesystem::path(argv[3]).u8string());
            return 0;
        }
        require(argc == 1, "unsupported verification test arguments");
        Fixtures fixtures;
        const std::vector<std::pair<const char*, std::function<void()>>> tests{
            {"independent Authenticode digests for PE32 and PE32+", [&] {
                for (bool plus : {false, true}) {
                    const auto bytes = image(plus);
                    require(pesign::authenticode_digest(bytes, "2.16.840.1.101.3.4.2.1") == image_hash(bytes, plus),
                            "independent SHA256 image digest mismatch");
                    require(pesign::authenticode_digest(bytes, "1.3.14.3.2.26") == image_hash(bytes, plus, EVP_sha1()),
                            "independent SHA1 image digest mismatch");
                    auto p7 = fixtures.signature(nullptr, plus);
                    const auto signed_bytes = attach(bytes, p7.get(), plus);
                    require(pesign::authenticode_digest(signed_bytes, "2.16.840.1.101.3.4.2.1") == image_hash(bytes, plus),
                            "certificate table must be excluded from image digest");
                    valid(pesign::analyze_bytes(signed_bytes, options(fixtures)), "real signed PE");
                }
            }},
            {"checksum exclusion and authenticated section tamper", [&] {
                auto p7 = fixtures.signature();
                auto bytes = attach(image(), p7.get());
                bytes[0x98 + 64] ^= 0x43;
                valid(pesign::analyze_bytes(bytes, options(fixtures)), "checksum mutation");
                bytes[0x225] ^= 1;
                const auto result = pesign::analyze_bytes(bytes, options(fixtures));
                require(first(result).content_digest != "valid" && first(result).overall != "valid",
                        "modified section was accepted");
            }},
            {"section gaps and reversed section headers are authenticated in file order", [&] {
                auto bytes = image();
                bytes.resize(0x900);
                for (std::size_t i = 0x200; i < bytes.size(); ++i)
                    bytes[i] = static_cast<std::uint8_t>(i * 71 + 13);
                put16(bytes, 0x86, 2);
                constexpr std::size_t first_section = 0x98 + 224;
                put32(bytes, first_section + 16, 0x100);
                put32(bytes, first_section + 20, 0x700); // Later raw section appears first in the section table.
                put32(bytes, first_section + 40 + 16, 0x100);
                put32(bytes, first_section + 40 + 20, 0x300);
                // Independent original Windows/osslsigncode hash stream: preserve file
                // order, excluding only checksum, security directory and certificate data.
                Bytes stream(bytes.begin(), bytes.begin() + 0xd8);
                stream.insert(stream.end(), bytes.begin() + 0xdc, bytes.begin() + 0x118);
                stream.insert(stream.end(), bytes.begin() + 0x120, bytes.begin() + 0x200);
                stream.insert(stream.end(), bytes.begin() + 0x200, bytes.end());
                const auto expected = hash(stream);
                require(pesign::authenticode_digest(bytes, "2.16.840.1.101.3.4.2.1") == expected,
                        "gapped/reversed section hash differed from independent range concatenation");
                const auto content = indirect_data(expected);
                auto p7 = signed_data(content);
                signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content));
                ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "gapped PE intermediate");
                auto signed_bytes = attach(bytes, p7.get());
                valid(pesign::analyze_bytes(signed_bytes, options(fixtures)), "gapped and reversed signed PE");
                signed_bytes[0x250] ^= 1;
                const auto gap_tamper = pesign::analyze_bytes(signed_bytes, options(fixtures));
                require(first(gap_tamper).content_digest != "valid" && first(gap_tamper).overall != "valid",
                        "raw-section gap tamper was accepted");
            }},
            {"data after the certificate table remains authenticated", [&] {
                const Bytes postfix{0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89};
                const auto unsigned_with_postfix = concat(image(), postfix);
                const auto content = indirect_data(image_hash(unsigned_with_postfix));
                auto p7 = signed_data(content);
                signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content));
                ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "post-certificate intermediate");
                auto bytes = concat(attach(image(), p7.get()), postfix);
                require(pesign::authenticode_digest(bytes, "2.16.840.1.101.3.4.2.1") == image_hash(unsigned_with_postfix),
                        "post-certificate overlay missing from hash");
                valid(pesign::analyze_bytes(bytes, options(fixtures)), "post-certificate overlay");
                bytes.back() ^= 1;
                const auto modified = pesign::analyze_bytes(bytes, options(fixtures));
                require(first(modified).content_digest != "valid" && first(modified).overall != "valid",
                        "post-certificate overlay tamper was accepted");
            }},
            {"legacy MD5 image digest remains supported", [&] {
                const auto expected = image_hash(image(), false, EVP_md5());
                require(pesign::authenticode_digest(image(), "1.2.840.113549.2.5") == expected,
                        "independent MD5 image digest mismatch");
                const auto content = indirect_data(expected, NID_md5);
                auto p7 = signed_data(content);
                signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content));
                ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "MD5 intermediate");
                valid(pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures)), "legacy MD5 image digest");
                auto md5_signer = signed_data(content);
                signer(md5_signer.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content),
                       spc_oid, "260102030405Z", EVP_md5());
                ssl_check(PKCS7_add_certificate(md5_signer.get(), fixtures.intermediate.get()) == 1, "MD5 signer intermediate");
                valid(pesign::analyze_bytes(attach(image(), md5_signer.get()), options(fixtures)), "legacy MD5 signed attributes");
            }},
            {"FileAlignment padding of an unaligned raw section remains authenticated", [&] {
                auto bytes = image();
                bytes.resize(0x600);
                for (std::size_t i = 0x400; i < bytes.size(); ++i)
                    bytes[i] = static_cast<std::uint8_t>(i * 43 + 7);
                put32(bytes, 0x98 + 36, 0x200); // FileAlignment.
                put16(bytes, 0x86, 2);
                put32(bytes, 0x98 + 224 + 16, 0x18f); // Raw bytes plus alignment padding occupy 0x200 bytes.
                put32(bytes, 0x98 + 224 + 40 + 16, 0x1a9);
                put32(bytes, 0x98 + 224 + 40 + 20, 0x400); // Git-style next section follows the padding gap.
                const auto expected = image_hash(bytes);
                require(pesign::authenticode_digest(bytes, "2.16.840.1.101.3.4.2.1") == expected,
                        "unaligned SizeOfRawData did not include its FileAlignment padding");
                const auto content = indirect_data(expected);
                auto p7 = signed_data(content);
                signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(content));
                ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "unaligned PE intermediate");
                auto signed_bytes = attach(bytes, p7.get());
                valid(pesign::analyze_bytes(signed_bytes, options(fixtures)), "unaligned raw section");
                signed_bytes[0x3f0] ^= 1; // Within raw padding, beyond the declared 0x18f section length.
                const auto altered = pesign::analyze_bytes(signed_bytes, options(fixtures));
                require(first(altered).content_digest != "valid" && first(altered).overall != "valid",
                        "FileAlignment padding tamper was accepted");
            }},
            {"cryptographic signature tamper", [&] {
                auto p7 = fixtures.signature();
                auto* primary = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
                primary->enc_digest->data[0] ^= 1;
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                require(first(result).cms_signature != "valid" && first(result).overall != "valid",
                        "modified RSA signature was accepted");
            }},
            {"SPC authenticated digest excludes its DER wrapper", [&] {
                const auto content = indirect_data(image_hash(image()));
                auto p7 = signed_data(content);
                signer(p7.get(), fixtures.code.get(), fixtures.signer_key.get(), content);
                ssl_check(PKCS7_add_certificate(p7.get(), fixtures.intermediate.get()) == 1, "intermediate");
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                require(first(result).cms_signature != "valid", "non-Authenticode content hash was accepted");
            }},
            {"signed attributes require unique messageDigest and matching contentType", [&] {
                auto duplicate = fixtures.signature();
                auto* primary = sk_PKCS7_SIGNER_INFO_value(duplicate->d.sign->signer_info, 0);
                auto duplicate_digest = own<X509_ATTRIBUTE, X509_ATTRIBUTE_free>(
                    X509_ATTRIBUTE_dup(sk_X509_ATTRIBUTE_value(primary->auth_attr,
                        X509at_get_attr_by_NID(primary->auth_attr, NID_pkcs9_messageDigest, -1))), "duplicate attr");
                ssl_check(sk_X509_ATTRIBUTE_push(primary->auth_attr, duplicate_digest.get()) > 0, "duplicate attr push");
                duplicate_digest.release();
                ssl_check(PKCS7_SIGNER_INFO_sign(primary) == 1, "sign duplicate attrs");
                require(first(pesign::analyze_bytes(attach(image(), duplicate.get()), options(fixtures))).cms_signature != "valid",
                        "duplicate authenticated messageDigest accepted");
                auto wrong_type = fixtures.signature();
                auto* wrong_signer = sk_PKCS7_SIGNER_INFO_value(wrong_type->d.sign->signer_info, 0);
                auto object = own<ASN1_OBJECT, ASN1_OBJECT_free>(OBJ_txt2obj("1.2.840.113549.1.7.1", 1), "wrong content OID");
                ssl_check(PKCS7_add_signed_attribute(wrong_signer, NID_pkcs9_contentType,
                    V_ASN1_OBJECT, object.get()) == 1, "wrong contentType attr");
                object.release();
                ssl_check(PKCS7_SIGNER_INFO_sign(wrong_signer) == 1, "sign wrong contentType");
                require(first(pesign::analyze_bytes(attach(image(), wrong_type.get()), options(fixtures))).cms_signature != "valid",
                        "authenticated contentType mismatch accepted");
            }},
            {"untrusted root and missing intermediate", [&] {
                auto p7 = fixtures.signature();
                auto untrusted = options(fixtures);
                untrusted.ca_file.clear();
                require(first(pesign::analyze_bytes(attach(image(), p7.get()), untrusted)).certificate_chain != "trusted",
                        "untrusted embedded root accepted");
                auto missing = fixtures.signature(nullptr, false, false);
                require(first(pesign::analyze_bytes(attach(image(), missing.get()), options(fixtures))).certificate_chain != "trusted",
                        "missing intermediate was accepted");
            }},
            {"code signing EKU and certificate expiry", [&] {
                auto wrong = fixtures.signature(fixtures.wrong_purpose.get());
                require(first(pesign::analyze_bytes(attach(image(), wrong.get()), options(fixtures))).overall != "valid",
                        "serverAuth-only signer accepted as code signer");
                auto expired = fixtures.signature(fixtures.expired.get());
                const auto result = pesign::analyze_bytes(attach(image(), expired.get()), options(fixtures));
                require(first(result).certificate_chain != "trusted" && first(result).overall != "valid",
                        "expired code signer accepted");
            }},
            {"self-asserted signingTime cannot rescue expired signer", [&] {
                auto p7 = fixtures.signature(fixtures.expired.get(), false, true, "260102030405Z");
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                require(first(result).overall != "valid", "untrusted signingTime changed certificate validation time");
            }},
            {"trusted RFC3161 timestamp rescues historical signer", [&] {
                for (bool key_id : {false, true}) {
                    auto p7 = fixtures.signature(fixtures.expired.get());
                    attach_timestamp(p7.get(), fixtures, nullptr, false, key_id);
                    const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                    valid(result, "timestamped expired signer");
                    require(first(result).timestamp == "valid", "RFC3161 timestamp was not trusted");
                }
            }},
            {"RFC3161 must bind the primary signature and TSA purpose", [&] {
                auto wrong_imprint = fixtures.signature(fixtures.expired.get());
                attach_timestamp(wrong_imprint.get(), fixtures, nullptr, true);
                const auto mismatch = pesign::analyze_bytes(attach(image(), wrong_imprint.get()), options(fixtures));
                require(first(mismatch).timestamp != "valid" && first(mismatch).overall != "valid",
                        "unbound timestamp was accepted");
                auto wrong_tsa = fixtures.signature(fixtures.expired.get());
                attach_timestamp(wrong_tsa.get(), fixtures, fixtures.bad_tsa.get());
                const auto purpose = pesign::analyze_bytes(attach(image(), wrong_tsa.get()), options(fixtures));
                require(first(purpose).timestamp != "valid" && first(purpose).overall != "valid",
                        "non-TSA certificate accepted for timestamp");
            }},
            {"RFC3161 rejects wrong ESS identity, untrusted TSA and future time", [&] {
                auto wrong_ess = fixtures.signature(fixtures.expired.get());
                auto* primary = sk_PKCS7_SIGNER_INFO_value(wrong_ess->d.sign->signer_info, 0);
                const auto token = timestamp(fixtures.tsa.get(), fixtures.tsa_key.get(), fixtures.intermediate.get(),
                    signature_bytes(primary), "20260102030405Z", false, fixtures.code.get());
                unsigned_attribute(primary, timestamp_oid, token);
                require(first(pesign::analyze_bytes(attach(image(), wrong_ess.get()), options(fixtures))).timestamp != "valid",
                        "wrong ESS signer identity accepted");
                auto rogue_tsa = certificate(fixtures.tsa_key.get(), 90, "Untrusted timestamp authority",
                                             nullptr, nullptr, "timeStamping");
                auto untrusted = fixtures.signature(fixtures.expired.get());
                attach_timestamp(untrusted.get(), fixtures, rogue_tsa.get());
                require(first(pesign::analyze_bytes(attach(image(), untrusted.get()), options(fixtures))).overall != "valid",
                        "untrusted TSA rescued expired code signer");
                auto future = fixtures.signature(fixtures.expired.get());
                attach_timestamp(future.get(), fixtures, nullptr, false, false, "20300101000000Z");
                require(first(pesign::analyze_bytes(attach(image(), future.get()), options(fixtures))).timestamp != "valid",
                        "future timestamp accepted");
            }},
            {"Microsoft additional ESS references distinguish compatibility and strict policy", [&] {
                auto ms = fixtures.signature(fixtures.expired.get());
                auto* primary = sk_PKCS7_SIGNER_INFO_value(ms->d.sign->signer_info, 0);
                const auto token = timestamp(fixtures.tsa.get(), fixtures.tsa_key.get(), fixtures.intermediate.get(),
                    signature_bytes(primary), "20260102030405Z", false, nullptr, fixtures.code.get());
                unsigned_attribute(primary, timestamp_oid, token);
                const auto bytes = attach(image(), ms.get());
                const auto compatible = pesign::analyze_bytes(bytes, options(fixtures));
                valid(compatible, "Microsoft first ESS identity with unrelated additional reference");
                require(first(compatible).timestamp == "valid", "Microsoft compatibility timestamp not accepted");
                require(!first(compatible).details.empty(), "unresolved additional ESS reference lacks diagnostics");
                auto strict = options(fixtures);
                strict.strict_timestamps = true;
                const auto rejected = pesign::analyze_bytes(bytes, strict);
                require(first(rejected).timestamp != "valid" && first(rejected).overall != "valid",
                        "strict policy ignored an unresolved additional ESS reference");
                auto standard = fixtures.signature(fixtures.expired.get());
                auto* standard_primary = sk_PKCS7_SIGNER_INFO_value(standard->d.sign->signer_info, 0);
                const auto standard_token = timestamp(fixtures.tsa.get(), fixtures.tsa_key.get(), fixtures.intermediate.get(),
                    signature_bytes(standard_primary), "20260102030405Z", false, nullptr, fixtures.code.get());
                unsigned_attribute(standard_primary, "1.2.840.113549.1.9.16.2.14", standard_token);
                const auto standard_result = pesign::analyze_bytes(attach(image(), standard.get()), options(fixtures));
                require(first(standard_result).timestamp != "valid" && first(standard_result).overall != "valid",
                        "standard RFC3161 OID bypassed complete ESS reference validation");
                for (bool enabled : {false, true}) {
                    auto bad_first = fixtures.signature(fixtures.expired.get());
                    auto* bad_primary = sk_PKCS7_SIGNER_INFO_value(bad_first->d.sign->signer_info, 0);
                    const auto bad_token = timestamp(fixtures.tsa.get(), fixtures.tsa_key.get(), fixtures.intermediate.get(),
                        signature_bytes(bad_primary), "20260102030405Z", false, fixtures.code.get());
                    unsigned_attribute(bad_primary, timestamp_oid, bad_token);
                    auto opts = options(fixtures);
                    opts.strict_timestamps = enabled;
                    const auto bad = pesign::analyze_bytes(attach(image(), bad_first.get()), opts);
                    require(first(bad).timestamp != "valid" && first(bad).overall != "valid",
                            "first ESS signer binding was weakened by Microsoft compatibility");
                    auto bad_serial = fixtures.signature(fixtures.expired.get());
                    auto* serial_primary = sk_PKCS7_SIGNER_INFO_value(bad_serial->d.sign->signer_info, 0);
                    const auto serial_token = timestamp(fixtures.tsa.get(), fixtures.tsa_key.get(), fixtures.intermediate.get(),
                        signature_bytes(serial_primary), "20260102030405Z", false, nullptr, nullptr, true);
                    unsigned_attribute(serial_primary, timestamp_oid, serial_token);
                    const auto serial_result = pesign::analyze_bytes(attach(image(), bad_serial.get()), opts);
                    require(first(serial_result).timestamp != "valid" && first(serial_result).overall != "valid",
                            "ESS issuerSerial mismatch bypassed a correct first certificate hash");
                }
            }},
            {"PKCS9 countersignature trust and binding", [&] {
                auto p7 = fixtures.signature(fixtures.expired.get());
                attach_counter(p7.get(), fixtures);
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                valid(result, "PKCS9 timestamp");
                require(first(result).timestamp == "valid", "PKCS9 countersignature not trusted");
                auto forged = fixtures.signature(fixtures.expired.get());
                attach_counter(forged.get(), fixtures, true);
                require(first(pesign::analyze_bytes(attach(image(), forged.get()), options(fixtures))).overall != "valid",
                        "unbound countersignature was accepted");
            }},
            {"Authenticode noncritical sole timestamp EKU compatibility", [&] {
                auto noncritical = own<X509, X509_free>(X509_dup(fixtures.tsa.get()), "duplicate noncritical TSA");
                const auto index = X509_get_ext_by_NID(noncritical.get(), NID_ext_key_usage, -1);
                require(index >= 0, "TSA EKU missing");
                ssl_check(X509_EXTENSION_set_critical(X509_get_ext(noncritical.get(), index), 0) == 1, "set noncritical TSA EKU");
                ssl_check(X509_sign(noncritical.get(), fixtures.intermediate_key.get(), EVP_sha256()) > 0, "resign noncritical TSA");
                for (bool rfc : {false, true}) {
                    auto p7 = fixtures.signature(fixtures.expired.get());
                    if (rfc) attach_timestamp(p7.get(), fixtures, noncritical.get());
                    else attach_counter(p7.get(), fixtures, false, noncritical.get());
                    const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                    valid(result, rfc ? "noncritical RFC3161 EKU" : "noncritical PKCS9 EKU");
                    require(first(result).timestamp == "valid", "compatible noncritical timestamp not trusted");
                }
                auto ambiguous = certificate(fixtures.tsa_key.get(), 91, "Ambiguous timestamp purpose",
                    fixtures.intermediate.get(), fixtures.intermediate_key.get(), "timeStamping,codeSigning");
                for (X509* cert : {fixtures.bad_tsa.get(), ambiguous.get()}) {
                    for (bool rfc : {false, true}) {
                        auto p7 = fixtures.signature(fixtures.expired.get());
                        if (rfc) attach_timestamp(p7.get(), fixtures, cert);
                        else attach_counter(p7.get(), fixtures, false, cert);
                        const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                        if (cert == ambiguous.get() && !rfc) {
                            valid(result, "legacy EKU collection containing timestamp purpose");
                        } else {
                            require(first(result).timestamp != "valid" && first(result).overall != "valid",
                                    "wrong or ambiguous RFC timestamp EKU accepted");
                        }
                    }
                }
                auto data_counter = fixtures.signature(fixtures.expired.get());
                attach_counter(data_counter.get(), fixtures, false, noncritical.get(), "1.2.840.113549.1.7.1");
                valid(pesign::analyze_bytes(attach(image(), data_counter.get()), options(fixtures)), "legacy pkcs7-data contentType");
                auto wrong_key_usage = own<X509, X509_free>(X509_dup(noncritical.get()), "wrong KU TSA");
                auto old_usage = own<X509_EXTENSION, X509_EXTENSION_free>(
                    X509_delete_ext(wrong_key_usage.get(), X509_get_ext_by_NID(wrong_key_usage.get(), NID_key_usage, -1)),
                    "remove original TSA KU");
                extension(wrong_key_usage.get(), fixtures.intermediate.get(), NID_key_usage, "critical,keyEncipherment");
                ssl_check(X509_sign(wrong_key_usage.get(), fixtures.intermediate_key.get(), EVP_sha256()) > 0, "resign wrong KU TSA");
                auto bad_counter = fixtures.signature(fixtures.expired.get());
                attach_counter(bad_counter.get(), fixtures, false, wrong_key_usage.get());
                require(first(pesign::analyze_bytes(attach(image(), bad_counter.get()), options(fixtures))).timestamp != "valid",
                        "legacy TSA lacking signing key usage was accepted");
            }},
            {"parse-only default performs no validation", [&] {
                auto p7 = fixtures.signature();
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()));
                require(first(result).overall == "not_performed", "default parse unexpectedly trusts a signature");
                require(result.signatures.front().signers.front().certificate_chain.status == "not_built",
                        "bytes-only overload unexpectedly constructs an external certificate chain");
            }},
            {"metadata parsing resolves a nonembedded root without verification", [&] {
                auto p7 = fixtures.signature();
                const auto bytes = attach(image(), p7.get());
                const auto opts = metadata_options(fixtures);
                const auto result = pesign::analyze_bytes(bytes, opts);
                require(first(result).overall == "not_performed" && result.verification.overall == "not_performed",
                        "metadata chain construction unexpectedly enables signature validation");
                require(result.signatures.front().certificates.size() == 2,
                        "external root incorrectly merged into the embedded certificate bag");
                complete_metadata_chain(result.signatures.front().signers.front(), fixtures, "metadata parse");
                require(first(result).certificate_chain == "not_checked" && first(result).revocation == "not_checked",
                        "metadata chain construction changes trust or revocation verdicts");
                write(fixtures.directory / "metadata-chain.exe", bytes);
                const auto from_file = pesign::analyze_file(fixtures.directory / "metadata-chain.exe", opts);
                complete_metadata_chain(from_file.signatures.front().signers.front(), fixtures, "metadata file parse");
                require(first(from_file).overall == "not_performed", "file metadata parsing validates a signature");
                const auto root_thumbprint = thumbprint(fixtures.root.get(), EVP_sha1());
                const auto json = pesign::to_json(result);
                const auto text = pesign::to_text(result);
                require(json.find("\"certificateChain\":{\"status\":\"built\",\"certificates\":[") != std::string::npos &&
                            json.find(root_thumbprint) != std::string::npos,
                        "JSON omits the nonembedded root certificate metadata");
                require(text.find("certificateChain.status: built") != std::string::npos &&
                            text.find("certificateChain.certificate[2] (chain metadata):") != std::string::npos &&
                            text.find(root_thumbprint) != std::string::npos,
                        "text omits the nonembedded root certificate metadata");
            }},
            {"expired and wrong-purpose signers still expose metadata chains", [&] {
                for (X509* certificate : {fixtures.expired.get(), fixtures.wrong_purpose.get()}) {
                    auto p7 = fixtures.signature(certificate);
                    const auto result = pesign::analyze_bytes(attach(image(), p7.get()), metadata_options(fixtures));
                    require(first(result).overall == "not_performed", "metadata parse validates an invalid signer");
                    complete_metadata_chain(result.signatures.front().signers.front(), fixtures,
                                            "invalid signer metadata parse");
                }
            }},
            {"metadata chain remains partial when an issuer is absent or forged", [&] {
                auto p7 = fixtures.signature();
                const auto bytes = attach(image(), p7.get());
                auto opts = metadata_options(fixtures);
                opts.ca_file.clear();
                const auto missing = pesign::analyze_bytes(bytes, opts);
                const auto& partial = missing.signatures.front().signers.front().certificate_chain;
                require(partial.status == "partial" && partial.certificates.size() == 2,
                        "missing root does not yield the available partial chain");
                require(partial.certificates.back().subject == "CN=Offline test intermediate",
                        "missing root replaced by fabricated self-signed metadata");
                require(first(missing).overall == "not_performed", "partial metadata chain enables validation");

                auto forged_root = own<X509, X509_free>(X509_dup(fixtures.root.get()), "forged metadata root");
                ssl_check(X509_set_pubkey(forged_root.get(), fixtures.tsa_key.get()) == 1, "forged root public key");
                ssl_check(X509_sign(forged_root.get(), fixtures.tsa_key.get(), EVP_sha256()) > 0, "forged root self-signature");
                opts.ca_file = fixtures.directory / "forged-metadata-root.pem";
                pem(opts.ca_file, forged_root.get());
                const auto forged = pesign::analyze_bytes(bytes, opts);
                const auto& forged_chain = forged.signatures.front().signers.front().certificate_chain;
                require(forged_chain.status == "partial" && forged_chain.certificates.size() == 2,
                        "issuer DN/AKI match without a valid certificate signature completes the metadata chain");
            }},
            {"metadata chain reports an unavailable signer certificate", [&] {
                auto p7 = fixtures.signature();
                auto* certificates = p7->d.sign->cert;
                for (int index = sk_X509_num(certificates) - 1; index >= 0; --index) {
                    if (X509_cmp(sk_X509_value(certificates, index), fixtures.code.get()) == 0)
                        X509_free(sk_X509_delete(certificates, index));
                }
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), metadata_options(fixtures));
                const auto& signer_info = result.signatures.front().signers.front();
                require(signer_info.certificate_index == -1 && signer_info.certificate_chain.status == "unavailable" &&
                            signer_info.certificate_chain.certificates.empty(),
                        "unrelated intermediate is reported as the missing signer's certificate");
                require(first(result).overall == "not_performed", "missing signer metadata enables validation");
            }},
            {"metadata chains read existing AIA issuer cache without verification", [&] {
                constexpr const char* issuer_url = "http://127.0.0.1:1/metadata-intermediate.der";
                auto leaf = certificate(fixtures.signer_key.get(), 22, "Cached issuer code signer",
                    fixtures.intermediate.get(), fixtures.intermediate_key.get(), "codeSigning", false,
                    "20200101000000Z", "20400101000000Z", "", "", issuer_url);
                auto p7 = fixtures.signature(leaf.get(), false, false);
                const auto bytes = attach(image(), p7.get());
                auto opts = metadata_options(fixtures);
                opts.revocation_cache = fixtures.directory / "metadata-aia-cache";
                std::filesystem::create_directory(opts.revocation_cache);
                const auto missing = pesign::analyze_bytes(bytes, opts);
                require(missing.signatures.front().signers.front().certificate_chain.status == "partial" &&
                            missing.signatures.front().signers.front().certificate_chain.certificates.size() == 1,
                        "uncached AIA issuer unexpectedly resolves without online verification");

                const auto identity = std::string("issuer:") + issuer_url;
                const auto cache_file = opts.revocation_cache /
                    (hex(hash(Bytes(identity.begin(), identity.end()))) + ".cer");
                auto poisoned = own<X509, X509_free>(X509_dup(fixtures.intermediate.get()), "poisoned metadata cache issuer");
                ssl_check(X509_set_pubkey(poisoned.get(), fixtures.tsa_key.get()) == 1, "poisoned issuer public key");
                ssl_check(X509_sign(poisoned.get(), fixtures.root_key.get(), EVP_sha256()) > 0, "poisoned issuer signature");
                write(cache_file, der(poisoned.get(), i2d_X509));
                const auto invalid = pesign::analyze_bytes(bytes, opts);
                require(invalid.signatures.front().signers.front().certificate_chain.status == "partial" &&
                            invalid.signatures.front().signers.front().certificate_chain.certificates.size() == 1,
                        "cached issuer DN/AKI match bypasses the child's actual signature");

                write(cache_file, der(fixtures.intermediate.get(), i2d_X509));
                const auto cached = pesign::analyze_bytes(bytes, opts);
                complete_metadata_chain(cached.signatures.front().signers.front(), fixtures, "cached AIA metadata chain");
                require(first(cached).overall == "not_performed" && first(cached).revocation == "not_checked",
                        "metadata issuer cache retrieval enables signature or revocation validation");
            }},
            {"multiple and nested signers have individual metadata chains", [&] {
                auto outer = fixtures.signature();
                const auto content = indirect_data(image_hash(image()));
                signer(outer.get(), fixtures.wrong_purpose.get(), fixtures.signer_key.get(), content_bytes(content));
                auto nested = fixtures.signature(fixtures.expired.get());
                auto* primary = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                unsigned_attribute(primary, "1.3.6.1.4.1.311.2.4.1", der(nested.get(), i2d_PKCS7));
                const auto result = pesign::analyze_bytes(attach(image(), outer.get()), metadata_options(fixtures));
                require(result.signatures.size() == 2 && result.signatures.front().signers.size() == 2,
                        "multiple or nested signer fixture not parsed");
                // SignerInfos is a SET OF: DER ordering may move the original
                // code signer after the wrong-purpose signer during encoding.
                int nested_parent_signer = -1;
                for (std::size_t index = 0; index < result.signatures.front().signers.size(); ++index) {
                    if (result.signatures.front().signers[index].serial == "03") {
                        require(nested_parent_signer < 0, "ambiguous nested parent signer fixture");
                        nested_parent_signer = static_cast<int>(index);
                    }
                }
                require(nested_parent_signer >= 0 && result.signatures[1].parent_signature == 0 &&
                            result.signatures[1].parent_signer == nested_parent_signer &&
                            result.signatures[1].signers.size() == 1 &&
                            result.signatures[1].signers.front().serial == "05",
                        "nested metadata signer provenance missing");
                for (const auto& signature : result.signatures) {
                    for (const auto& signer_info : signature.signers) {
                        complete_metadata_chain(signer_info, fixtures, "individual signer metadata chain");
                        require(signer_info.verification.overall == "not_performed",
                                "individual metadata chain enables validation");
                    }
                }
            }},
            {"verified signatures retain both root metadata and trust verdicts", [&] {
                auto p7 = fixtures.signature();
                const auto result = pesign::analyze_bytes(attach(image(), p7.get()), options(fixtures));
                valid(result, "verified metadata chain");
                complete_metadata_chain(result.signatures.front().signers.front(), fixtures, "verified metadata chain");
                const auto& verified_chain = first(result).chain;
                require(verified_chain.size() == 3 &&
                            verified_chain.back().sha1_thumbprint == thumbprint(fixtures.root.get(), EVP_sha1()),
                        "validated chain loses its actual root certificate");
                const auto root_thumbprint = thumbprint(fixtures.root.get(), EVP_sha1());
                require(pesign::to_json(result).find(root_thumbprint) != std::string::npos &&
                            pesign::to_text(result).find(root_thumbprint) != std::string::npos,
                        "verified reports omit full root certificate metadata");
            }},
            {"multiple certificate records and nested signatures validate independently", [&] {
                auto outer = fixtures.signature();
                auto nested = fixtures.signature();
                auto* primary = sk_PKCS7_SIGNER_INFO_value(outer->d.sign->signer_info, 0);
                unsigned_attribute(primary, "1.3.6.1.4.1.311.2.4.1", der(nested.get(), i2d_PKCS7));
                auto bytes = attach(image(), outer.get());
                const auto first_table_size = bytes.size() - 0x400;
                auto second = fixtures.signature();
                const auto second_only = attach(image(), second.get());
                bytes.insert(bytes.end(), second_only.begin() + 0x400, second_only.end());
                put32(bytes, security(false) + 4, static_cast<std::uint32_t>(first_table_size + second_only.size() - 0x400));
                const auto result = pesign::analyze_bytes(bytes, options(fixtures));
                require(result.certificate_records.size() == 2 && result.signatures.size() == 3,
                        "multiple certificate or nested signature not parsed");
                for (const auto& signature : result.signatures) {
                    require(signature.verification.overall == "valid", "independent signature not verified");
                    require(signature.signers.front().verification.overall == "valid", "independent signer not verified");
                }
                require(result.signatures[1].parent_signature == 0, "nested parent provenance lost");
            }},
            {"offline CRL good, revoked, unknown and stale", [&] {
                auto opts = options(fixtures);
                opts.revocation = pesign::RevocationMode::cache;
                opts.crl_directory = fixtures.directory / "crls";
                std::filesystem::create_directory(opts.crl_directory);
                write(opts.crl_directory / "root.crl", crl(fixtures.root.get(), fixtures.root_key.get()));
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get()));
                auto p7 = fixtures.signature();
                const auto bytes = attach(image(), p7.get());
                const auto good = pesign::analyze_bytes(bytes, opts);
                valid(good, "offline good CRL");
                require(first(good).revocation == "good", "good CRL status " + first(good).revocation);
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get()));
                const auto revoked = pesign::analyze_bytes(bytes, opts);
                require(first(revoked).revocation == "revoked" && first(revoked).overall != "valid", "revoked cert accepted");
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get()));
                write(opts.crl_directory / "root.crl", crl(fixtures.root.get(), fixtures.root_key.get(), fixtures.intermediate.get()));
                const auto revoked_intermediate = pesign::analyze_bytes(bytes, opts);
                require(first(revoked_intermediate).revocation == "revoked" && first(revoked_intermediate).overall != "valid",
                        "revoked intermediate was accepted");
                write(opts.crl_directory / "root.crl", crl(fixtures.root.get(), fixtures.root_key.get()));
                std::filesystem::remove(opts.crl_directory / "issuer.crl");
                const auto unknown = pesign::analyze_bytes(bytes, opts);
                require(first(unknown).revocation == "unknown" && first(unknown).overall != "valid", "missing CRL accepted");
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), nullptr,
                                                           "20200101000000Z", "20210101000000Z"));
                const auto stale = pesign::analyze_bytes(bytes, opts);
                require(first(stale).revocation == "unknown" && first(stale).overall != "valid", "stale CRL accepted");
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.root_key.get()));
                const auto forged = pesign::analyze_bytes(bytes, opts);
                require(first(forged).revocation == "unknown" && first(forged).overall != "valid", "forged CRL accepted");
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                    nullptr, "20200101000000Z", "20400101000000Z", "http://127.0.0.1:1/offline.crl"));
                const auto scoped = pesign::analyze_bytes(bytes, opts);
                valid(scoped, "direct issuingDistributionPoint CRL");
                require(first(scoped).revocation == "good", "matching direct scoped CRL not accepted");
                write(opts.crl_directory / "issuer.crl", crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                    nullptr, "20200101000000Z", "20400101000000Z", "http://127.0.0.1:1/wrong-scope.crl"));
                const auto wrong_scope = pesign::analyze_bytes(bytes, opts);
                require(first(wrong_scope).revocation == "unknown" && first(wrong_scope).overall != "valid",
                        "CRL for another distribution point was accepted");
            }},
            {"catalog membership is authenticated and required", [&] {
                auto opts = options(fixtures);
                opts.catalog = fixtures.directory / "member.cat";
                const auto unsigned_image = image();
                auto p7 = catalog(fixtures, image_hash(unsigned_image));
                write(opts.catalog, der(p7.get(), i2d_PKCS7));
                const auto member = pesign::analyze_bytes(unsigned_image, opts);
                valid(member, "catalog member");
                require(member.signature_type == "cataloged", "catalog source not recorded");
                auto other = image_hash(unsigned_image);
                other.front() ^= 1;
                auto wrong = catalog(fixtures, other);
                write(opts.catalog, der(wrong.get(), i2d_PKCS7));
                const auto missing = pesign::analyze_bytes(unsigned_image, opts);
                require(missing.verification.overall != "valid", "catalog without image membership was accepted");
                auto* primary = sk_PKCS7_SIGNER_INFO_value(p7->d.sign->signer_info, 0);
                primary->enc_digest->data[0] ^= 1;
                write(opts.catalog, der(p7.get(), i2d_PKCS7));
                const auto bad_signature = pesign::analyze_bytes(unsigned_image, opts);
                require(bad_signature.verification.overall != "valid", "tampered catalog signature accepted");
                // An image hash in listIdentifier is catalog metadata, not a member.
                const auto genuine_member = ctl(other);
                const auto fields = content_bytes(genuine_member);
                const auto usage = tlv(0x30, oid("1.3.6.1.4.1.311.12.1.1"));
                const auto decoy_ctl = tlv(0x30, concat(concat(usage, tlv(0x04, image_hash(unsigned_image))),
                    Bytes(fields.begin() + static_cast<std::ptrdiff_t>(usage.size()), fields.end())));
                auto decoy = signed_data(decoy_ctl, "1.3.6.1.4.1.311.10.1");
                signer(decoy.get(), fixtures.code.get(), fixtures.signer_key.get(), content_bytes(decoy_ctl),
                       "1.3.6.1.4.1.311.10.1");
                ssl_check(PKCS7_add_certificate(decoy.get(), fixtures.intermediate.get()) == 1, "decoy intermediate");
                write(opts.catalog, der(decoy.get(), i2d_PKCS7));
                require(pesign::analyze_bytes(unsigned_image, opts).verification.overall != "valid",
                        "catalog metadata was confused with membership");
            }},
            {"compatible direct delta CRLs require their complete base", [&] {
                auto opts = options(fixtures);
                opts.revocation = pesign::RevocationMode::cache;
                opts.crl_directory = fixtures.directory / "delta-crls";
                std::filesystem::create_directory(opts.crl_directory);
                write(opts.crl_directory / "root.crl", crl(fixtures.root.get(), fixtures.root_key.get()));
                const auto base_file = opts.crl_directory / "base.crl";
                const auto delta_file = opts.crl_directory / "delta.crl";
                const auto complete_base = crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                    nullptr, "20200101000000Z", "20400101000000Z", "", 10);
                write(base_file, complete_base);
                write(delta_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get(),
                    "20260101000000Z", "20400101000000Z", "", 11, 10, CRL_REASON_KEY_COMPROMISE));
                auto p7 = fixtures.signature();
                const auto bytes = attach(image(), p7.get());
                const auto revoked = pesign::analyze_bytes(bytes, opts);
                require(first(revoked).revocation == "revoked" && first(revoked).overall != "valid",
                        "compatible delta revocation was ignored");
                write(delta_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), nullptr,
                    "20260101000000Z", "20400101000000Z", "", 11, 10));
                valid(pesign::analyze_bytes(bytes, opts), "complete base and good delta");
                std::filesystem::remove(base_file);
                const auto no_base = pesign::analyze_bytes(bytes, opts);
                require(first(no_base).revocation == "unknown" && first(no_base).overall != "valid",
                        "standalone delta CRL was accepted");
                write(base_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                    nullptr, "20200101000000Z", "20400101000000Z", "", 9));
                const auto wrong_base = pesign::analyze_bytes(bytes, opts);
                require(first(wrong_base).revocation == "unknown" && first(wrong_base).overall != "valid",
                        "delta accepted an incompatible base CRL number");
                write(base_file, complete_base);
                write(delta_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get(),
                    "20260101000000Z", "20400101000000Z", "http://127.0.0.1:1/wrong-scope.crl", 11, 10));
                const auto wrong_scope = pesign::analyze_bytes(bytes, opts);
                valid(wrong_scope, "complete base with unrelated scoped delta");
                require(first(wrong_scope).revocation == "good",
                        "delta for another distribution point incorrectly revoked this certificate");
                write(base_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get(),
                    "20200101000000Z", "20400101000000Z", "", 10, -1, CRL_REASON_CERTIFICATE_HOLD));
                write(delta_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get(),
                    "20260101000000Z", "20400101000000Z", "", 11, 10, CRL_REASON_REMOVE_FROM_CRL));
                valid(pesign::analyze_bytes(bytes, opts), "delta removeFromCRL releases certificateHold");
                write(base_file, crl(fixtures.intermediate.get(), fixtures.intermediate_key.get(), fixtures.code.get(),
                    "20200101000000Z", "20400101000000Z", "", 10, -1, CRL_REASON_KEY_COMPROMISE));
                const auto unsafe_release = pesign::analyze_bytes(bytes, opts);
                require(first(unsafe_release).revocation == "unknown" && first(unsafe_release).overall != "valid",
                        "removeFromCRL erased a permanent key-compromise revocation");
            }},
            {"offline OCSP good, revoked, unknown and signature rejection", [&] {
                auto opts = options(fixtures);
                opts.verification_time = std::time(nullptr); // Matches OpenSSL's generated producedAt.
                opts.revocation = pesign::RevocationMode::cache;
                opts.revocation_cache = fixtures.directory / "ocsp-cache";
                std::filesystem::create_directory(opts.revocation_cache);
                const auto root_response = ocsp_cache_path(opts.revocation_cache, fixtures.intermediate.get(), fixtures.root.get());
                const auto leaf_response = ocsp_cache_path(opts.revocation_cache, fixtures.code.get(), fixtures.intermediate.get());
                write(root_response, ocsp(fixtures.intermediate.get(), fixtures.root.get(), fixtures.root_key.get()));
                write(leaf_response, ocsp(fixtures.code.get(), fixtures.intermediate.get(), fixtures.intermediate_key.get()));
                auto p7 = fixtures.signature();
                const auto bytes = attach(image(), p7.get());
                const auto good = pesign::analyze_bytes(bytes, opts);
                valid(good, "offline OCSP good");
                require(first(good).revocation == "good", "OCSP good status " + first(good).revocation);
                write(leaf_response, ocsp(fixtures.code.get(), fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                                          V_OCSP_CERTSTATUS_REVOKED));
                const auto revoked = pesign::analyze_bytes(bytes, opts);
                require(first(revoked).revocation == "revoked" && first(revoked).overall != "valid", "OCSP revoked accepted");
                write(leaf_response, ocsp(fixtures.code.get(), fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                                          V_OCSP_CERTSTATUS_UNKNOWN));
                const auto unknown = pesign::analyze_bytes(bytes, opts);
                require(first(unknown).revocation == "unknown" && first(unknown).overall != "valid", "OCSP unknown accepted");
                // Alter only the response signature, retaining its valid ASN.1 shape.
                write(leaf_response, ocsp(fixtures.code.get(), fixtures.intermediate.get(), fixtures.intermediate_key.get(),
                                          V_OCSP_CERTSTATUS_GOOD, true));
                const auto forged = pesign::analyze_bytes(bytes, opts);
                require(first(forged).revocation == "unknown" && first(forged).overall != "valid", "forged OCSP accepted");
            }},
            {"Microsoft catalog v1 and mixed SHA1 SHA256 v2 members", [&] {
                auto opts = options(fixtures);
                opts.catalog = fixtures.directory / "microsoft.cat";
                const auto sha1_member = image_hash(image(), false, EVP_sha1());
                const auto sha256_member = image_hash(image());
                auto v1 = signed_catalog(fixtures, microsoft_ctl({sha1_member}, false));
                write(opts.catalog, der(v1.get(), i2d_PKCS7));
                valid(pesign::analyze_bytes(image(), opts), "Microsoft v1 catalog");
                auto v2 = signed_catalog(fixtures, microsoft_ctl({Bytes(20, 0x11), sha256_member}, true));
                write(opts.catalog, der(v2.get(), i2d_PKCS7));
                valid(pesign::analyze_bytes(image(), opts), "Microsoft v2 mixed member catalog");
                auto v2_sha1 = signed_catalog(fixtures, microsoft_ctl({sha1_member, Bytes(32, 0x22)}, true));
                write(opts.catalog, der(v2_sha1.get(), i2d_PKCS7));
                valid(pesign::analyze_bytes(image(), opts), "Microsoft v2 SHA1 member catalog");
                const auto attribute = tlv(0x30, concat(oid("1.2.3.4.777"), tlv(0x31, tlv(0x04, sha256_member))));
                auto decoy = signed_catalog(fixtures, microsoft_ctl({Bytes(32, 0x44)}, true, attribute));
                write(opts.catalog, der(decoy.get(), i2d_PKCS7));
                const auto not_member = pesign::analyze_bytes(image(), opts);
                require(not_member.verification.overall != "valid", "catalog attribute OCTET STRING satisfied membership");
            }},
            {"catalog directory discovery and embedded-only control", [&] {
                const auto directory = fixtures.directory / "catalogs";
                std::filesystem::create_directory(directory);
                const auto image_file = fixtures.directory / "unsigned.exe";
                write(image_file, image());
                auto p7 = catalog(fixtures, image_hash(image()));
                write(directory / "matching.cat", der(p7.get(), i2d_PKCS7));
                auto opts = options(fixtures);
                opts.catalog_directories.push_back(directory);
                const auto result = pesign::analyze_file(image_file, opts);
                valid(result, "catalog discovery");
                require(!result.catalog_file.empty(), "discovered catalog path not reported");
                opts.embedded_only = true;
                bool conflict_rejected = false;
                try {
                    static_cast<void>(pesign::analyze_file(image_file, opts));
                } catch (const pesign::ParseError&) {
                    conflict_rejected = true;
                }
                require(conflict_rejected, "embedded-only and explicit catalog search options must conflict");
                opts.catalog_directories.clear();
                const auto only = pesign::analyze_file(image_file, opts);
                require(only.signatures.empty() && only.verification.overall != "valid", "embedded-only inspected catalog");
            }},
        };
        std::size_t failures = 0;
        for (const auto& test : tests) {
            try {
                test.second();
                std::cout << "PASS " << test.first << '\n';
            } catch (const std::exception& error) {
                ++failures;
                std::cerr << "FAIL " << test.first << ": " << error.what() << '\n';
            }
        }
        if (failures) return 1;
        std::cout << tests.size() << " verification scenarios passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "verification fixture setup: " << error.what() << '\n';
        return 1;
    }
}

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) { return run(argc, argv); }
#else
int main(int argc, char** argv) { return run(argc, argv); }
#endif
