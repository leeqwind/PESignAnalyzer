#include "pesign/analyzer.h"

#include <iomanip>
#include <sstream>

namespace pesign {
namespace {
std::size_t utf8_sequence_size(const std::string& value, std::size_t offset) {
    const auto lead = static_cast<unsigned char>(value[offset]);
    const std::size_t length = lead >= 0xc2 && lead <= 0xdf ? 2 :
        lead >= 0xe0 && lead <= 0xef ? 3 : lead >= 0xf0 && lead <= 0xf4 ? 4 : 0;
    if (!length || length > value.size() - offset) return 0;
    for (std::size_t index = 1; index < length; ++index) {
        const auto byte = static_cast<unsigned char>(value[offset + index]);
        if (byte < 0x80 || byte > 0xbf) return 0;
    }
    const auto second = static_cast<unsigned char>(value[offset + 1]);
    if ((lead == 0xe0 && second < 0xa0) || // Overlong encoding.
        (lead == 0xed && second > 0x9f) || // UTF-16 surrogate.
        (lead == 0xf0 && second < 0x90) || // Overlong encoding.
        (lead == 0xf4 && second > 0x8f)) return 0; // Beyond U+10FFFF.
    return length;
}

std::string quote(const std::string& value) {
    std::ostringstream out;
    out << '"';
    for (std::size_t index = 0; index < value.size(); ++index) {
        const auto c = static_cast<unsigned char>(value[index]);
        if (c >= 0x80) {
            const auto length = utf8_sequence_size(value, index);
            if (length) {
                out.write(value.data() + index, static_cast<std::streamsize>(length));
                index += length - 1;
            } else out << "\\ufffd";
            continue;
        }
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) out << "\\u" << std::hex << std::setw(4)
                              << std::setfill('0') << static_cast<unsigned>(c);
            else out << c;
        }
    }
    out << '"';
    return out.str();
}

template <typename T, typename F>
std::string array(const std::vector<T>& values, F encode) {
    std::string out = "[";
    bool first = true;
    for (const auto& value : values) {
        if (!first) out += ',';
        first = false;
        out += encode(value);
    }
    return out + "]";
}

std::string algorithm(const Algorithm& a) {
    return "{\"oid\":" + quote(a.oid) + ",\"name\":" + quote(a.name) + "}";
}

std::string certificate(const Certificate& c) {
    return "{\"version\":" + std::to_string(c.version)
        + ",\"subject\":" + quote(c.subject) + ",\"issuer\":" + quote(c.issuer)
        + ",\"serial\":" + quote(c.serial)
        + ",\"sha1Thumbprint\":" + quote(c.sha1_thumbprint)
        + ",\"sha256Thumbprint\":" + quote(c.sha256_thumbprint)
        + ",\"notBefore\":" + quote(c.not_before)
        + ",\"notAfter\":" + quote(c.not_after)
        + ",\"signatureAlgorithm\":" + algorithm(c.signature_algorithm)
        + ",\"crlDistributionPoints\":" + array(c.crl_distribution_points, quote) + "}";
}

std::string timestamp(const Timestamp& t) {
    return "{\"type\":" + quote(t.type) + ",\"time\":" + quote(t.time)
        + ",\"digestAlgorithm\":" + algorithm(t.digest_algorithm)
        + ",\"messageImprint\":" + quote(t.message_imprint)
        + ",\"signerSubject\":" + quote(t.signer_subject)
        + ",\"certificates\":" + array(t.certificates, certificate) + "}";
}

std::string verification(const Verification& v) {
    return "{\"contentDigest\":" + quote(v.content_digest)
        + ",\"cmsSignature\":" + quote(v.cms_signature)
        + ",\"certificateChain\":" + quote(v.certificate_chain)
        + ",\"timestamp\":" + quote(v.timestamp)
        + ",\"revocation\":" + quote(v.revocation)
        + ",\"overall\":" + quote(v.overall)
        + ",\"errorCode\":" + std::to_string(v.error_code)
        + ",\"verificationTime\":" + quote(v.verification_time)
        + ",\"chain\":" + array(v.chain, certificate)
        + ",\"details\":" + array(v.details, quote) + "}";
}

std::string certificate_chain(const CertificateChain& chain) {
    return "{\"status\":" + quote(chain.status)
        + ",\"certificates\":" + array(chain.certificates, certificate)
        + ",\"details\":" + array(chain.details, quote) + "}";
}

std::string signer(const Signer& s) {
    return "{\"version\":" + std::to_string(s.version)
        + ",\"digestAlgorithm\":" + algorithm(s.digest_algorithm)
        + ",\"signatureAlgorithm\":" + algorithm(s.signature_algorithm)
        + ",\"issuer\":" + quote(s.issuer) + ",\"serial\":" + quote(s.serial)
        + ",\"signingTime\":" + quote(s.signing_time)
        + ",\"certificateIndex\":" + std::to_string(s.certificate_index)
        + ",\"timestamps\":" + array(s.timestamps, timestamp)
        + ",\"certificateChain\":" + certificate_chain(s.certificate_chain)
        + ",\"verification\":" + verification(s.verification) + "}";
}

std::string signature(const Signature& s) {
    return "{\"certificateRecord\":" + std::to_string(s.certificate_record)
        + ",\"parentSignature\":" + std::to_string(s.parent_signature)
        + ",\"parentSigner\":" + std::to_string(s.parent_signer)
        + ",\"version\":" + std::to_string(s.version)
        + ",\"contentType\":" + quote(s.content_type)
        + ",\"digestAlgorithm\":" + algorithm(s.digest_algorithm)
        + ",\"embeddedDigest\":" + quote(s.embedded_digest)
        + ",\"certificates\":" + array(s.certificates, certificate)
        + ",\"signers\":" + array(s.signers, signer)
        + ",\"verification\":" + verification(s.verification) + "}";
}

std::string record(const CertificateRecord& r) {
    return "{\"offset\":" + std::to_string(r.offset)
        + ",\"length\":" + std::to_string(r.length)
        + ",\"revision\":" + std::to_string(r.revision)
        + ",\"type\":" + std::to_string(r.type) + "}";
}

void certificate_text(std::ostringstream& out, const Certificate& c, const char* indent) {
    out << indent << "subject: " << c.subject << '\n'
        << indent << "issuer: " << c.issuer << '\n'
        << indent << "version: " << c.version << '\n'
        << indent << "serial: " << c.serial << '\n'
        << indent << "sha1Thumbprint: " << c.sha1_thumbprint << '\n'
        << indent << "sha256Thumbprint: " << c.sha256_thumbprint << '\n'
        << indent << "notBefore: " << c.not_before << '\n'
        << indent << "notAfter: " << c.not_after << '\n'
        << indent << "signatureAlgorithm: " << c.signature_algorithm.name << '\n';
    for (const auto& uri : c.crl_distribution_points)
        out << indent << "crlDistributionPoint: " << uri << '\n';
}
} // namespace

std::string to_json(const Analysis& a) {
    return "{\"schemaVersion\":2,\"toolVersion\":" + quote(version)
        + ",\"file\":" + quote(a.file) + ",\"peFormat\":" + quote(a.pe_format)
        + ",\"machine\":" + std::to_string(a.machine)
        + ",\"signatureType\":" + quote(a.signatures.empty() ? "none" :
            a.signature_type == "cataloged" ? "cataloged" : "embedded")
        + ",\"catalogFile\":" + quote(a.catalog_file)
        + ",\"verification\":" + quote(a.verification.overall)
        + ",\"verificationResult\":" + verification(a.verification)
        + ",\"parseStatus\":" + quote(a.errors.empty() ? "ok" : "partial")
        + ",\"certificateTableOffset\":" + std::to_string(a.certificate_table_offset)
        + ",\"certificateTableSize\":" + std::to_string(a.certificate_table_size)
        + ",\"certificateRecords\":" + array(a.certificate_records, record)
        + ",\"signatures\":" + array(a.signatures, signature)
        + ",\"warnings\":" + array(a.warnings, quote)
        + ",\"errors\":" + array(a.errors, quote) + "}";
}

std::string to_text(const Analysis& a) {
    std::ostringstream out;
    out << "file: " << a.file << "\npeFormat: " << a.pe_format
        << "\nmachine: 0x" << std::hex << a.machine << std::dec
        << "\nsignatureType: " << (a.signatures.empty() ? "none" :
            a.signature_type == "cataloged" ? "cataloged" : "embedded")
        << "\ncatalogFile: " << a.catalog_file
        << "\nverification: " << a.verification.overall << "\nparseStatus: "
        << (a.errors.empty() ? "ok" : "partial") << '\n';
    for (std::size_t i = 0; i < a.signatures.size(); ++i) {
        const auto& s = a.signatures[i];
        out << "\n[Signature " << i << "] record=" << s.certificate_record
            << " parent=" << s.parent_signature << " parentSigner=" << s.parent_signer
            << "\ncontentType: " << s.content_type
            << "\nversion: " << s.version << '\n';
        if (s.content_type != "1.3.6.1.4.1.311.10.1") {
            out << "imageDigestAlgorithm: " << s.digest_algorithm.name
                << " (" << s.digest_algorithm.oid << ")"
                << "\nembeddedDigest: " << s.embedded_digest << '\n';
        }
        for (std::size_t j = 0; j < s.signers.size(); ++j) {
            const auto& signer = s.signers[j];
            out << "  signer[" << j << "]: issuer=" << signer.issuer
                << " serial=" << signer.serial
                << " certificateIndex=" << signer.certificate_index
                << "\n    digestAlgorithm: " << signer.digest_algorithm.name
                << " (" << signer.digest_algorithm.oid << ")"
                << "\n    signatureAlgorithm: " << signer.signature_algorithm.name
                << " (" << signer.signature_algorithm.oid << ")"
                << "\n    signingTime (claimed): " << signer.signing_time << '\n';
            if (signer.verification.overall != "not_performed") {
                const auto& v = signer.verification;
                out << "    verification.contentDigest: " << v.content_digest
                    << "\n    verification.cmsSignature: " << v.cms_signature
                    << "\n    verification.certificateChain: " << v.certificate_chain
                    << "\n    verification.timestamp: " << v.timestamp
                    << "\n    verification.revocation: " << v.revocation
                    << "\n    verification.overall: " << v.overall
                    << "\n    verification.time: " << v.verification_time << '\n';
                for (const auto& certificate : v.chain)
                    out << "    chain: " << certificate.subject << '\n';
                for (const auto& detail : v.details) out << "    verification.detail: " << detail << '\n';
            }
            if (signer.certificate_chain.status != "not_built") {
                const auto& chain = signer.certificate_chain;
                out << "    certificateChain.status: " << chain.status << '\n';
                for (std::size_t k = 0; k < chain.certificates.size(); ++k) {
                    out << "    certificateChain.certificate[" << k << "] (chain metadata):\n";
                    certificate_text(out, chain.certificates[k], "      ");
                }
                for (const auto& detail : chain.details) out << "    certificateChain.detail: " << detail << '\n';
            }
            for (const auto& t : signer.timestamps)
                out << "    timestamp (" << t.type << "): " << t.time
                    << " signer=" << t.signer_subject << '\n';
        }
        for (std::size_t j = 0; j < s.certificates.size(); ++j) {
            out << "  certificate[" << j << "] (embedded, unverified):\n";
            certificate_text(out, s.certificates[j], "    ");
        }
    }
    for (const auto& warning : a.warnings) out << "warning: " << warning << '\n';
    for (const auto& error : a.errors) out << "error: " << error << '\n';
    return out.str();
}
} // namespace pesign
