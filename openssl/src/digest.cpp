#include "verification_internal.h"

#include <openssl/evp.h>
#include <openssl/objects.h>

#include <algorithm>
#include <memory>
#include <utility>

namespace pesign {
namespace {
class Layout {
public:
    explicit Layout(const std::vector<std::uint8_t>& bytes) : bytes_(bytes) {}
    void require(std::size_t offset, std::size_t size) const {
        if (offset > bytes_.size() || size > bytes_.size() - offset)
            throw ParseError("Out-of-bounds Authenticode hashing range");
    }
    std::uint16_t u16(std::size_t offset) const {
        require(offset, 2);
        return static_cast<std::uint16_t>(bytes_[offset] | (bytes_[offset + 1] << 8));
    }
    std::uint32_t u32(std::size_t offset) const {
        require(offset, 4);
        return std::uint32_t(bytes_[offset]) | (std::uint32_t(bytes_[offset + 1]) << 8) |
            (std::uint32_t(bytes_[offset + 2]) << 16) | (std::uint32_t(bytes_[offset + 3]) << 24);
    }
private:
    const std::vector<std::uint8_t>& bytes_;
};
} // namespace

std::vector<std::uint8_t> authenticode_digest(
    const std::vector<std::uint8_t>& bytes, const std::string& algorithm_oid) {
    const Layout layout(bytes);
    layout.require(0, 64);
    if (layout.u16(0) != 0x5a4d) throw ParseError("Missing DOS header while hashing");
    const std::size_t pe = layout.u32(60);
    layout.require(pe, 24);
    if (pe < 64 || layout.u32(pe) != 0x4550) throw ParseError("Missing PE header while hashing");
    const std::size_t optional = pe + 24;
    const std::size_t optional_size = layout.u16(pe + 20);
    layout.require(optional, optional_size);
    if (optional_size < 2) throw ParseError("Missing optional header while hashing");
    const auto magic = layout.u16(optional);
    const std::size_t directories = magic == 0x10b ? 96 : magic == 0x20b ? 112 : 0;
    if (!directories || optional_size < directories) throw ParseError("Invalid optional header while hashing");
    const std::size_t count = layout.u32(optional + directories - 4);
    if (count > (optional_size - directories) / 8) throw ParseError("Invalid directory count while hashing");
    const std::size_t checksum = optional + 64;
    const std::size_t security = optional + directories + 32;
    const bool has_security = count > 4;
    const std::size_t headers = layout.u32(optional + 60);
    const std::size_t section_count = layout.u16(pe + 6);
    const std::size_t section_table = optional + optional_size;
    layout.require(section_table, section_count * 40);
    layout.require(0, headers);
    if (headers < section_table + section_count * 40 || headers < checksum + 4 ||
        (has_security && headers < security + 8))
        throw ParseError("SizeOfHeaders does not cover the PE headers");
    std::size_t cert_offset = 0, cert_size = 0;
    if (has_security) {
        cert_offset = layout.u32(security);
        cert_size = layout.u32(security + 4);
        if ((cert_offset == 0) != (cert_size == 0)) throw ParseError("Invalid certificate table while hashing");
        if (cert_size) {
            layout.require(cert_offset, cert_size);
            if (cert_offset < headers || (cert_offset & 7)) throw ParseError("Invalid certificate offset while hashing");
        }
    }
    std::vector<std::pair<std::size_t, std::size_t>> sections;
    for (std::size_t i = 0; i < section_count; ++i) {
        const std::size_t size = layout.u32(section_table + i * 40 + 16);
        const std::size_t offset = layout.u32(section_table + i * 40 + 20);
        if (!size) continue;
        layout.require(offset, size);
        if (offset < headers || (cert_size && offset < cert_offset + cert_size && offset + size > cert_offset))
            throw ParseError("Section overlaps headers or certificate table while hashing");
        sections.emplace_back(offset, size);
    }
    std::sort(sections.begin(), sections.end());
    std::size_t last_end = headers;
    for (const auto& section : sections) {
        if (section.first < last_end) throw ParseError("Overlapping PE sections cannot be hashed safely");
        last_end = section.first + section.second;
    }
    // Match the original Windows implementation: hash in file order, including
    // raw-section padding and gaps. Real PE files can have unaligned raw sizes;
    // the documented SUM_OF_BYTES_HASHED recipe would duplicate bytes there.
    if (cert_size && cert_offset < last_end)
        throw ParseError("Certificate table precedes the end of the PE sections");
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> object(
        OBJ_txt2obj(algorithm_oid.c_str(), 0), ASN1_OBJECT_free);
    const EVP_MD* algorithm = object ? EVP_get_digestbyobj(object.get()) : nullptr;
    const int digest_size = algorithm ? EVP_MD_get_size(algorithm) : 0;
    if (digest_size <= 0 || digest_size > EVP_MAX_MD_SIZE ||
        (algorithm && (EVP_MD_get_flags(algorithm) & EVP_MD_FLAG_XOF)))
        throw ParseError("Unsupported image digest algorithm: " + algorithm_oid);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context || EVP_DigestInit_ex(context.get(), algorithm, nullptr) != 1)
        throw ParseError("Cannot initialize Authenticode digest");
    const auto hash = [&](std::size_t start, std::size_t end) {
        if (end < start) throw ParseError("Invalid Authenticode digest interval");
        layout.require(start, end - start);
        if (end > start && EVP_DigestUpdate(context.get(), bytes.data() + start, end - start) != 1)
            throw ParseError("Cannot update Authenticode digest");
    };
    hash(0, checksum);
    if (has_security) {
        hash(checksum + 4, security);
        hash(security + 8, cert_size ? cert_offset : bytes.size());
    } else hash(checksum + 4, bytes.size());
    if (cert_size) {
        hash(cert_offset + cert_size, bytes.size());
    }
    std::vector<std::uint8_t> result(static_cast<std::size_t>(digest_size));
    unsigned size = 0;
    if (EVP_DigestFinal_ex(context.get(), result.data(), &size) != 1)
        throw ParseError("Cannot finalize Authenticode digest");
    result.resize(size);
    return result;
}
} // namespace pesign
