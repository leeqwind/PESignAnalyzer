#include "verification_internal.h"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <limits>
#include <sstream>
#include <utility>

namespace pesign {
namespace {

constexpr std::uint64_t max_file_size = 1024ULL * 1024ULL * 1024ULL;
constexpr std::size_t max_certificate_records = 4096;

class Reader {
public:
    explicit Reader(const std::vector<std::uint8_t>& bytes) : bytes_(bytes) {}

    void require(std::size_t offset, std::size_t length, const char* what) const {
        if (offset > bytes_.size() || length > bytes_.size() - offset) {
            throw ParseError(std::string("Truncated or out-of-bounds ") + what);
        }
    }

    std::uint16_t u16(std::size_t offset) const {
        require(offset, 2, "16-bit field");
        return static_cast<std::uint16_t>(bytes_[offset]) |
               static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes_[offset + 1]) << 8);
    }

    std::uint32_t u32(std::size_t offset) const {
        require(offset, 4, "32-bit field");
        return static_cast<std::uint32_t>(bytes_[offset]) |
               (static_cast<std::uint32_t>(bytes_[offset + 1]) << 8) |
               (static_cast<std::uint32_t>(bytes_[offset + 2]) << 16) |
               (static_cast<std::uint32_t>(bytes_[offset + 3]) << 24);
    }

private:
    const std::vector<std::uint8_t>& bytes_;
};

std::string hex16(std::uint16_t value) {
    std::ostringstream out;
    out << "0x" << std::hex << std::setfill('0') << std::setw(4) << value;
    return out.str();
}

std::string record_label(std::size_t index) {
    return "Certificate record " + std::to_string(index);
}

} // namespace

Analysis detail::parse_pe_metadata(const std::vector<std::uint8_t>& bytes,
                                  const Options* chain_options) {
    const Reader reader(bytes);
    reader.require(0, 64, "DOS header");
    if (reader.u16(0) != 0x5a4d) {
        throw ParseError("Missing MZ DOS signature");
    }

    const std::size_t pe_offset = reader.u32(0x3c);
    if (pe_offset < 64) {
        throw ParseError("PE header overlaps the DOS header");
    }
    reader.require(pe_offset, 24, "PE signature and COFF header");
    if (reader.u32(pe_offset) != 0x00004550) {
        throw ParseError("Missing PE signature");
    }

    Analysis result;
    result.machine = reader.u16(pe_offset + 4);
    const std::size_t section_count = reader.u16(pe_offset + 6);
    const std::size_t optional_size = reader.u16(pe_offset + 20);
    const std::size_t optional_offset = pe_offset + 24;
    reader.require(optional_offset, optional_size, "optional header");
    if (optional_size < 2) {
        throw ParseError("Missing PE optional-header magic");
    }

    std::size_t directory_offset = 0;
    switch (reader.u16(optional_offset)) {
    case 0x010b:
        result.pe_format = "PE32";
        directory_offset = 96;
        break;
    case 0x020b:
        result.pe_format = "PE32+";
        directory_offset = 112;
        break;
    default:
        throw ParseError("Unsupported PE optional-header magic");
    }
    if (optional_size < directory_offset) {
        throw ParseError("Truncated PE optional-header fields");
    }

    const std::size_t directory_count = reader.u32(optional_offset + directory_offset - 4);
    // Division avoids overflowing for an attacker-controlled directory count.
    if (directory_count > (optional_size - directory_offset) / 8) {
        throw ParseError("Data-directory count exceeds the optional-header size");
    }

    const std::size_t sections_offset = optional_offset + optional_size;
    reader.require(sections_offset, section_count * 40, "section headers");
    const std::size_t headers_end = sections_offset + section_count * 40;
    std::vector<std::pair<std::size_t, std::size_t>> raw_sections;
    raw_sections.reserve(section_count);
    for (std::size_t index = 0; index < section_count; ++index) {
        const std::size_t section_offset = sections_offset + index * 40;
        const std::size_t raw_size = reader.u32(section_offset + 16);
        const std::size_t raw_offset = reader.u32(section_offset + 20);
        if (raw_size == 0) {
            continue; // Uninitialized sections have no bytes in the file.
        }
        reader.require(raw_offset, raw_size, "section raw data");
        if (raw_offset < headers_end) {
            throw ParseError("Section raw data overlaps PE headers");
        }
        raw_sections.emplace_back(raw_offset, raw_offset + raw_size);
    }

    // A short directory array is legal, and has no embedded signature entry.
    if (directory_count <= 4) {
        return result;
    }

    const std::size_t security_directory = optional_offset + directory_offset + 4 * 8;
    const std::size_t table_offset = reader.u32(security_directory);
    const std::size_t table_size = reader.u32(security_directory + 4);
    result.certificate_table_offset = table_offset;
    result.certificate_table_size = static_cast<std::uint32_t>(table_size);
    if (table_offset == 0 && table_size == 0) {
        return result;
    }
    if (table_offset == 0 || table_size == 0) {
        throw ParseError("Certificate-table offset and size must both be nonzero");
    }
    if ((table_offset & 7U) != 0) {
        throw ParseError("Certificate table is not aligned to 8 bytes");
    }
    // Unlike other directories, the security-directory address is a file offset.
    reader.require(table_offset, table_size, "certificate table");
    const std::size_t table_end = table_offset + table_size;
    if (table_offset < headers_end) {
        throw ParseError("Certificate table overlaps PE headers");
    }
    for (const auto& section : raw_sections) {
        if (table_offset < section.second && table_end > section.first) {
            throw ParseError("Certificate table overlaps section raw data");
        }
    }

    std::size_t cursor = table_offset;
    while (cursor < table_end) {
        if (result.certificate_records.size() >= max_certificate_records) {
            throw ParseError("Certificate table exceeds the 4096-record safety limit");
        }
        if (table_end - cursor < 8) {
            throw ParseError("Truncated WIN_CERTIFICATE header");
        }
        const std::size_t length = reader.u32(cursor);
        if (length < 8) {
            throw ParseError("WIN_CERTIFICATE length is smaller than its header");
        }
        if (length > table_end - cursor) {
            throw ParseError("WIN_CERTIFICATE extends beyond the certificate table");
        }
        // Round using the remaining length, without length + 7 overflow.
        const std::size_t padding = (8 - (length & 7U)) & 7U;
        if (padding > table_end - cursor - length) {
            throw ParseError("WIN_CERTIFICATE alignment padding exceeds the certificate table");
        }
        if (!std::all_of(bytes.begin() + static_cast<std::ptrdiff_t>(cursor + length),
                         bytes.begin() + static_cast<std::ptrdiff_t>(cursor + length + padding),
                         [](std::uint8_t byte) { return byte == 0; })) {
            throw ParseError("WIN_CERTIFICATE alignment padding is not zero");
        }

        CertificateRecord record;
        record.offset = cursor;
        record.length = static_cast<std::uint32_t>(length);
        record.revision = reader.u16(cursor + 4);
        record.type = reader.u16(cursor + 6);
        const std::size_t index = result.certificate_records.size();
        result.certificate_records.push_back(record);
        if (record.revision != 0x0100 && record.revision != 0x0200) {
            result.warnings.push_back(record_label(index) + " has unknown revision " +
                                      hex16(record.revision));
        }
        if (record.type == 0x0002) {
            detail::parse_pkcs7(bytes.data() + cursor + 8, length - 8, index, result, chain_options);
        } else {
            result.warnings.push_back(record_label(index) + " has unsupported type " +
                                      hex16(record.type) + "; payload was not parsed");
        }
        cursor += length + padding;
    }
    return result;
}

Analysis analyze_bytes(const std::vector<std::uint8_t>& bytes) {
    return detail::parse_pe_metadata(bytes, nullptr);
}

namespace detail {
std::vector<std::uint8_t> read_file(const std::filesystem::path& file, std::size_t maximum_bytes) {
    // The filesystem path overload preserves native Unicode paths on Windows.
    std::ifstream input(file, std::ios::binary | std::ios::ate);
    if (!input) {
        throw ParseError("Cannot open input file");
    }
    const std::streamoff file_size = input.tellg();
    if (file_size < 0) {
        throw ParseError("Cannot determine input-file size");
    }
    const auto size = static_cast<std::uint64_t>(file_size);
    if (size > max_file_size || size > maximum_bytes || size > std::numeric_limits<std::size_t>::max() ||
        size > static_cast<std::uint64_t>(std::numeric_limits<std::streamsize>::max())) {
        throw ParseError("Input file exceeds the configured size limit");
    }
    input.seekg(0, std::ios::beg);
    if (!input) {
        throw ParseError("Cannot seek input file");
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
    if (!bytes.empty()) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (!input || input.gcount() != static_cast<std::streamsize>(size)) {
            throw ParseError("Cannot read the complete input file");
        }
    }
    // Detect concurrent growth instead of silently analyzing an incomplete file.
    if (input.peek() != std::ifstream::traits_type::eof()) {
        throw ParseError("Input file changed while it was being read");
    }
    if (input.bad()) {
        throw ParseError("Cannot finish reading input file");
    }
    return bytes;
}
} // namespace detail

Analysis analyze_file(const std::filesystem::path& file) {
    return analyze_file(file, Options{});
}

Analysis analyze_file(const std::filesystem::path& file, const Options& options) {
    return detail::analyze_with_options(detail::read_file(file), file, options);
}

Analysis analyze_bytes(const std::vector<std::uint8_t>& bytes, const Options& options) {
    return detail::analyze_with_options(bytes, {}, options);
}

} // namespace pesign
