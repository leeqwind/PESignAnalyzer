#include "pesign/analyzer.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;
constexpr std::size_t pe_offset = 0x80;
constexpr std::size_t optional_offset = pe_offset + 24;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void put16(Bytes& bytes, std::size_t offset, std::uint16_t value) {
    bytes.at(offset) = static_cast<std::uint8_t>(value);
    bytes.at(offset + 1) = static_cast<std::uint8_t>(value >> 8);
}

void put32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    for (std::size_t index = 0; index < 4; ++index) {
        bytes.at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
    }
}

std::size_t directories(bool plus) { return plus ? 112 : 96; }
std::size_t security(bool plus = false) { return optional_offset + directories(plus) + 32; }
std::size_t sections(bool plus = false, std::uint32_t count = 16) {
    return optional_offset + directories(plus) + count * 8;
}

Bytes image(bool plus = false, std::uint32_t count = 16) {
    Bytes bytes(0x300, 0);
    put16(bytes, 0, 0x5a4d);
    put32(bytes, 0x3c, static_cast<std::uint32_t>(pe_offset));
    put32(bytes, pe_offset, 0x00004550);
    put16(bytes, pe_offset + 4, plus ? 0x8664 : 0x014c);
    put16(bytes, pe_offset + 6, 1);
    put16(bytes, pe_offset + 20, static_cast<std::uint16_t>(directories(plus) + count * 8));
    put16(bytes, optional_offset, plus ? 0x020b : 0x010b);
    put32(bytes, optional_offset + directories(plus) - 4, count);
    const auto section = sections(plus, count);
    put32(bytes, section + 12, 0x1000); // The RVA intentionally differs from the file offset.
    put32(bytes, section + 16, 0x100);
    put32(bytes, section + 20, 0x200);
    return bytes;
}

void table(Bytes& bytes, std::uint32_t offset, std::uint32_t size, bool plus = false) {
    put32(bytes, security(plus), offset);
    put32(bytes, security(plus) + 4, size);
}

void append_record(Bytes& bytes, std::uint16_t type, const Bytes& payload,
                   std::uint16_t revision = 0x0200, bool include_padding_in_length = true) {
    const std::size_t offset = bytes.size();
    const std::size_t actual_length = 8 + payload.size();
    const std::size_t padded_length = (actual_length + 7) & ~std::size_t{7};
    bytes.resize(offset + padded_length, 0);
    put32(bytes, offset, static_cast<std::uint32_t>(include_padding_in_length ? padded_length : actual_length));
    put16(bytes, offset + 4, revision);
    put16(bytes, offset + 6, type);
    for (std::size_t index = 0; index < payload.size(); ++index) {
        bytes[offset + 8 + index] = payload[index];
    }
}

void expect_parse_error(const std::function<void()>& operation, const std::string& message) {
    try {
        operation();
    } catch (const pesign::ParseError&) {
        return;
    }
    throw std::runtime_error("Expected ParseError: " + message);
}

void reject(const Bytes& bytes, const std::string& message) {
    expect_parse_error([&] { static_cast<void>(pesign::analyze_bytes(bytes)); }, message);
}

void unsigned_images() {
    for (bool plus : {false, true}) {
        const auto result = pesign::analyze_bytes(image(plus));
        require(result.pe_format == (plus ? "PE32+" : "PE32"), "PE format");
        require(result.machine == (plus ? 0x8664 : 0x014c), "machine");
        require(result.signatures.empty() && result.certificate_records.empty(), "unsigned image");
        require(result.errors.empty() && result.warnings.empty(), "unsigned image diagnostics");
        for (std::uint32_t count : {0U, 4U}) {
            require(pesign::analyze_bytes(image(plus, count)).certificate_records.empty(),
                    "absent security directory must be unsigned");
        }
    }
}

void malformed_headers() {
    reject({}, "empty input");
    reject(Bytes(63, 0), "short DOS header");
    auto bytes = image();
    put16(bytes, 0, 0);
    reject(bytes, "MZ signature");
    bytes = image();
    put32(bytes, 0x3c, 32);
    reject(bytes, "PE offset overlaps DOS");
    bytes = image();
    put32(bytes, 0x3c, 0xfffffff0U);
    reject(bytes, "large PE offset");
    bytes = image();
    bytes.resize(pe_offset + 23);
    reject(bytes, "short COFF header");
    bytes = image();
    put32(bytes, pe_offset, 0);
    reject(bytes, "PE signature");
    bytes = image();
    put16(bytes, pe_offset + 20, 0);
    reject(bytes, "missing optional header");
    bytes = image();
    put16(bytes, optional_offset, 0x0107);
    reject(bytes, "ROM optional header");
    for (bool plus : {false, true}) {
        bytes = image(plus);
        put16(bytes, pe_offset + 20, static_cast<std::uint16_t>(directories(plus) - 1));
        reject(bytes, "truncated fixed optional header");
        bytes = image(plus);
        put16(bytes, pe_offset + 20, static_cast<std::uint16_t>(directories(plus) + 4 * 8 + 7));
        reject(bytes, "truncated security directory");
        bytes = image(plus);
        put32(bytes, optional_offset + directories(plus) - 4, 0xffffffffU);
        reject(bytes, "overflowing directory count");
    }
    bytes = image();
    put16(bytes, pe_offset + 6, 0xffff);
    reject(bytes, "section-header count");
    bytes = image();
    bytes.resize(sections() + 39);
    reject(bytes, "truncated section header");
    bytes = image();
    put32(bytes, sections() + 20, 0xfffffff0U);
    reject(bytes, "section raw-data range overflow");
    bytes = image();
    put32(bytes, sections() + 20, 0x100);
    reject(bytes, "section overlaps header");
    bytes = image();
    put32(bytes, sections() + 16, 0);
    put32(bytes, sections() + 20, 0xffffffffU);
    require(pesign::analyze_bytes(bytes).errors.empty(), "uninitialized section ignores raw pointer");
}

void malformed_tables() {
    auto bytes = image();
    table(bytes, 0x300, 0);
    reject(bytes, "nonzero offset with zero size");
    table(bytes, 0, 16);
    reject(bytes, "zero offset with nonzero size");
    bytes.resize(0x310);
    table(bytes, 0x301, 8);
    reject(bytes, "misaligned table");
    table(bytes, 0xfffffff8U, 16);
    reject(bytes, "table range overflow");
    table(bytes, 0x300, 0xffffffffU);
    reject(bytes, "table size overflow");
    table(bytes, 0x80, 16);
    reject(bytes, "table overlaps headers");
    table(bytes, 0x200, 16);
    reject(bytes, "table overlaps raw section");
    table(bytes, 0x300, 7);
    reject(bytes, "short record header");
    table(bytes, 0x300, 16);
    put32(bytes, 0x300, 0);
    reject(bytes, "zero record length");
    put32(bytes, 0x300, 7);
    reject(bytes, "record shorter than header");
    put32(bytes, 0x300, 0xffffffffU);
    reject(bytes, "record length overflow");
    put32(bytes, 0x300, 9);
    table(bytes, 0x300, 9);
    reject(bytes, "missing record alignment padding");
    table(bytes, 0x300, 16);
    bytes[0x30f] = 1;
    reject(bytes, "nonzero external alignment padding");
    bytes[0x30f] = 0;
    put32(bytes, 0x300, 8);
    table(bytes, 0x300, 12);
    reject(bytes, "partial following record");
}

void records_and_payloads() {
    for (bool plus : {false, true}) {
        auto bytes = image(plus);
        append_record(bytes, 1, {0x30}, 0x0200, false);
        append_record(bytes, 4, {0x01, 0x02}, 0x1234);
        table(bytes, 0x300, static_cast<std::uint32_t>(bytes.size() - 0x300), plus);
        const auto result = pesign::analyze_bytes(bytes);
        require(result.certificate_table_offset == 0x300, "security address is a file offset");
        require(result.certificate_records.size() == 2, "all records parsed");
        require(result.certificate_records[0].length == 9, "unrounded dwLength retained");
        require(result.certificate_records[1].offset == 0x310, "8-byte record alignment");
        require(result.certificate_records[1].revision == 0x1234, "revision retained");
        require(result.certificate_records[1].type == 4, "type retained");
        require(result.signatures.empty(), "unsupported types do not create signatures");
        require(result.warnings.size() == 3, "unsupported type and revision diagnostics");
        require(result.errors.empty(), "unsupported type is not a malformed PE");
    }

    auto bytes = image();
    append_record(bytes, 2, {0xff, 0x00, 0xff});
    append_record(bytes, 1, {0x01});
    table(bytes, 0x300, static_cast<std::uint32_t>(bytes.size() - 0x300));
    const auto result = pesign::analyze_bytes(bytes);
    require(result.certificate_records.size() == 2, "malformed payload does not stop enumeration");
    require(!result.errors.empty(), "PKCS#7 decoder reports invalid payload");

    bytes = image();
    for (std::size_t index = 0; index < 4097; ++index) {
        append_record(bytes, 1, {});
    }
    table(bytes, 0x300, static_cast<std::uint32_t>(bytes.size() - 0x300));
    reject(bytes, "certificate-record safety limit");
}

void file_paths() {
    const auto nonce = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const auto directory = std::filesystem::temp_directory_path() / ("pesign-reader-test-" + nonce);
    std::filesystem::create_directory(directory);
    struct Cleanup {
        std::filesystem::path directory;
        ~Cleanup() { std::error_code ignored; std::filesystem::remove_all(directory, ignored); }
    } cleanup{directory};
    const auto file = directory / std::filesystem::u8path("PE-\xe6\xb5\x8b\xe8\xaf\x95 sample.exe");
    const auto bytes = image(true);
    {
        std::ofstream output(file, std::ios::binary);
        output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
        require(static_cast<bool>(output), "write Unicode test path");
    }
    const auto result = pesign::analyze_file(file);
    const auto utf8_path = file.u8string();
    require(result.file == std::string(utf8_path.begin(), utf8_path.end()), "UTF-8 output path");
    require(result.pe_format == "PE32+", "read binary PE image from Unicode path");
    expect_parse_error([&] { static_cast<void>(pesign::analyze_file(directory / "missing.exe")); },
                       "nonexistent file");
    {
        std::ofstream output(file, std::ios::binary | std::ios::trunc);
    }
    expect_parse_error([&] { static_cast<void>(pesign::analyze_file(file)); }, "empty file");
}

} // namespace

int main() {
    try {
        unsigned_images();
        malformed_headers();
        malformed_tables();
        records_and_payloads();
        file_paths();
        std::cout << "PE reader tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "PE reader test failed: " << error.what() << '\n';
        return 1;
    }
}
