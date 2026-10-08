#include "verification_internal.h"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <memory>
#include <set>

namespace pesign::detail {
namespace {
struct View { const std::uint8_t* data = nullptr; std::size_t size = 0; };
struct Element { unsigned tag = 0; View body; View encoded; };
bool next(View view, std::size_t& cursor, Element& element) {
    const auto start = cursor;
    if (cursor >= view.size) return false;
    element.tag = view.data[cursor++];
    if ((element.tag & 31) == 31 || cursor >= view.size) return false;
    unsigned first = view.data[cursor++];
    std::size_t length = first;
    if (first & 128) {
        const unsigned count = first & 127;
        if (!count || count > sizeof(std::size_t) || count > view.size - cursor || view.data[cursor] == 0)
            return false;
        length = 0;
        for (unsigned i = 0; i < count; ++i) length = (length << 8) | view.data[cursor++];
        if (length < 128) return false;
    }
    if (length > view.size - cursor) return false;
    element.body = {view.data + cursor, length};
    cursor += length;
    element.encoded = {view.data + start, cursor - start};
    return true;
}
std::string oid(const Element& element) {
    if (element.tag != 6 || element.encoded.size > 256) return {};
    const auto* cursor = element.encoded.data;
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> object(
        d2i_ASN1_OBJECT(nullptr, &cursor, static_cast<long>(element.encoded.size)), ASN1_OBJECT_free);
    if (!object || cursor != element.encoded.data + element.encoded.size) return {};
    char text[256]{};
    const auto size = OBJ_obj2txt(text, sizeof(text), object.get(), 1);
    return size > 0 && size < static_cast<int>(sizeof(text)) ? text : "";
}
View content(PKCS7* message) {
    if (!message || !PKCS7_type_is_signed(message) || !message->d.sign || !message->d.sign->contents) return {};
    PKCS7* inner = message->d.sign->contents;
    char type[64]{};
    OBJ_obj2txt(type, sizeof(type), inner->type, 1);
    if (std::string(type) != "1.3.6.1.4.1.311.10.1" || !PKCS7_type_is_other(inner) || !inner->d.other) return {};
    const ASN1_TYPE* other = inner->d.other;
    const ASN1_STRING* bytes = other->type == V_ASN1_SEQUENCE ? other->value.sequence :
        other->type == V_ASN1_OCTET_STRING ? other->value.octet_string : nullptr;
    const int size = bytes ? ASN1_STRING_length(bytes) : 0;
    return size > 0 ? View{ASN1_STRING_get0_data(bytes), static_cast<std::size_t>(size)} : View{};
}
std::string utf8(const std::filesystem::path& path) {
    const auto bytes = path.u8string();
    return std::string(bytes.begin(), bytes.end());
}
std::vector<std::vector<std::uint8_t>> candidate_digests(const std::vector<std::uint8_t>& pe) {
    std::vector<std::vector<std::uint8_t>> digests;
    for (const auto* id : {"2.16.840.1.101.3.4.2.1", "1.3.14.3.2.26",
                           "2.16.840.1.101.3.4.2.2", "2.16.840.1.101.3.4.2.3"})
        digests.push_back(authenticode_digest(pe, id));
    return digests;
}
bool contains_digest(const std::vector<std::uint8_t>& catalog,
                     const std::vector<std::vector<std::uint8_t>>& digests) {
    bool possible = false;
    for (const auto& digest : digests)
        if (std::search(catalog.begin(), catalog.end(), digest.begin(), digest.end()) != catalog.end()) {
            possible = true; break;
        }
    if (!possible) return false;
    const auto* cursor = catalog.data();
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> message(
        d2i_PKCS7(nullptr, &cursor, static_cast<long>(catalog.size())), PKCS7_free);
    if (!message || !std::all_of(cursor, catalog.data() + catalog.size(), [](std::uint8_t byte) {return byte == 0;}))
        return false;
    const View value = content(message.get());
    for (const auto& digest : digests)
        if (catalog_content_contains(value.data, value.size, digest)) return true;
    return false;
}
std::vector<std::filesystem::path> search_directories(const Options& options, bool has_file) {
    auto directories = options.catalog_directories;
#ifdef _WIN32
    if (has_file) {
        const wchar_t* windows = _wgetenv(L"SystemRoot");
        if (!windows) windows = _wgetenv(L"WINDIR");
        if (windows) {
            // A 32-bit process needs Sysnative to see the native system CatRoot.
            auto native = std::filesystem::path(windows) / L"Sysnative" / L"CatRoot";
            std::error_code error;
            directories.push_back(std::filesystem::is_directory(native, error) ? native :
                std::filesystem::path(windows) / L"System32" / L"CatRoot");
        }
    }
#else
    (void)has_file;
#endif
    return directories;
}
std::filesystem::path discover(const std::vector<std::uint8_t>& pe,
    const Options& options, bool has_file, Analysis& result) {
    auto directories = search_directories(options, has_file);
    if (directories.empty()) return {};
    std::vector<std::vector<std::uint8_t>> digests;
    try {
        digests = candidate_digests(pe);
    } catch (const ParseError& error) {
        result.warnings.push_back(std::string("Catalog lookup skipped: ") + error.what());
        return {};
    }
    std::set<std::filesystem::path> seen;
    std::size_t inspected = 0;
    for (const auto& directory : directories) {
        std::error_code error;
        std::filesystem::recursive_directory_iterator iterator(directory,
            std::filesystem::directory_options::skip_permission_denied, error), end;
        if (error) {result.warnings.push_back("Cannot read catalog directory: " + utf8(directory)); continue;}
        for (; iterator != end; iterator.increment(error)) {
            if (error) {error.clear(); continue;}
            if (!iterator->is_regular_file(error) || error) {error.clear(); continue;}
            auto extension = utf8(iterator->path().extension());
            std::transform(extension.begin(), extension.end(), extension.begin(),
                [](unsigned char byte) {return static_cast<char>(std::tolower(byte));});
            if (extension != ".cat" || !seen.insert(iterator->path()).second) continue;
            if (++inspected > 100000) {result.errors.push_back("Catalog scan exceeds 100000-file limit"); return {};}
            try {
                if (contains_digest(read_file(iterator->path(), 64u * 1024u * 1024u), digests)) return iterator->path();
            } catch (const ParseError&) { /* An unrelated malformed catalog is not a match. */ }
        }
    }
    return {};
}
} // namespace

bool catalog_content_contains(const std::uint8_t* data, std::size_t size,
                              const std::vector<std::uint8_t>& digest) {
    if (!data || !size || digest.empty()) return false;
    Element root, field;
    std::size_t cursor = 0;
    if (!next({data,size}, cursor, root) || root.tag != 0x30 || cursor != size) return false;
    cursor = 0;
    if (!next(root.body, cursor, field)) return false;
    if (field.tag == 2 && !next(root.body, cursor, field)) return false; // Optional version.
    if (field.tag != 0x30) return false; // SubjectUsage.
    std::size_t usage_cursor = 0;
    Element usage;
    while (usage_cursor < field.body.size)
        if (!next(field.body, usage_cursor, usage) || oid(usage).empty()) return false;
    if (!next(root.body, cursor, field)) return false;
    if (field.tag == 4 && !next(root.body, cursor, field)) return false; // ListIdentifier.
    if (field.tag == 2 && !next(root.body, cursor, field)) return false; // SequenceNumber.
    if (field.tag != 0x17 && field.tag != 0x18) return false;
    if (!next(root.body, cursor, field)) return false;
    if ((field.tag == 0x17 || field.tag == 0x18) && !next(root.body, cursor, field)) return false;
    if (field.tag != 0x30) return false; // SubjectAlgorithm.
    Element algorithm_oid;
    std::size_t algorithm_cursor = 0;
    if (!next(field.body, algorithm_cursor, algorithm_oid)) return false;
    const auto algorithm = oid(algorithm_oid);
    // Microsoft catalogs use catalog-list-member algorithms, rather than a
    // hash OID. Their entries may mix SHA-1 and SHA-256 subject identifiers.
    const bool catalog_algorithm = algorithm == "1.3.6.1.4.1.311.12.1.2" ||
                                   algorithm == "1.3.6.1.4.1.311.12.1.3";
    const std::size_t expected = algorithm == "1.3.14.3.2.26" ? 20 :
        algorithm == "2.16.840.1.101.3.4.2.1" ? 32 :
        algorithm == "2.16.840.1.101.3.4.2.2" ? 48 :
        algorithm == "2.16.840.1.101.3.4.2.3" ? 64 : 0;
    if (!catalog_algorithm && (!expected || expected != digest.size())) return false;
    if (!next(root.body, cursor, field) || field.tag != 0x30) return false; // CTLEntries.
    if (cursor < root.body.size) {
        Element extensions;
        if (!next(root.body, cursor, extensions) || extensions.tag != 0xa0 || cursor != root.body.size) return false;
    }
    bool match = false;
    std::size_t entries_cursor = 0, entries = 0;
    while (entries_cursor < field.body.size) {
        Element entry, identifier, attributes;
        if (++entries > 100000 || !next(field.body, entries_cursor, entry) || entry.tag != 0x30) return false;
        std::size_t entry_cursor = 0;
        if (!next(entry.body, entry_cursor, identifier) || identifier.tag != 4 ||
            !next(entry.body, entry_cursor, attributes) || attributes.tag != 0x31 ||
            entry_cursor != entry.body.size) return false;
        // Only CTLEntry subjectIdentifier may match; unrelated OCTET STRINGs
        // in attributes, certificates or unsigned data can never satisfy this.
        if (identifier.body.size == digest.size() &&
            std::equal(digest.begin(), digest.end(), identifier.body.data)) match = true;
    }
    return match;
}

Analysis analyze_with_options(const std::vector<std::uint8_t>& bytes,
    const std::filesystem::path& file, const Options& options) {
    if (options.embedded_only && (!options.catalog.empty() || !options.catalog_directories.empty()))
        throw ParseError("embedded_only conflicts with catalog options");
    if (options.network_timeout_seconds == 0 || options.network_timeout_seconds > 300)
        throw ParseError("Network timeout must be between 1 and 300 seconds");
    Analysis result = parse_pe_metadata(bytes, &options);
    result.file = utf8(file);
    const bool verify = options.verify || options.strict_timestamps || options.revocation != RevocationMode::none;
    if (!result.signatures.empty()) {
        result.signature_type = "embedded";
        if (verify) {
            for (std::size_t i = 0; i < result.certificate_records.size(); ++i) {
                const auto& record = result.certificate_records[i];
                if (record.type == 2)
                    verify_pkcs7(bytes.data() + static_cast<std::size_t>(record.offset) + 8,
                        record.length - 8, i, bytes, options, result, false);
            }
        }
    } else if (result.errors.empty() && !options.embedded_only) {
        auto catalog = options.catalog;
        if (catalog.empty()) catalog = discover(bytes, options, !file.empty(), result);
        if (!catalog.empty()) {
            const auto payload = read_file(catalog, 64u * 1024u * 1024u);
            result.catalog_file = utf8(catalog);
            parse_pkcs7(payload.data(), payload.size(), 0, result, &options);
            if (!result.signatures.empty()) {
                result.signature_type = "cataloged";
                if (verify) verify_pkcs7(payload.data(), payload.size(), 0, bytes, options, result, true);
            }
        }
    }
    if (verify && !result.signatures.empty() && !result.signatures.front().signers.empty())
        result.verification = result.signatures.front().signers.front().verification;
    return result;
}
} // namespace pesign::detail
