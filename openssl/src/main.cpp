#include "pesign/analyzer.h"

#include <exception>
#include <iostream>
#include <string>

namespace {
void usage() {
    std::cout << "PESignAnalyzerOpenSSL " << pesign::version << "\n"
              << "Usage: PESignAnalyzerOpenSSL [options] <PE file>\n"
              << "Default: parse metadata and resolve local certificate chains; use --verify to validate.\n"
              << "  --json                      Print JSON.\n"
              << "  --verify                    Verify Authenticode.\n"
              << "  --strict-timestamps         Enforce all Microsoft ESS references; implies --verify.\n"
              << "  --revocation <mode>         none, cache, online; implies --verify.\n"
              << "  -c, --catalog <file>        Catalog fallback.\n"
              << "  --catalog-dir <directory>   Search catalogs recursively; repeatable.\n"
              << "  --embedded-only             Disable catalog fallback.\n"
              << "  --ca-file <file>            Additional trusted PEM roots.\n"
              << "  --ca-dir <directory>        Trusted PEM/DER root directory.\n"
              << "  --no-system-roots           Use only explicit trusted roots.\n"
              << "  --crl-file <file>           PEM/DER CRL input.\n"
              << "  --crl-dir <directory>       Local CRL directory.\n"
              << "  --revocation-cache <dir>    Issuer/CRL/OCSP cache directory.\n"
              << "  --network-timeout <seconds> Per-chain network budget, 1..300 (default 10).\n"
              << "  -h, --help, /?              Show help.\n"
              << "  -V, --version               Show version.\n"
              << "  --                          Stop processing options.\n";
}

template <typename Char>
int run(int argc, Char** argv) {
    bool json = false;
    bool options = true;
    pesign::Options settings;
    std::filesystem::path file;
    for (int i = 1; i < argc; ++i) {
        const auto utf8_argument = std::filesystem::path(argv[i]).u8string();
        const std::string argument(utf8_argument.begin(), utf8_argument.end());
        if (options && argument == "--") options = false;
        else if (options && argument == "--json") json = true;
        else if (options && (argument == "--help" || argument == "-h" || argument == "/?")) {
            usage();
            return 0;
        } else if (options && (argument == "--version" || argument == "-V")) {
            std::cout << "PESignAnalyzerOpenSSL " << pesign::version << '\n';
            return 0;
        } else if (options && argument == "--verify") settings.verify = true;
        else if (options && argument == "--strict-timestamps") {
            settings.strict_timestamps = true;
            settings.verify = true;
        }
        else if (options && argument == "--embedded-only") settings.embedded_only = true;
        else if (options && argument == "--no-system-roots") settings.use_system_roots = false;
        else if (options && (argument == "--catalog" || argument == "-c" ||
            argument == "--catalog-dir" || argument == "--ca-file" || argument == "--ca-dir" ||
            argument == "--crl-file" || argument == "--crl-dir" || argument == "--revocation-cache" ||
            argument == "--revocation" || argument == "--network-timeout")) {
            if (++i >= argc || !*argv[i]) {
                std::cerr << "Error: " << argument << " requires a value.\n"; return 2;
            }
            const std::filesystem::path value(argv[i]);
            const auto utf8_value = value.u8string();
            const std::string value_text(utf8_value.begin(), utf8_value.end());
            if (argument == "--catalog" || argument == "-c") settings.catalog = value;
            else if (argument == "--catalog-dir") settings.catalog_directories.push_back(value);
            else if (argument == "--ca-file") settings.ca_file = value;
            else if (argument == "--ca-dir") settings.ca_directory = value;
            else if (argument == "--crl-file") settings.crl_file = value;
            else if (argument == "--crl-dir") settings.crl_directory = value;
            else if (argument == "--revocation-cache") settings.revocation_cache = value;
            else if (argument == "--revocation") {
                if (value_text == "none") settings.revocation = pesign::RevocationMode::none;
                else if (value_text == "cache") settings.revocation = pesign::RevocationMode::cache;
                else if (value_text == "online") settings.revocation = pesign::RevocationMode::online;
                else {std::cerr << "Error: invalid revocation mode.\n"; return 2;}
                settings.verify = true;
            } else {
                if (value_text.size() > 3 || value_text.find_first_not_of("0123456789") != std::string::npos) {
                    std::cerr << "Error: network timeout must be 1..300 seconds.\n"; return 2;
                }
                const auto seconds = std::stoul(value_text);
                if (!seconds || seconds > 300) {std::cerr << "Error: network timeout must be 1..300 seconds.\n"; return 2;}
                settings.network_timeout_seconds = static_cast<unsigned>(seconds);
            }
        } else if (options && argument.compare(0, 10, "--catalog=") == 0) {
            if (argument.size() == 10) {std::cerr << "Error: catalog path is empty.\n"; return 2;}
            settings.catalog = std::filesystem::path(std::basic_string<Char>(argv[i]).substr(10));
        } else if (options && !argument.empty() && argument.front() == '-') {
            std::cerr << "Error: unknown option: " << argument << '\n';
            return 2;
        } else if (!file.empty() || argument.empty()) {
            std::cerr << "Error: exactly one nonempty input path is required.\n";
            return 2;
        } else file = std::filesystem::path(argv[i]);
    }
    if (file.empty()) {
        usage();
        return 2;
    }
    if (settings.embedded_only && (!settings.catalog.empty() || !settings.catalog_directories.empty())) {
        std::cerr << "Error: --embedded-only conflicts with catalog options.\n"; return 2;
    }
    auto result = pesign::analyze_file(file, settings);
    std::cout << (json ? pesign::to_json(result) : pesign::to_text(result)) << '\n';
    if (!result.errors.empty()) return 3;
    if (result.signatures.empty()) return 1;
    if (settings.verify || settings.revocation != pesign::RevocationMode::none) {
        if (result.verification.overall == "indeterminate") return 4;
        if (result.verification.overall != "valid") return 3;
    }
    return 0;
}

template <typename Char>
int entry(int argc, Char** argv) {
    try { return run(argc, argv); }
    catch (const std::exception& error) {
        std::cerr << "Error: " << error.what() << '\n';
        return 3;
    }
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) { return entry(argc, argv); }
#else
int main(int argc, char** argv) { return entry(argc, argv); }
#endif
