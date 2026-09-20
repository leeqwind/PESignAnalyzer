# Architecture

PESignAnalyzer keeps the command-line application thin and groups the Windows
cryptography implementation by responsibility.

| Path | Responsibility |
|---|---|
| `include/analyzer/` | Public data types and analyzer API |
| `src/main.cpp` | Command-line parsing, output, and exit codes |
| `src/analyzer.cpp` | High-level embedded/catalog analysis selection |
| `src/signature_parser.cpp` | CMS signer, nested signature, and timestamp parsing |
| `src/certificate_info.cpp` | Certificate metadata and chain extraction |
| `src/asn1.cpp` | Bounded DER parsing and digest OID decoding |
| `src/authenticode.cpp` | PE hashing and cryptographic verification |
| `src/catalog.cpp` | Catalog loading, matching, and system catalog discovery |
| `src/internal.h` | Private declarations shared only by implementation units |
| `msvc/` | Legacy Visual Studio 2013/2015 project entry points |
| `dist/` | Packaged x86 and x64 Release executables |
| `tests/` | Executable-level smoke tests |
| `blog/` | Long-form documentation and diagrams |

The public headers intentionally expose the existing API and result structures
without introducing a binary compatibility layer. Implementation helpers stay
under `src/`; applications should include only
`analyzer/analyzer.h`.

CMake builds the implementation as `PESignAnalyzerCore` and links the thin
command-line executable against it. The legacy Visual Studio projects compile
the same source list directly into the executable. CMake is the preferred
entry point for current toolchains, while the old projects retain the original
compiler targets.
