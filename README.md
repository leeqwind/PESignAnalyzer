# PESignAnalyzer

[简体中文](README.zh.md)

An independent OpenSSL cross-platform version is available under
[`openssl/`](openssl/README.md), with its own CMake build targeting Windows,
Linux, and macOS. It implements embedded and catalog signature parsing, image
digest and cryptographic verification, both timestamp formats, certificate
chains, and cached/online revocation checks. The rest of this page describes
the original Windows CryptoAPI version; see the subproject for its dependencies,
options, and trust policy.

PESignAnalyzer is a Windows command-line tool for inspecting and verifying
Authenticode signatures on PE files. It supports embedded signatures and
catalog-signed files, including automatic discovery of installed system
catalogs.

The verification path does **not** import or call any API from `Wintrust.dll`.
PE hashing, catalog membership lookup, CMS verification, timestamp validation,
certificate-chain building, and optional revocation checks are implemented with
PE parsing plus APIs from Kernel32, Crypt32, and Advapi32.

## Current status

Current version: **1.3.0**

| Capability | Status |
|---|---|
| Embedded Authenticode metadata | Supported |
| Multiple/nested signature metadata | Supported |
| Automatic system Catalog discovery | Supported without WinTrust |
| Explicit Catalog selection | Supported with `--catalog` |
| Authenticode content digest verification | Supported |
| CMS/PKCS#7 signature verification | Supported |
| RFC 3161 timestamps | Supported |
| Legacy PKCS#9 countersignatures | Supported |
| Certificate-chain policy verification | Supported |
| Cached or online revocation checks | Supported |
| x86 and x64 release binaries | Available from [GitHub Releases](https://github.com/leeqwind/PESignAnalyzer/releases) |

The native analyzer links Windows CryptoAPI and a static MSVC runtime; it does
not require OpenSSL or curl. Download `PESignAnalyzer-<tag>-windows-x64.zip` or
`PESignAnalyzer-<tag>-windows-x86.zip` and extract it before running the examples
below. The separate `PESignAnalyzerOpenSSL-*` packages contain the cross-platform implementation.

## How verification works

PESignAnalyzer performs the following checks without `WinVerifyTrust` or
`CryptCATAdmin*`:

1. Parse the PE headers and calculate the Authenticode image digest while
   excluding the checksum, security-directory entry, and certificate table.
2. For embedded signatures, extract the signed digest from the PKCS#7 content
   and compare it with the calculated image digest.
3. For catalog signatures, calculate candidate digests, scan the Windows
   CatRoot, parse Catalog DER members, and locate a matching member digest.
4. Verify the CMS signer with `CryptMsgControl` and
   `CMSG_CTRL_VERIFY_SIGNATURE_EX`.
5. Verify RFC 3161 or legacy countersignature timestamps.
6. Build the signer and timestamp certificate chains and apply Authenticode
   chain policies.
7. Optionally check revocation using the local cache or online CRL/OCSP access.

Catalog discovery uses a lightweight DER member prefilter, then confirms the
digest in the candidate's CMS content. With `--verify`, the candidate's CMS
signature and certificate chain are also verified. A cold scan, especially
when no catalog matches, is slower than the Windows WinTrust catalog index.

## Command line

```text
Usage: PESignAnalyzer.exe [options] <file>

Options:
  -c, --catalog <file>  Use a specific catalog as fallback.
      --embedded-only   Require an embedded signature.
      --verify          Verify the Authenticode signature.
      --revocation <mode>
                        Revocation mode: none, cache, or online.
  -h, --help, /?        Show this help and exit.
  -V, --version         Show version information and exit.
      --                Stop processing options.
```

The original metadata-only invocation remains supported:

```powershell
.\PESignAnalyzer.exe "C:\Program Files\Git\cmd\git.exe"
```

Verify an embedded signature:

```powershell
.\PESignAnalyzer.exe --verify `
  "C:\Program Files\Git\cmd\git.exe"
```

Automatically discover and verify the Catalog for a system file:

```powershell
.\PESignAnalyzer.exe --verify `
  "C:\Windows\System32\notepad.exe"
```

Specify a Catalog explicitly:

```powershell
.\PESignAnalyzer.exe --verify `
  --catalog "C:\Windows\System32\CatRoot\{GUID}\package.cat" `
  "C:\Windows\System32\notepad.exe"
```

Enable online revocation checks (`--revocation` implies `--verify`):

```powershell
.\PESignAnalyzer.exe --revocation online `
  "C:\Windows\System32\notepad.exe"
```

In PowerShell, a continuation backtick must be the final character on its line.

## Verification output

| Field | Meaning |
|---|---|
| `contentDigest` | The PE digest matches the embedded signature or Catalog member |
| `cmsSignature` | The CMS/PKCS#7 cryptographic signature is valid |
| `certificateChain` | The signer chain satisfies the selected Authenticode policy |
| `timestamp` | The RFC 3161 or legacy timestamp is valid |
| `revocation` | `not_checked`, `good`, `revoked`, or `unknown` |
| `overall` | `valid`, `invalid`, or `indeterminate` |

`indeterminate` means the cryptographic signature and chain can be valid while
the requested revocation status cannot be established. It must not be treated
as equivalent to `valid` in a strict security policy.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Analysis or verification succeeded |
| `1` | No readable signature was found |
| `2` | Invalid command line |
| `3` | Signature verification failed |
| `4` | Verification is indeterminate |

## Building

The preferred build entry point is CMake. Build both native Windows architectures
from a Visual Studio Developer Command Prompt:

```cmd
cmake -S . -B .build\cmake-x64 -A x64
cmake --build .build\cmake-x64 --config Release --parallel

cmake -S . -B .build\cmake-x86 -A Win32
cmake --build .build\cmake-x86 --config Release --parallel
```

Legacy Visual C++ project files remain available under `msvc/`:

- `msvc/vs2013.vcxproj`
- `msvc/vs2015.vcxproj`

Example MSBuild commands:

```cmd
MSBuild msvc\vs2015.vcxproj /p:Configuration=Release /p:Platform=x64
MSBuild msvc\vs2015.vcxproj /p:Configuration=Release /p:Platform=Win32
```

The implementation is organized under `src/`, with its public API under
`include/analyzer/`. See [docs/architecture.md](docs/architecture.md)
for the module map and ownership boundaries.

Both build systems link `Crypt32.lib` and `Advapi32.lib`. `Wintrust.lib` is
neither required nor linked.

## Release publishing

Pushing a new `v*` tag runs `.github/workflows/release.yml`. To rebuild an existing
tag, open Actions → Release analyzers → Run workflow, select `master`, and enter
the tag, or run `gh workflow run release.yml --ref master -f tag=v1.3.0`.
Both native Windows architectures and all four OpenSSL builds must pass before
the six archives and their SHA-256 files are uploaded to the Release. Native
archives also run the smoke suite after extraction. Build provenance is recorded
in `BUILD-INFO.json`; no release binaries are stored in the source tree.

## Tests

Run the smoke suite against either build:

```powershell
.\tests\smoke.ps1 -Executable .\.build\cmake-x64\Release\PESignAnalyzer.exe
.\tests\smoke.ps1 -Executable .\.build\cmake-x86\Release\PESignAnalyzer.exe
```

The suite covers command-line behavior, embedded verification, tamper
detection, automatic Catalog discovery, Catalog verification, and
`--embedded-only` behavior.

## Limitations

- Catalog auto-discovery scans the local Windows CatRoot because the WinTrust
  index is intentionally not used. Cold or unsuccessful scans can be slower.
- Automatic discovery only considers locally installed system catalogs. Use
  `--catalog` for another Catalog file.
- Revocation checks depend on the local cache, network configuration, and CA
  CRL/OCSP availability; an unavailable status produces `indeterminate`.
- Metadata extraction supports multiple/nested signatures. The current
  verification summary evaluates the primary signer selected from the message.
- This project is a diagnostic tool. Validate its behavior against the security
  requirements and samples of your deployment before using it as an enforcement
  boundary.

## License

[MIT](LICENSE)

## Contact

leeq.live@outlook.com
