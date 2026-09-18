# PESignAnalyzer

[简体中文](README.zh.md)

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
| x86 and x64 release binaries | Included in `Build/` |

The release binaries have been checked to import only `kernel32.dll`,
`crypt32.dll`, and `advapi32.dll`.

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
      --                 Stop processing options.
```

The original metadata-only invocation remains supported:

```powershell
.\PESignAnalyzer_VS2015_x64.exe "C:\Program Files\Git\cmd\git.exe"
```

Verify an embedded signature:

```powershell
.\PESignAnalyzer_VS2015_x64.exe --verify `
  "C:\Program Files\Git\cmd\git.exe"
```

Automatically discover and verify the Catalog for a system file:

```powershell
.\PESignAnalyzer_VS2015_x64.exe --verify `
  "C:\Windows\System32\notepad.exe"
```

Specify a Catalog explicitly:

```powershell
.\PESignAnalyzer_VS2015_x64.exe --verify `
  --catalog "C:\Windows\System32\CatRoot\{GUID}\package.cat" `
  "C:\Windows\System32\notepad.exe"
```

Enable online revocation checks (`--revocation` implies `--verify`):

```powershell
.\PESignAnalyzer_VS2015_x64.exe --revocation online `
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

The repository contains Visual C++ project files under `MSVC/`:

- `MSVC/PESignAnalyzer_VS2013.vcxproj`
- `MSVC/PESignAnalyzer_VS2015.vcxproj`

Example MSBuild commands:

```cmd
MSBuild MSVC\PESignAnalyzer_VS2015.vcxproj /p:Configuration=Release /p:Platform=x64
MSBuild MSVC\PESignAnalyzer_VS2015.vcxproj /p:Configuration=Release /p:Platform=Win32
```

The single source file can also be compiled from a Visual Studio Developer
Command Prompt:

```cmd
cl.exe /EHsc /nologo /W3 /O2 /MT /DUNICODE /D_UNICODE ^
  PESignAnalyzer.cpp Crypt32.lib Advapi32.lib /Fe:PESignAnalyzer.exe
```

`Crypt32.lib` and `Advapi32.lib` are also selected by `#pragma comment` in the
source. `Wintrust.lib` is neither required nor linked.

## Tests

Run the smoke suite against either architecture:

```powershell
.\tests\smoke.ps1 -Executable .\Build\PESignAnalyzer_VS2015_x64.exe
.\tests\smoke.ps1 -Executable .\Build\PESignAnalyzer_VS2015_x86.exe
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
