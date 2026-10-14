# PESignAnalyzerOpenSSL

基于 OpenSSL 的跨平台 Windows PE Authenticode 解析和验证库，版本 **0.2.2**。
使用 C++17、OpenSSL libcrypto 和 libcurl，目标平台为 Windows、Linux、macOS。
输入为 Windows PE 文件（exe、dll、sys 等），不需要在 Windows 上运行。

本目录使用独立 CMake 入口。根目录 Windows CryptoAPI 版本及 dist 发布文件保留
原构建方式；本目录不调用 WinTrust 或 CryptCATAdmin。

## 功能

| 原 Windows 版本功能 | OpenSSL 版本 |
|---|---|
| PE32 / PE32+、全部 WIN_CERTIFICATE | 有界读取、8 字节对齐 |
| 多签名者、多记录、嵌套签名 | 解析并逐个验证，保留父签名索引 |
| 签名、证书、算法、摘要、CRL URL 元数据 | 支持文本及 UTF-8 JSON |
| Authenticode 内容摘要 | 按原 Windows 文件顺序排除校验和、安全目录项、证书表，覆盖节间填充 |
| CMS/PKCS#7 验签 | 内容及 signed attributes，RSA、RSA-PSS、ECDSA、DSA |
| RFC 3161 时间戳 | CMS、TSTInfo、签名值绑定、ESS 签者身份及链，额外 ESS 约束可严格检查 |
| PKCS#9 countersignature | 签名值绑定及时间戳证书链 |
| 证书链 | 构链、有效期、代码签名/TSA 用途、密钥用途、系统及显式根 |
| 吊销检查 | none / cache / online，签者及 TSA 非根证书逐级检查 |
| Catalog | 显式文件、递归目录查找、已签名 CTL 成员摘要匹配 |
| Windows 系统 Catalog 自动发现 | CatRoot，兼容 32 位进程 Sysnative |
| 退出码 | 0 成功、1 无签名、2 参数错误、3 失败、4 无法确定 |

默认解析元数据并离线构建签名者证书链，从签名证书集合、系统证书库、显式 CA 和本地发行者缓存补齐根证书。
只有启用 --verify、--revocation 或 --strict-timestamps 才执行验证。certificates 是内嵌证书集合；
signingTime 和时间戳元数据本身是声明。只有通过签名绑定、TSA 信任和有效期检查的
时间戳才能决定历史链验证时间，签名者自述的 signingTime 不能恢复过期证书的信任。

## 构建

依赖 CMake 3.20+、C++17 编译器、OpenSSL 3.0+、libcurl 7.68+ 开发包。
建议 GCC 9+、Clang 9+、Apple Clang 12+ 或 Visual Studio 2019+。
Python 3 可选，用于本地 HTTP 测试。

### Linux（Ubuntu / Debian）

```sh
sudo apt-get install build-essential cmake libssl-dev libcurl4-openssl-dev
cmake -S openssl -B .build/openssl-linux -DCMAKE_BUILD_TYPE=Release
cmake --build .build/openssl-linux --parallel
ctest --test-dir .build/openssl-linux --output-on-failure
```

### macOS（Homebrew）

```sh
brew install cmake openssl@3 curl
cmake -S openssl -B .build/openssl-macos -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)" \
  -DCURL_ROOT="$(brew --prefix curl)"
cmake --build .build/openssl-macos --parallel
ctest --test-dir .build/openssl-macos --output-on-failure
```

### Windows（Visual Studio + vcpkg）

```powershell
$vcpkgRoot = 'C:\dev\vcpkg'
& "$vcpkgRoot\vcpkg.exe" install openssl:x64-windows curl:x64-windows
cmake -S openssl -B .build/openssl-windows -A x64 `
  "-DCMAKE_TOOLCHAIN_FILE=$vcpkgRoot/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build .build/openssl-windows --config Release --parallel
ctest --test-dir .build/openssl-windows -C Release --output-on-failure
```

也可指定 OPENSSL_ROOT_DIR 和 CURL_ROOT 使用匹配架构的开发包。
动态构建需要 libcrypto、libcurl 及其运行时依赖；vcpkg CMake 集成处理依赖复制。
32 位 Windows 可使用 x86-windows triplet 和 -A Win32；两种架构均解析 PE32/PE32+。
本机 Windows x64 Release 运行包位于 .build/openssl-native/package/windows-x64，包含程序及所需 DLL；
解压后保留同目录 DLL 即可运行。当前包使用静态 MSVC 运行库，无需单独安装 VC Runtime。
OpenSSL 编译输出及压缩包仅放在 Git 忽略的 .build 下，不持久化到 dist 或纳入版本控制。
Windows 链接 Crypt32，macOS 链接 Security/CoreFoundation 读取系统信任来源；
验签和构链均由 OpenSSL 执行。使用 -DBUILD_TESTING=OFF 关闭测试，
或 cmake --install <build-dir> --prefix <目录> 安装。

## GitHub Release 发布

`.github/workflows/release.yml` 独立执行发布构建。推送新的 `v*` 版本 tag 会自动发布；
已有 tag 可在 Actions → Release OpenSSL analyzer → Run workflow 中选择 `master`，
在 `tag` 输入框填写已有 tag（例如 `v1.3.0`）。GitHub 的手动输入框不提供动态 tag 下拉列表。
也可使用命令：

```sh
gh workflow run release.yml --ref master -f tag=v1.3.0
```

发布工具使用所选工作流版本，产品源码严格使用 tag 对应的提交，因此不必移动旧 tag。
四个平台全部构建、测试及解压后 CLI 冒烟检查通过，才会创建 Release 并上传附件：

| 包 | 运行要求 |
|---|---|
| `PESignAnalyzerOpenSSL-<tag>-windows-x64.zip` | Windows x64；静态链接依赖和 MSVC 运行库 |
| `PESignAnalyzerOpenSSL-<tag>-windows-x86.zip` | Windows x86/x64；静态链接依赖和 MSVC 运行库 |
| `PESignAnalyzerOpenSSL-<tag>-linux-x64.tar.gz` | Ubuntu 24.04+、glibc 2.39+，安装 `libssl3t64 libcurl4t64 ca-certificates` |
| `PESignAnalyzerOpenSSL-<tag>-macos-arm64.tar.gz` | macOS 15+、Apple Silicon；附带非系统 dylib，使用 ad-hoc 签名，未经公证 |

这些是解压运行包；当前不生成 MSI/DMG，也不包含 macOS Intel 或 Linux arm64。
附件提供独立的 `.sha256` 校验文件，包内 `BUILD-INFO.json` 记录 tag、源码提交、平台及
OpenSSL 子项目版本。仓库 tag 与 OpenSSL 子项目版本独立，例如 `v1.3.0` 中子项目仍为 `0.2.2`。
安装包也会保存在该次 Actions 的 artifacts 中，保留 14 天。
重跑同一 tag 会替换同名 Release 附件；发布前会再次检查远端 tag 未移动。

## 使用

```sh
# 元数据解析和本地证书链
.build/openssl-linux/PESignAnalyzerOpenSSL --json sample.exe

# 验证嵌入式签名，明确选择信任根
.build/openssl-linux/PESignAnalyzerOpenSSL --verify --embedded-only \
  --no-system-roots --ca-file roots.pem sample.exe

# 显式 Catalog 或指定目录查找
.build/openssl-linux/PESignAnalyzerOpenSSL --verify --catalog package.cat sample.exe
.build/openssl-linux/PESignAnalyzerOpenSSL --verify --catalog-dir catalogs sample.exe

# 在线检查，然后使用同一缓存离线检查
.build/openssl-linux/PESignAnalyzerOpenSSL --revocation online \
  --revocation-cache cache sample.exe
.build/openssl-linux/PESignAnalyzerOpenSSL --revocation cache \
  --revocation-cache cache sample.exe
```

完整参数查看 --help。还支持 --ca-dir（PEM/DER 根目录）、--crl-file、--crl-dir、
--network-timeout 1..300（每链累计网络预算，默认 10 秒）、--version、--。
--catalog-dir 可重复指定；--embedded-only 与 Catalog 选项冲突。
Catalog 是没有嵌入式签名时的回退。Windows 默认扫描已安装的 CatRoot；
Linux/macOS 需提供 Catalog 或目录，可直接验证从 Windows 复制的文件和 Catalog。
Catalog 的内容类型 1.3.6.1.4.1.311.10.1 表示 CTL，属于正常格式；
其成员摘要不在 SpcIndirectDataContent 中，文本输出不显示 imageDigestAlgorithm 和 embeddedDigest。
JSON 的 digestAlgorithm 和 embeddedDigest 元数据仍为空，验证结果由 verification.contentDigest 表示。

Windows 上默认显示系统文件的签名者完整链及根证书；加上 --verify 执行验证：

```powershell
.\PESignAnalyzerOpenSSL.exe C:\Windows\notepad.exe
.\PESignAnalyzerOpenSSL.exe --verify C:\Windows\notepad.exe
```

Windows 程序位于 .build/openssl-windows/Release/PESignAnalyzerOpenSSL.exe。
CLI 使用宽字符入口，库使用 std::filesystem::path，支持 Unicode 路径。
JSON 非法 UTF-8 字节替换为 Unicode 替换字符；日期为 UTC，时间戳小数秒保留精度。

## 信任和吊销策略

- Windows：当前用户和计算机 ROOT、Disallowed、根证书用途限制。
- Windows HTTPS 在支持 CURLSSLOPT_NATIVE_CA 的 libcurl 上也使用系统 CA，避免依赖
  DLL 原安装目录中的 CA bundle；当前 Windows 发布包已验证该行为。
- macOS：系统锚点及用户、管理员、系统信任设置，应用用途和显式拒绝。
- Linux：OpenSSL 默认 CA 文件/目录，取决于安装环境及 OpenSSL 配置。
- --ca-file / --ca-dir 增加显式根，--no-system-roots 仅使用这些根。
  不把签名内嵌的自签证书自动视为可信。
- 签者链检查代码签名用途；RFC 3161 TSA 叶证书要求唯一的 timeStamping EKU，
  PKCS#9 叶证书也必须允许时间戳用途。兼容 Microsoft 非 critical EKU 的时间戳。
  可信时间戳允许在历史时刻验证签者链。
- Microsoft Authenticode 时间戳 OID 默认使用原 Windows 兼容语义：ESS 第一项必须
  绑定实际 TSA 签名证书，额外 ESS 证书/属性证书引用不强制决定信任。
  此类兼容情况在 details 中明确输出。--strict-timestamps 要求全部额外引用满足约束，
  不匹配或无法验证时失败。标准 RFC 3161 时间戳 OID 始终执行严格 ESS 检查。
- none 不查吊销、不联网、不读取本工具的中间证书缓存；
  cache 读取本地 CRL/OCSP 和缓存中间证书、不联网；
  online 允许 AIA 补链及 CRL/OCSP 请求，保存经验证的响应。
- CRL 优先，无法给出状态时使用 OCSP；校验证书标识、签名、授权、有效期和状态。
  缺失、过期、不可信或无法处理的响应返回 unknown；要求吊销检查时汇总为
  indeterminate。确认吊销为 revoked，汇总为 invalid。certificateChain 的
  trusted 表示路径信任，吊销状态单独输出。
- 缓存属于本工具，不直接复用 CryptoAPI 缓存。默认 Windows
  %LOCALAPPDATA%/PESignAnalyzer/revocation、macOS
  ~/Library/Caches/PESignAnalyzer/revocation、Linux
  $XDG_CACHE_HOME/PESignAnalyzer/revocation 或 ~/.cache/PESignAnalyzer/revocation。

各平台根库和策略不同，结果不保证逐位等同 Windows Authenticode 策略。
Linux/macOS CA 集合可能缺少 Microsoft 根；通过 --ca-file 提供明确受信任的根，
不应直接把全部内嵌证书当作根导入。

## 输出及库 API

JSON schemaVersion 为 2，parseStatus 为 ok 或 partial。
顶层 verification 是汇总字符串；verificationResult 包含 contentDigest、
cmsSignature、certificateChain、timestamp、revocation、overall、errorCode、
verificationTime、实际 chain 及 details。
每个 signature/signer 都有独立结果，汇总取第一条主签名的第一个签者。
未验证时 verification 为 not_performed，退出 0 仅表示解析成功。

signers[].certificateChain 包含 status、certificates、details。certificates 按叶证书、
中间证书、根证书排列，并包含完整的主题、发行者、序列号、指纹、有效期及 CRL 地址。
built 表示链到达经自签名确认的根；partial 表示发行者缺失或达到限制；
unavailable 表示无法获取签名者证书。构链状态不代表信任，不检查有效期、用途、吊销或签名文件摘要。
此过程只读取本地来源，不下载证书。--verify 的信任结论仍位于 verification.certificateChain，
通过在线 AIA 补齐的链位于 verification.chain。

signatures[].certificateRecord 指向记录；parentSignature、parentSigner 标识
嵌套来源，顶层为 -1；signers[].certificateIndex 指向该消息的证书集合。
读取、PE 结构、解析或验证失败返回 3；无签名返回 1；无法确认吊销状态返回 4。

```cpp
#include <pesign/analyzer.h>
#include <iostream>

pesign::Options options;
options.verify = true;
options.ca_file = "roots.pem";
auto result = pesign::analyze_file("sample.exe", options);
std::cout << pesign::to_json(result) << '\n';
```

链接 CMake 目标 pesign::openssl，或安装后的静态库及 OpenSSL、libcurl 和平台信任库。
公开头文件不暴露 OpenSSL 或 Windows 类型。文件重载及带 Options 的字节重载默认离线构链；
Options 可配置 Catalog、根、CRL、缓存及库级验证时间。
analyze_bytes(bytes) 只解析嵌入式元数据，不读取本地证书库，其 certificateChain.status 为 not_built。

## 测试与边界

pe_reader_tests.cpp 检查 PE32/PE32+、目录、节和证书表边界。
pkcs7_tests.cpp 检查真实 ASN.1、证书匹配、嵌套、两类时间戳、资源限制。
verification_tests.cpp 生成根、中间证书、签者/TSA、PE、Catalog、CRL/OCSP，
覆盖离线根证书补齐、链不完整、多签者/嵌套构链，以及正确结果、篡改、过期、用途错误、不可信根、错误成员和时间戳绑定。
可选 Python 使用本地 HTTP 服务检查 AIA、CRL、OCSP、缓存及断网行为，
不依赖外部 CA 服务或系统信任库。CI 配置包括 Windows x64/x86、Linux、macOS。

| 源文件 | 职责 |
|---|---|
| pe_reader.cpp / pkcs7_parser.cpp | 有界 PE 和签名元数据 |
| digest.cpp / catalog.cpp | PE 摘要、CTL 成员、Catalog 查找 |
| verification.cpp | 签名、时间戳、逐签者汇总 |
| trust.cpp / network.cpp | 信任来源、构链、吊销、缓存、HTTP |
| report.cpp / main.cpp | 文本/JSON、CLI 和退出码 |

输入上限 1 GiB、4096 记录；单条 PKCS#7 最大 64 MiB、嵌套深度 8，
签名总数 64、每条 128 签者和 512 证书、每签者 64 时间戳。
解析元数据预算 16 MiB（最坏 JSON 转义估算），字段最大 4 KiB。
Catalog 扫描最多 100000 文件；网络仅 HTTP/HTTPS、最多 3 次重定向、
每链最多 32 请求，响应大小及累计时间受限。文件当前整体读取。
支持完整 direct IDP 范围和 base/delta CRL 配对、freshestCRL 检索及认证的 hold/release。
分区理由、间接 CRL 或无法安全确认的扩展返回 unknown。

格式依据：[Microsoft PE Format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)、
[Authenticode 时间戳](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures)、
[OpenSSL 证书链验证](https://docs.openssl.org/3.0/man3/X509_verify_cert/)。

## English overview

An independent C++17 / OpenSSL 3 / libcurl PE Authenticode analyzer and verifier.
It supports embedded/catalog signatures, multiple/nested signers, image integrity,
cryptographic signatures, RFC 3161/PKCS#9 timestamps, certificate chains, and
cached/online CRL/OCSP. Native APIs supply Windows/macOS trust settings; OpenSSL
performs verification. Use --verify to validate and --ca-file for explicit roots.
JSON schema 2 separates metadata from verdicts. Default file analysis resolves
local signer chains, including available roots, without network or trust validation.
