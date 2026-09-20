# PESignAnalyzer

[English](README.md)

PESignAnalyzer 是一个用于分析和验证 Windows PE 文件 Authenticode 签名的
命令行工具。它支持嵌入式签名和 Catalog 目录签名，并能自动查找系统中已经安装
的 Catalog。

验证流程**不会导入或调用 `Wintrust.dll` 中的任何 API**。PE 摘要计算、Catalog
成员查找、CMS 签名校验、时间戳验证、证书链构建以及可选的吊销检查，均由 PE
结构解析及 Kernel32、Crypt32、Advapi32 提供的 API 完成。

## 当前进展

当前版本：**1.3.0**

| 功能 | 状态 |
|---|---|
| 嵌入式 Authenticode 元数据解析 | 已支持 |
| 多签名及嵌套签名元数据解析 | 已支持 |
| 自动查找系统 Catalog | 已支持，且不使用 WinTrust |
| 显式指定 Catalog | 已支持，使用 `--catalog` |
| Authenticode 内容摘要验证 | 已支持 |
| CMS/PKCS#7 签名验证 | 已支持 |
| RFC 3161 时间戳 | 已支持 |
| 旧式 PKCS#9 countersignature | 已支持 |
| 证书链策略验证 | 已支持 |
| 缓存或在线吊销检查 | 已支持 |
| x86、x64 发布二进制 | 已包含在 `dist/` 中 |

发布二进制已经检查，导入表中只有 `kernel32.dll`、`crypt32.dll` 和
`advapi32.dll`。

## 验证原理

PESignAnalyzer 不使用 `WinVerifyTrust` 或 `CryptCATAdmin*`，验证流程如下：

1. 解析 PE 头并计算 Authenticode 镜像摘要，排除校验和字段、安全目录项以及
   证书表。
2. 对嵌入式签名，从 PKCS#7 内容中提取已签名摘要，并与计算结果比较。
3. 对 Catalog 签名，计算候选摘要，扫描 Windows CatRoot，解析 Catalog DER
   成员并查找匹配的成员摘要。
4. 使用 `CryptMsgControl` 和 `CMSG_CTRL_VERIFY_SIGNATURE_EX` 验证 CMS 签名者。
5. 验证 RFC 3161 时间戳或旧式 countersignature。
6. 构建签名证书链和时间戳证书链，并应用 Authenticode 证书链策略。
7. 根据选项使用本地缓存或在线 CRL/OCSP 执行吊销检查。

自动查找时先使用轻量 DER 成员摘要筛选，再确认摘要确实存在于候选项的 CMS
内容中；启用 `--verify` 后还会验证该候选项的 CMS 签名和证书链。由于不使用
Windows WinTrust Catalog 索引，首次扫描或没有匹配项时会比系统索引查询更慢。

## 命令行

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

原有的仅分析元数据调用方式保持兼容：

```powershell
.\dist\bin_x64.exe "C:\Program Files\Git\cmd\git.exe"
```

验证嵌入式签名：

```powershell
.\dist\bin_x64.exe --verify `
  "C:\Program Files\Git\cmd\git.exe"
```

自动查找并验证系统文件对应的 Catalog：

```powershell
.\dist\bin_x64.exe --verify `
  "C:\Windows\System32\notepad.exe"
```

显式指定 Catalog：

```powershell
.\dist\bin_x64.exe --verify `
  --catalog "C:\Windows\System32\CatRoot\{GUID}\package.cat" `
  "C:\Windows\System32\notepad.exe"
```

启用在线吊销检查（`--revocation` 隐含启用 `--verify`）：

```powershell
.\dist\bin_x64.exe --revocation online `
  "C:\Windows\System32\notepad.exe"
```

在 PowerShell 中，用于续行的反引号必须是该行最后一个字符。

## 验证输出

| 字段 | 含义 |
|---|---|
| `contentDigest` | PE 摘要与嵌入式签名或 Catalog 成员记录匹配 |
| `cmsSignature` | CMS/PKCS#7 密码学签名有效 |
| `certificateChain` | 签名证书链满足所选 Authenticode 策略 |
| `timestamp` | RFC 3161 或旧式时间戳有效 |
| `revocation` | `not_checked`、`good`、`revoked` 或 `unknown` |
| `overall` | `valid`、`invalid` 或 `indeterminate` |

`indeterminate` 表示密码学签名和证书链可能有效，但无法确认所要求的吊销状态。
在严格安全策略中，不能把它视为等同于 `valid`。

## 退出码

| 代码 | 含义 |
|---:|---|
| `0` | 分析或验证成功 |
| `1` | 未找到可读取的签名 |
| `2` | 命令行参数错误 |
| `3` | 签名验证失败 |
| `4` | 验证结果无法确定 |

## 编译

推荐使用 CMake 作为统一构建入口。以下命令可在 Visual Studio 开发人员命令
提示符中重新生成 `dist/` 内发布的两个可执行文件：

```cmd
cmake -S . -B .build\cmake-x64 -A x64
cmake --build .build\cmake-x64 --config Release --parallel
copy /Y .build\cmake-x64\Release\PESignAnalyzer.exe dist\bin_x64.exe

cmake -S . -B .build\cmake-x86 -A Win32
cmake --build .build\cmake-x86 --config Release --parallel
copy /Y .build\cmake-x86\Release\PESignAnalyzer.exe dist\bin_x86.exe
```

仓库仍在 `msvc/` 目录保留旧版 Visual C++ 工程文件：

- `msvc/vs2013.vcxproj`
- `msvc/vs2015.vcxproj`

MSBuild 示例：

```cmd
MSBuild msvc\vs2015.vcxproj /p:Configuration=Release /p:Platform=x64
MSBuild msvc\vs2015.vcxproj /p:Configuration=Release /p:Platform=Win32
```

实现代码按职责放在 `src/`，公开 API 位于 `include/analyzer/`。模块划分
与依赖边界详见 [docs/architecture.md](docs/architecture.md)。两套构建系统都会链接
`Crypt32.lib` 和 `Advapi32.lib`，不需要、也不会链接 `Wintrust.lib`。

## 测试

可以分别对 `dist/` 中的两个发布架构运行冒烟测试：

```powershell
.\tests\smoke.ps1 -Executable .\dist\bin_x64.exe
.\tests\smoke.ps1 -Executable .\dist\bin_x86.exe
```

测试覆盖命令行行为、嵌入式签名验证、篡改检测、Catalog 自动查找、Catalog
验证以及 `--embedded-only` 行为。

## 当前限制

- 因为刻意不使用 WinTrust 索引，Catalog 自动查找需要扫描本机 Windows
  CatRoot；冷扫描或没有匹配项时耗时可能更长。
- 自动发现仅检查本机已经安装的系统 Catalog。其他 Catalog 文件需要通过
  `--catalog` 指定。
- 吊销检查依赖本机缓存、网络环境以及 CA 的 CRL/OCSP 可用性；无法获取状态时
  会返回 `indeterminate`。
- 元数据分析支持多签名及嵌套签名；当前验证汇总针对消息中选定的主签名者。
- 本项目定位为诊断工具。在把它用作安全强制边界前，应结合部署环境的安全要求
  和签名样本进行验证。

## 许可证

[MIT](LICENSE)

## 联系方式

leeq.live@outlook.com
