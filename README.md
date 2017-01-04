# PESignAnalyzer

This program is used to get signature information from PE files which signed by a/some certificate(s). Supporting multi-signed &amp; cert-chain. Runned on Windows 7+ OS.

This code uses CryptoAPI to parse the signature and certificate data from specified file, including .exe, .cat(catalog file), .dll, .sys, etc.

这个程序用来从由1个/多个证书签名的PE文件中获取签名信息。支持多签名；支持证书链的提取。运行在Windows7及以上的操作系统平台。

这份代码使用CryptoAPI来解析指定文件中的签名和证书数据，包括exe，cat（catalog文件），dll，sys等格式文件。

## Running Demo

运行演示

```
D:\GitHub\PESignAnalyzer\Debug>PESignAnalyzer_vs2013.exe C:\Windows\notepad.exe
filepath: C:\Windows\notepad.exe
signtype: cataloged
catafile: C:\WINDOWS\system32\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\Microsoft-Windows-Client-Features-Package-AutoMerged-shell~31bf3856ad364e35~amd64~~10.0.14393.0.cat
-----------------------
[ The 1 Sign Info ]
version:         V2
digestAlgorithm: SHA256
 |---------------------
 |- subject:       Microsoft Windows
 |- issuer:        Microsoft Windows Production PCA 2011
 |- serial:        33000000bce120fdd27cc8ee930000000000bc
 |- thumbprint:    e85459b23c232db3cb94c7a56d47678f58e8e51e
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2015/08/18 17:15:28
 |- notafter:      2016/11/18 17:15:28
 |- CRLpoint:      http://www.microsoft.com/pkiops/crl/MicWinProPCA2011_2011-10-19.crl
 |---------------------
 |- subject:       Microsoft Windows Production PCA 2011
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        61077656000000000008
 |- thumbprint:    580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2011/10/19 18:41:42
 |- notafter:      2026/10/19 18:51:42
 |- CRLpoint:      http://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl
 |---------------------
 |- subject:       Microsoft Root Certificate Authority 2010
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        28cc3a25bfba44ac449a9b586b4339aa
 |- thumbprint:    3b1efd3a66ea28b16697394703a72ca340a05bd5
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2010/06/23 21:57:24
 |- notafter:      2035/06/23 22:04:01
 |- CRLpoint:
-----------------------

```

## Compile

编译

Developer can compile this program with Microsoft Visual Studio 2008 or later version Visual Studio. The target binary file will be built at Debug or Release folder, depending on which compiling method developers select.

开发者可以通过Microsoft Visual Studio 2008或更新版本的Visual Studio来编译这个程序。目标二进制文件会在Debug或Release目录生成，这取决于开发者选择何种编译方式。

## Multi-signatured Supporting

多签名支持

This code does not use the `WinVerifyTrust` to verify and get the signature and certificate information, but uses `CryptoAPIs` instead.

It might also be noted that this program supports analyzing multi-signatured PE file, even thought on the OS platforms not supporting multi-signature detection, such as Windows 7, Windows Vista, etc. Multi-signatured PE file means that this file has been signatured by more than one embedded signature certificate.

If you transfer the path of a multi-signatured file to PESignAnalyzer binary file, it will show information as shown below. Every `[The X Sign Info]` means a chunk of completed information of a signature.

这份代码没有使用`WinVerifyTrust`来验证和获取签名证书信息，而是用`CryptoAPIs`来代替。

需要注意的是，这个程序支持解析多签名的PE文件，即使是在诸如Windows 7，Windows Vista这种不支持多签名检测的操作系统平台上。多签名的PE文件意味着这个文件已经被多个嵌入式代码签名证书所签名了。

```
D:\GitHub\PESignAnalyzer\Debug>PESignAnalyzer_vs2013.exe D:\sign_samples\multi_sign\sample.sys
filepath: D:\sign_samples\multi_sign\sample.sys
signtype: embedded
catafile:
-----------------------
[ The 1 Sign Info ]
version:         V2
digestAlgorithm: SHA1
 |---------------------
 |- subject:       Future Technology Devices International Ltd
 |- issuer:        VeriSign Class 3 Code Signing 2010 CA
 |- serial:        03c3ce928ee0415b782a96d3fb5dc283
 |- thumbprint:    055ef6258c59fe21f14d9fa938da92f345e7eb9d
 |- signAlgorithm: sha1RSA(RSA)
 |- version:       V3
 |- notbefore:     2013/09/18 00:00:00
 |- notafter:      2016/11/16 23:59:59
 |- CRLpoint:      http://csc3-2010-crl.verisign.com/CSC3-2010.crl
 |---------------------
 |- subject:       VeriSign Class 3 Code Signing 2010 CA
 |- issuer:        VeriSign Class 3 Public Primary Certification Authority - G5
 |- serial:        5200e5aa2556fc1a86ed96c9d44b33c7
 |- thumbprint:    495847a93187cfb8c71f840cb7b41497ad95c64f
 |- signAlgorithm: sha1RSA(RSA)
 |- version:       V3
 |- notbefore:     2010/02/08 00:00:00
 |- notafter:      2020/02/07 23:59:59
 |- CRLpoint:      http://crl.verisign.com/pca3-g5.crl
 |---------------------
 |- subject:       VeriSign Class 3 Public Primary Certification Authority - G5
 |- issuer:        VeriSign Class 3 Public Primary Certification Authority - G5
 |- serial:        18dad19e267de8bb4a2158cdcc6b3b4a
 |- thumbprint:    4eb6d578499b1ccf5f581ead56be3d9b6744a5e5
 |- signAlgorithm: sha1RSA(RSA)
 |- version:       V3
 |- notbefore:     2006/11/08 00:00:00
 |- notafter:      2036/07/16 23:59:59
 |- CRLpoint:
-----------------------
[ The 2 Sign Info ]
version:         V2
digestAlgorithm: SHA256
 |---------------------
 |- subject:       Microsoft Windows Hardware Compatibility Publisher
 |- issuer:        Microsoft Windows Third Party Component CA 2012
 |- serial:        330000001dc31a761624754f8000000000001d
 |- thumbprint:    96c51247e27dae45a1bcd582a0503256f9eaedac
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2014/12/19 19:27:34
 |- notafter:      2016/03/19 19:27:34
 |- CRLpoint:      http://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202012.crl
 |---------------------
 |- subject:       Microsoft Windows Third Party Component CA 2012
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        610baac1000000000009
 |- thumbprint:    77a10ebf07542725218cd83a01b521c57bc67f73
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2012/04/18 23:48:38
 |- notafter:      2027/04/18 23:58:38
 |- CRLpoint:      http://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl
 |---------------------
 |- subject:       Microsoft Root Certificate Authority 2010
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        28cc3a25bfba44ac449a9b586b4339aa
 |- thumbprint:    3b1efd3a66ea28b16697394703a72ca340a05bd5
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2010/06/23 21:57:24
 |- notafter:      2035/06/23 22:04:01
 |- CRLpoint:
-----------------------
[ The 3 Sign Info ]
version:         V2
digestAlgorithm: SHA256
 |---------------------
 |- subject:       Microsoft Windows Hardware Compatibility Publisher
 |- issuer:        Microsoft Windows Third Party Component CA 2012
 |- serial:        330000001dc31a761624754f8000000000001d
 |- thumbprint:    96c51247e27dae45a1bcd582a0503256f9eaedac
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2014/12/19 19:27:34
 |- notafter:      2016/03/19 19:27:34
 |- CRLpoint:      http://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202012.crl
 |---------------------
 |- subject:       Microsoft Windows Third Party Component CA 2012
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        610baac1000000000009
 |- thumbprint:    77a10ebf07542725218cd83a01b521c57bc67f73
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2012/04/18 23:48:38
 |- notafter:      2027/04/18 23:58:38
 |- CRLpoint:      http://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl
 |---------------------
 |- subject:       Microsoft Root Certificate Authority 2010
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        28cc3a25bfba44ac449a9b586b4339aa
 |- thumbprint:    3b1efd3a66ea28b16697394703a72ca340a05bd5
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2010/06/23 21:57:24
 |- notafter:      2035/06/23 22:04:01
 |- CRLpoint:
-----------------------
[ The 4 Sign Info ]
version:         V2
digestAlgorithm: SHA256
 |---------------------
 |- subject:       Microsoft Windows Hardware Compatibility Publisher
 |- issuer:        Microsoft Windows Third Party Component CA 2012
 |- serial:        330000001dc31a761624754f8000000000001d
 |- thumbprint:    96c51247e27dae45a1bcd582a0503256f9eaedac
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2014/12/19 19:27:34
 |- notafter:      2016/03/19 19:27:34
 |- CRLpoint:      http://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202012.crl
 |---------------------
 |- subject:       Microsoft Windows Third Party Component CA 2012
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        610baac1000000000009
 |- thumbprint:    77a10ebf07542725218cd83a01b521c57bc67f73
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2012/04/18 23:48:38
 |- notafter:      2027/04/18 23:58:38
 |- CRLpoint:      http://crl.microsoft.com/pki/crl/products/MicRooCerAut_2010-06-23.crl
 |---------------------
 |- subject:       Microsoft Root Certificate Authority 2010
 |- issuer:        Microsoft Root Certificate Authority 2010
 |- serial:        28cc3a25bfba44ac449a9b586b4339aa
 |- thumbprint:    3b1efd3a66ea28b16697394703a72ca340a05bd5
 |- signAlgorithm: sha256RSA(RSA)
 |- version:       V3
 |- notbefore:     2010/06/23 21:57:24
 |- notafter:      2035/06/23 22:04:01
 |- CRLpoint:
-----------------------

```
