# FetchSignFromPE

This program is used to get signature information from PE files which signed by a/some certificate(s). Supporting multi-signed &amp; cert-chain. Runned on Windows 7+ OS.

This code uses CryptoAPI to parse the signature and certificate data from specified file, including .exe, .cat(catalog file), .dll, .sys, etc.

这个程序用来从由1个/多个证书签名的PE文件中获取签名信息。支持多签名；支持证书链的提取。运行在Windows7及以上的操作系统平台。

这份代码使用CryptoAPI来解析指定文件中的签名和证书数据，包括exe，cat（catalog文件），dll，sys等格式文件。
