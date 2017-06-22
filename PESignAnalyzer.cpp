/**
 * COPYRIGHT NOTICE & DESCRIPTION
 *
 * Source: PESignAnalyzer.cpp
 * Author: leeqwind
 * E-mail: leeqwind123@outlook.com
 * Notice: This program can retrieve signature information from PE
 *         files which signed by a/some certificate(s) on Windows.
 *         Supporting multi-signed info and certificates chain.
 */

#include <Windows.h>
#include <WinTrust.h>
#include <list>
#include <Mscat.h>
#include <SoftPub.h>
#include <strsafe.h>
#include <WinCrypt.h>

#include <math.h>
#include <map>
#include <algorithm>
#include <string>
#include <iostream>

using namespace std;

#define MY_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#ifndef szOID_RFC3161_counterSign
#define szOID_RFC3161_counterSign "1.3.6.1.4.1.311.3.3.1"
#endif
#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE    "1.3.6.1.4.1.311.2.4.1"
#endif

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Wintrust.lib")

typedef struct _SIGN_COUNTER_SIGN {
    std::string signerName;
    std::string mailAddress;
    std::string timeStamp;
} SIGN_COUNTER_SIGN, *PSIGN_COUNTER_SIGN;

// 针对证书链中每个证书的节点
typedef struct _CERT_NODE_INFO {
    std::string subjectName;
    std::string issuerName;
    std::string version;
    std::string serial;
    std::string thumbprint;
    std::string notbefore;
    std::string notafter;
    std::string signAlgorithm;
    std::wstring CRLpoint;
} CERT_NODE_INFO, *PCERT_NODE_INFO;

// 针对多签名中每个签名的节点
typedef struct _SIGN_NODE_INFO {
    std::string digestAlgorithm;
    std::string version;
    SIGN_COUNTER_SIGN CounterSign;
    std::list<CERT_NODE_INFO> CertNodeChain;
} SIGN_NODE_INFO, *PSIGN_NODE_INFO;

BOOL CheckFileDigitalSignature(LPCWSTR filePath, BOOL bNoRevocation,
    LPCWSTR CatalogPath,
    std::wstring & catFile,
    std::string & signType,
    std::list<SIGN_NODE_INFO> & signChain);

BOOL CertificateCheck(CONST WCHAR *szCurrFullPath)
{
    std::string     signType;
    std::wstring    cataFile;
    std::wstring    imagePath;
    std::list<SIGN_NODE_INFO> signChain;

    imagePath = szCurrFullPath;
    BOOL bReturn = CheckFileDigitalSignature(imagePath.c_str(), TRUE,
        NULL,
        cataFile,
        signType,
        signChain);
    std::wcout << L"filepath: " << imagePath << endl;
    if (!bReturn)
    {
        std::cout << "signtype: " << "none" << endl;
        return FALSE;
    }
    std::cout  << "signtype: "  << signType << endl;
    std::wcout << L"catafile: " << cataFile << endl;
    std::cout  << "-----------------------" << endl;
    UINT idx = 0;
    std::list<SIGN_NODE_INFO>::iterator iter;
    for (iter = signChain.begin(); iter != signChain.end(); iter++)
    {
        std::cout << "[ The " << ++idx << " Sign Info ]" << endl;
        std::cout << "timestamp:       " << iter->CounterSign.timeStamp << endl;
        std::cout << "version:         " << iter->version << endl;
        std::cout << "digestAlgorithm: " << iter->digestAlgorithm << endl;

        std::list<CERT_NODE_INFO>::iterator iter1;
        for (iter1 = iter->CertNodeChain.begin();
            iter1 != iter->CertNodeChain.end(); iter1++)
        {
            std::cout  <<  " |--"  << "-------------------" << endl;
            std::cout  <<  " |- "  <<  "subject:       " << iter1->subjectName << endl;
            std::cout  <<  " |- "  <<  "issuer:        " << iter1->issuerName << endl;
            std::cout  <<  " |- "  <<  "serial:        " << iter1->serial << endl;
            std::cout  <<  " |- "  <<  "thumbprint:    " << iter1->thumbprint << endl;
            std::cout  <<  " |- "  <<  "signAlgorithm: " << iter1->signAlgorithm << endl;
            std::cout  <<  " |- "  <<  "version:       " << iter1->version << endl;
            std::cout  <<  " |- "  <<  "notbefore:     " << iter1->notbefore << endl;
            std::cout  <<  " |- "  <<  "notafter:      " << iter1->notafter << endl;
            std::wcout << L" |- "  << L"CRLpoint:      " << iter1->CRLpoint << endl;
        }
        std::cout << "-----------------------" << endl;
    }
    return TRUE;
}

BOOL MyCryptMsgGetParam(HCRYPTMSG hCryptMsg, DWORD dwParamType,
    DWORD dwIndex,
    PVOID *pParam,
    DWORD *dwOutSize)
{
    DWORD dwSize = 0;
    if (!pParam)
    {
        return FALSE;
    }
    // Get size
    if (!CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, NULL, &dwSize))
    {
        return FALSE;
    }
    // Alloc memory via size
    *pParam = (PVOID)LocalAlloc(LPTR, dwSize);
    if (!*pParam)
    {
        return FALSE;
    }
    // Get data to alloced memory
    if (!CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, *pParam, &dwSize))
    {
        return FALSE;
    }
    if (dwOutSize)
    {
        *dwOutSize = dwSize;
    }
    return TRUE;
}

typedef struct _SIGNDATA_HANDLE {
    HCERTSTORE hCertStore;
    DWORD      dwObjSize;
    PCMSG_SIGNER_INFO pSignerInfo;
} SIGNDATA_HANDLE, *PNESTED_HANDLE;

CONST UCHAR SG_ProtoCoded[] = {
    0x30, 0x82,
};

CONST UCHAR SG_SignedData[] = {
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02,
};

#define XCH_WORD_LITEND(num) \
    (WORD)(((((WORD)num) & 0xFF00) >> 8) | ((((WORD)num) & 0x00FF) << 8))

#define _8BYTE_ALIGN(offset, base) \
    (((offset + base + 7) & 0xFFFFFFF8L) - (base & 0xFFFFFFF8L))

// https://msdn.microsoft.com/zh-cn/library/windows/desktop/aa374890(v=vs.85).aspx
BOOL GetNestedSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, DWORD cbSignerSize,
    std::list<SIGNDATA_HANDLE> & NestedChain)
{
    BOOL        bReturn     = FALSE;
    HCRYPTMSG   hNestedMsg  = NULL;
    DWORD       n           = 0x00;
    PBYTE       pbCurrData  = NULL;
    PBYTE       pbNextData  = NULL;
    DWORD       cbCurrData  = 0x00;

    if (!pSignerInfo)
    {
        return FALSE;
    }
    __try
    {
        // Traverse and look for a nested signature.
        for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
        {
            if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                szOID_NESTED_SIGNATURE) == 0)
            {
                break;
            }
        }
        // Cannot find a nested signature attribute.
        if (n >= pSignerInfo->UnauthAttrs.cAttr)
        {
            __leave;
        }
        pbCurrData = pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData;
        cbCurrData = pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData;
        // Multiple nested signatures just add one attr in UnauthAttrs
        // list of the main signature pointing to the first nested si-
        // gnature. Every nested signature exists side by side in an 8
        // bytes aligned way. According to the size of major signature
        // parse the nested signatures one by one.
        while (pbCurrData > (BYTE *)pSignerInfo &&
            pbCurrData < (BYTE *)pSignerInfo + cbSignerSize)
        {
            SIGNDATA_HANDLE NestedHandle = { 0 };
            hNestedMsg = NULL;
            // NOTE: The size in 30 82 xx doesnt contain its own size.
            // HEAD:
            // 0000: 30 82 04 df                ; SEQUENCE (4df Bytes)
            // 0004:    06 09                   ; OBJECT_ID(9 Bytes)
            // 0006:    |  2a 86 48 86 f7 0d 01 07  02
            //          |     ; 1.2.840.113549.1.7.2 PKCS 7 SignedData
            if (memcmp(pbCurrData + 0, SG_ProtoCoded, sizeof(SG_ProtoCoded)) ||
                memcmp(pbCurrData + 6, SG_SignedData, sizeof(SG_SignedData)))
            {
                break;
            }
            hNestedMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                0,
                0,
                NULL, 0);
            if (!hNestedMsg)
            {
                break; // Fatal Error
            }
            // Big Endian -> Little Endian
            cbCurrData = XCH_WORD_LITEND(*(WORD *)(pbCurrData + 2)) + 4;
            pbNextData = pbCurrData;
            pbNextData += _8BYTE_ALIGN(cbCurrData, (ULONG_PTR)pbCurrData);
            if (!CryptMsgUpdate(hNestedMsg, pbCurrData, cbCurrData, TRUE))
            {
                CryptMsgClose(hNestedMsg);
                hNestedMsg = NULL;
                pbCurrData = pbNextData;
                continue;
            }
            if (!MyCryptMsgGetParam(hNestedMsg, CMSG_SIGNER_INFO_PARAM,
                0,
                (PVOID *)&NestedHandle.pSignerInfo,
                &NestedHandle.dwObjSize))
            {
                CryptMsgClose(hNestedMsg);
                hNestedMsg = NULL;
                pbCurrData = pbNextData;
                continue;
            }
            NestedHandle.hCertStore = CertOpenStore(CERT_STORE_PROV_MSG,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                0,
                0,
                hNestedMsg);
            NestedChain.push_back(NestedHandle);
            CryptMsgClose(hNestedMsg);
            hNestedMsg = NULL;
            pbCurrData = pbNextData;
            bReturn = TRUE;
        }
    }
    __finally
    {
        if (hNestedMsg) CryptMsgClose(hNestedMsg);
    }
    return bReturn;
}

BOOL GetAuthedAttribute(PCMSG_SIGNER_INFO pSignerInfo)
{
    BOOL    bReturn    = FALSE;
    DWORD   dwObjSize  = 0x00;
    DWORD   n          = 0x00;

    __try
    {
        for (n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
        {
            if (lstrcmpA(pSignerInfo->AuthAttrs.rgAttr[n].pszObjId,
                szOID_RSA_counterSign) == 0)
            {
                break;
            }
        }
        bReturn = TRUE;
    }
    __finally
    {
    }
    return bReturn;
}

// http://support.microsoft.com/kb/323809
BOOL GetCounterSignerInfo(PCMSG_SIGNER_INFO pSignerInfo, PCMSG_SIGNER_INFO *pTargetSigner)
{
    BOOL    bReturn    = FALSE;
    DWORD   dwObjSize  = 0x00;
    DWORD   n          = 0x00;

    if (!pSignerInfo || !pTargetSigner)
    {
        return FALSE;
    }
    __try
    {
        *pTargetSigner = NULL;
        for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
        {
            if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                szOID_RSA_counterSign) == 0)
            {
                break;
            }
        }
        if (n >= pSignerInfo->UnauthAttrs.cAttr)
        {
            __leave;
        }
        if (!CryptDecodeObject(MY_ENCODING,
            PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            NULL,
            &dwObjSize))
        {
            __leave;
        }
        *pTargetSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwObjSize);
        if (!*pTargetSigner)
        {
            __leave;
        }
        if (!CryptDecodeObject(MY_ENCODING,
            PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            (PVOID)*pTargetSigner,
            &dwObjSize))
        {
            __leave;
        }
        bReturn = TRUE;
    }
    __finally
    {
    }
    return bReturn;
}

std::string TimeToString(FILETIME *pftIn, SYSTEMTIME *pstIn = NULL)
{
    SYSTEMTIME st;
    CHAR szBuffer[256] = { 0 };

    if (!pstIn)
    {
        if (!pftIn)
        {
            return std::string("");
        }
        FileTimeToSystemTime(pftIn, &st);
        pstIn = &st;
    }
    _snprintf_s(szBuffer, 256, "%04d/%02d/%02d %02d:%02d:%02d",
        pstIn->wYear,
        pstIn->wMonth,
        pstIn->wDay,
        pstIn->wHour,
        pstIn->wMinute,
        pstIn->wSecond);
    return std::string(szBuffer);
}

BOOL GetCounterSignerData(PCMSG_SIGNER_INFO pSignerInfo, std::string & signerName,
    std::string & timeStamp,
    std::string & emailAddr)
{
    BOOL        bReturn = FALSE;
    DWORD       n       = 0x00;
    DWORD       dwData  = 0x00;
    FILETIME    lft, ft;
    SYSTEMTIME  st;

    // 循环遍历认证属性并查找 szOID_RSA_signingTime OID.
    for (n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
    {
        if (lstrcmpA(pSignerInfo->AuthAttrs.rgAttr[n].pszObjId,
            szOID_RSA_signingTime) == 0)
        {
            break;
        }
    }
    if (n >= pSignerInfo->AuthAttrs.cAttr)
    {
        return bReturn;
    }
    // 解码并获得 FILETIME 结构体.
    dwData = sizeof(ft);
    if (!CryptDecodeObject(MY_ENCODING,
        szOID_RSA_signingTime,
        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
        pSignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
        0,
        (PVOID)&ft,
        &dwData))
    {
        return bReturn;
    }
    // 转换成本地时间.
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    timeStamp = TimeToString(NULL, &st);
    bReturn = TRUE;
    return bReturn;
}

BOOL SafeToReadNBytes(DWORD dwSize, DWORD dwStart, DWORD dwRequestSize)
{
    return dwSize - dwStart >= dwRequestSize;
}

void ParseDERType(BYTE bIn, INT & iType, INT & iClass)
{
    iType = bIn & 0x3F;
    iClass = bIn >> 6;
}

DWORD ReadNumberFromNBytes(PBYTE pbSignature, DWORD dwStart, DWORD dwRequestSize)
{
    DWORD dwNumber = 0;
    for (DWORD i = 0; i < dwRequestSize; i++)
    {
        dwNumber = dwNumber * 0x100 + pbSignature[dwStart + i];
    }
    return dwNumber;
}

BOOL ParseDERSize(PBYTE pbSignature, DWORD dwSize, DWORD & dwSizefound, DWORD & dwBytesParsed)
{
    if (pbSignature[0] > 0x80 &&
        !SafeToReadNBytes(dwSize, 1, pbSignature[0] - 0x80))
    {
        return FALSE;
    }
    if (pbSignature[0] <= 0x80)
    {
        dwSizefound = pbSignature[0];
        dwBytesParsed = 1;
    }
    else
    {
        dwSizefound = ReadNumberFromNBytes(pbSignature, 1, pbSignature[0] - 0x80);
        dwBytesParsed = 1 + pbSignature[0] - 0x80;
    }
    return TRUE;
}

BOOL ParseDERFindType(int iTypeSearch, PBYTE pbSignature, DWORD dwSize,
    DWORD & dwPositionFound,
    DWORD & dwLengthFound,
    DWORD & dwPositionError,
    INT & iTypeError)
{
    INT     iType           = 0;
    INT     iClass          = 0;
    DWORD   dwPosition      = 0;
    DWORD   dwSizeFound     = 0;
    DWORD   dwBytesParsed   = 0;

    dwPositionFound = 0;
    dwLengthFound = 0;
    dwPositionError = 0;
    iTypeError = -1;
    if (NULL == pbSignature)
    {
        iTypeError = -1;
        return FALSE;
    }
    while (dwSize > dwPosition)
    {
        if (!SafeToReadNBytes(dwSize, dwPosition, 2))
        {
            dwPositionError = dwPosition;
            iTypeError = -2;
            return FALSE;
        }
        ParseDERType(pbSignature[dwPosition], iType, iClass);
        switch (iType)
        {
        case 0x05: // NULL
            dwPosition++;
            if (pbSignature[dwPosition] != 0x00)
            {
                dwPositionError = dwPosition;
                iTypeError = -4;
                return FALSE;
            }
            dwPosition++;
            break;

        case 0x06: // OID
            dwPosition++;
            if (!SafeToReadNBytes(dwSize - dwPosition, 1, pbSignature[dwPosition]))
            {
                dwPositionError = dwPosition;
                iTypeError = -5;
                return FALSE;
            }
            dwPosition += 1 + pbSignature[dwPosition];
            break;

        case 0x00: // ?
        case 0x01: // boolean
        case 0x02: // integer
        case 0x03: // bit std::string
        case 0x04: // octec std::string
        case 0x0A: // enumerated
        case 0x0C: // UTF8string
        case 0x13: // printable std::string
        case 0x14: // T61 std::string
        case 0x16: // IA5String
        case 0x17: // UTC time
        case 0x18: // Generalized time
        case 0x1E: // BMPstring
            dwPosition++;
            if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition,
                dwSizeFound, dwBytesParsed))
            {
                dwPositionError = dwPosition;
                iTypeError = -7;
                return FALSE;
            }
            dwPosition += dwBytesParsed;
            if (!SafeToReadNBytes(dwSize - dwPosition, 0, dwSizeFound))
            {
                dwPositionError = dwPosition;
                iTypeError = -8;
                return FALSE;
            }
            if (iTypeSearch == iType)
            {
                dwPositionFound = dwPosition;
                dwLengthFound = dwSizeFound;
                return TRUE;
            }
            dwPosition += dwSizeFound;
            break;

        case 0x20: // context specific
        case 0x21: // context specific
        case 0x23: // context specific
        case 0x24: // context specific
        case 0x30: // sequence
        case 0x31: // set
            dwPosition++;
            if (!ParseDERSize(pbSignature + dwPosition, dwSize - dwPosition,
                dwSizeFound, dwBytesParsed))
            {
                dwPositionError = dwPosition;
                iTypeError = -9;
                return FALSE;
            }
            dwPosition += dwBytesParsed;
            break;

        case 0x22: // ?
            dwPosition += 2;
            break;

        default:
            dwPositionError = dwPosition;
            iTypeError = iType;
            return FALSE;
        }
    }
    return FALSE;
}

BOOL GetGeneralizedTimeStamp(PCMSG_SIGNER_INFO pSignerInfo, std::string & timeStamp)
{
    DWORD       dwPositionFound = 0;
    DWORD       dwLengthFound   = 0;
    DWORD       dwPositionError = 0;
    DWORD       n               = 0;
    INT         iTypeError      = 0;
    SYSTEMTIME  sst, lst;
    FILETIME    fft, lft;

    ULONG wYear         = 0;
    ULONG wMonth        = 0;
    ULONG wDay          = 0;
    ULONG wHour         = 0;
    ULONG wMinute       = 0;
    ULONG wSecond       = 0;
    ULONG wMilliseconds = 0;

    for (n = 0; n < pSignerInfo->UnauthAttrs.cAttr; n++)
    {
        if (lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
            szOID_RFC3161_counterSign) == 0)
        {
            break;
        }
    }
    if (n >= pSignerInfo->UnauthAttrs.cAttr)
    {
        return FALSE;
    }
    if (!ParseDERFindType(0x04,
        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
        dwPositionFound,
        dwLengthFound,
        dwPositionError, iTypeError))
    {
        return FALSE;
    }
    PBYTE pbOctetString = &(pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData[dwPositionFound]);
    if (!ParseDERFindType(0x18, pbOctetString, dwLengthFound,
        dwPositionFound,
        dwLengthFound,
        dwPositionError, iTypeError))
    {
        return FALSE;
    }
    CHAR szBuffer[256];
    strncpy_s(szBuffer, (CHAR *)&(pbOctetString[dwPositionFound]), dwLengthFound);
    szBuffer[dwLengthFound] = 0;
    _snscanf_s(szBuffer, 256, "%04d%02d%02d%02d%02d%02d.%03dZ",
        &wYear,
        &wMonth,
        &wDay,
        &wHour,
        &wMinute,
        &wSecond, &wMilliseconds);
    sst.wYear         = (WORD)wYear;
    sst.wMonth        = (WORD)wMonth;
    sst.wDay          = (WORD)wDay;
    sst.wHour         = (WORD)wHour;
    sst.wMinute       = (WORD)wMinute;
    sst.wSecond       = (WORD)wSecond;
    sst.wMilliseconds = (WORD)wMilliseconds;
    SystemTimeToFileTime(&sst, &fft);
    FileTimeToLocalFileTime(&fft, &lft);
    FileTimeToSystemTime(&lft, &lst);
    timeStamp = TimeToString(NULL, &lst);
    return TRUE;
}

int IsCharacterToStrip(int character)
{
    return 0 == character || '\t' == character || '\n' == character || '\r' == character;
}

void StripString(std::string & stringArg)
{
    stringArg.erase(remove_if(stringArg.begin(), stringArg.end(),
        IsCharacterToStrip),
        stringArg.end());
}

BOOL GetStringFromCertContext(PCCERT_CONTEXT pCertContext,
    DWORD type,
    DWORD flag,
    std::string & str)
{
    DWORD dwData = 0;
    LPSTR pszTempName = NULL;

    if (!(dwData = CertGetNameStringA(pCertContext, type,
        flag, NULL, NULL, 0)))
    {
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }
    pszTempName = (LPSTR)LocalAlloc(LPTR, dwData * sizeof(CHAR));
    if (!pszTempName)
    {
        CertFreeCertificateContext(pCertContext);
        return FALSE;
    }
    if (!(dwData = CertGetNameStringA(pCertContext, type,
        flag,
        NULL,
        pszTempName,
        dwData)))
    {
        LocalFree(pszTempName);
        return FALSE;
    }
    str = std::string(pszTempName);
    StripString(str);
    LocalFree(pszTempName);
    return TRUE;
}

BOOL CalculateSignVersion(DWORD dwVersion, std::string & version)
{
    switch (dwVersion)
    {
    case CERT_V1:
        version = "V1";
        break;
    case CERT_V2:
        version = "V2";
        break;
    case CERT_V3:
        version = "V3";
        break;
    default:
        version = "Unknown";
        break;
    }
    StripString(version);
    return TRUE;
}

BOOL CalculateDigestAlgorithm(LPCSTR pszObjId, std::string & algorithm)
{
    if (!pszObjId)
    {
        algorithm = "Unknown";
    }
    else if (!strcmp(pszObjId, szOID_OIWSEC_sha1))
    {
        algorithm = "SHA1";
    }
    else if (!strcmp(pszObjId, szOID_RSA_MD5))
    {
        algorithm = "MD5";
    }
    else if (!strcmp(pszObjId, szOID_NIST_sha256))
    {
        algorithm = "SHA256";
    }
    else
    {
        algorithm = std::string(pszObjId);
    }
    StripString(algorithm);
    return TRUE;
}

BOOL CalculateCertAlgorithm(LPCSTR pszObjId, std::string & algorithm)
{
    if (!pszObjId)
    {
        algorithm = "Unknown";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA1RSA))
    {
        algorithm = "sha1RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_sha1RSASign))
    {
        algorithm = "sha1RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD5RSA))
    {
        algorithm = "md5RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_md5RSA))
    {
        algorithm = "md5RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD2RSA))
    {
        algorithm = "md2RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA256RSA))
    {
        algorithm = "sha256RSA(RSA)";
    }
    else
    {
        algorithm = pszObjId;
    }
    StripString(algorithm);
    return TRUE;
}

#define SHA1LEN  20
#define BUFSIZE  2048
#define MD5LEN   16

BOOL CalculateHashOfBytes(BYTE *pbBinary, ALG_ID Algid, DWORD dwBinary,
    std::string & hash)
{
    DWORD       dwLastError         = 0;
    BOOL        bResult             = FALSE;
    HCRYPTPROV  hProv               = 0;
    HCRYPTHASH  hHash               = 0;
    BYTE        rgbHash[SHA1LEN]    = { 0 };
    CHAR        hexbyte[3]          = { 0 };
    DWORD       cbHash              = 0;
    CONST CHAR  rgbDigits[]         = "0123456789abcdef";
    std::string calculatedHash;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL,
        CRYPT_VERIFYCONTEXT))
    {
        dwLastError = GetLastError();
        return FALSE;
    }
    if (!CryptCreateHash(hProv, Algid, 0, 0, &hHash))
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    if (!CryptHashData(hHash, pbBinary, dwBinary, 0))
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return FALSE;
    }
    if (CALG_SHA1 == Algid)
    {
        cbHash = SHA1LEN;
    }
    else if (CALG_MD5 == Algid)
    {
        cbHash = MD5LEN;
    }
    else
    {
        cbHash = 0;
    }
    hexbyte[2] = '\0';
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))
    {
        for (DWORD i = 0; i < cbHash; i++)
        {
            hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
            hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
            calculatedHash.append(hexbyte);
        }
    }
    else
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        CryptDestroyHash(hHash);
        return FALSE;
    }
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    hash = calculatedHash;
    return TRUE;
}

BOOL CalculateCertCRLpoint(DWORD cExtensions,
    CERT_EXTENSION rgExtensions[],
    std::wstring & CRLpoint)
{
    BYTE                    btData[512]     = { 0 };
    WCHAR                   csProperty[512] = { 0 };
    ULONG                   ulDataLen       = 512;
    PCRL_DIST_POINTS_INFO   pCRLDistPoint   = (PCRL_DIST_POINTS_INFO)btData;
    PCRL_DIST_POINT_NAME    dpn             = NULL;
    PCERT_EXTENSION         pe              = NULL;

    CRLpoint.clear();
    pe = CertFindExtension(szOID_CRL_DIST_POINTS, cExtensions, rgExtensions);
    if (!pe)
    {
        return FALSE;
    }
    if (!CryptDecodeObject(MY_ENCODING, szOID_CRL_DIST_POINTS,
        pe->Value.pbData,
        pe->Value.cbData,
        CRYPT_DECODE_NOCOPY_FLAG,
        pCRLDistPoint, &ulDataLen))
    {
        return FALSE;
    }
    for (ULONG ulIndex = 0; ulIndex < pCRLDistPoint->cDistPoint; ulIndex++)
    {
        dpn = &pCRLDistPoint->rgDistPoint[ulIndex].DistPointName;
        for (ULONG ulAltEntry = 0;
            ulAltEntry < dpn->FullName.cAltEntry;
            ulAltEntry++)
        {
            if (wcslen(csProperty) > 0)
            {
                wcscat_s(csProperty, 512, L";");
            }
            wcscat_s(csProperty, 512, dpn->FullName.rgAltEntry[ulAltEntry].pwszURL);
        }
    }
    CRLpoint = csProperty;
    return TRUE;
}

BOOL CalculateSignSerial(BYTE *pbData, DWORD cbData, std::string & serial)
{
    DWORD   dwSize          = 0x400;
    BYTE    abSerial[0x400] = { 0 };
    CHAR    NameBuff[0x400] = { 0 };

    serial.clear();
    for (unsigned int uiIter = 0;
        uiIter < cbData && uiIter < 0x400;
        uiIter++)
    {
        abSerial[uiIter] = pbData[cbData - 1 - uiIter];
    }
    if (CryptBinaryToStringA(abSerial, cbData, CRYPT_STRING_HEX,
        NameBuff, &dwSize))
    {
        DWORD dwIter1 = 0;
        DWORD dwIter2 = 0;

        for (dwIter1 = 0; dwIter1 < dwSize; dwIter1++)
        {
            if (!isspace(NameBuff[dwIter1]))
            {
                NameBuff[dwIter2++] = NameBuff[dwIter1];
            }
        }
        NameBuff[dwIter2] = '\0';
        serial = std::string(NameBuff);
        StripString(serial);
    }
    return TRUE;
}

BOOL GetSignerCertificateInfo(LPCWSTR filename, std::list<SIGN_NODE_INFO> & signChain)
{
    HCRYPTMSG       hAuthCryptMsg   = NULL;
    HCERTSTORE      hSystemStore    = NULL;
    BOOL            bReturn         = FALSE;
    DWORD           dwEncoding      = 0x00;
    DWORD           dwContentType   = 0x00;
    DWORD           dwFormatType    = 0x00;
    SIGNDATA_HANDLE AuthSignData    = { 0 };
    std::list<SIGNDATA_HANDLE> SignDataChain;

    signChain.clear();
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filename,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &AuthSignData.hCertStore,
        &hAuthCryptMsg,
        NULL))
    {
        INT error = GetLastError();
        return bReturn;
    }
    if (!MyCryptMsgGetParam(hAuthCryptMsg, CMSG_SIGNER_INFO_PARAM,
        0,
        (PVOID *)&AuthSignData.pSignerInfo,
        &AuthSignData.dwObjSize))
    {
        CryptMsgClose(hAuthCryptMsg);
        CertCloseStore(AuthSignData.hCertStore, 0);
        return bReturn;
    }
    CryptMsgClose(hAuthCryptMsg);
    hAuthCryptMsg = NULL;
    // 打开系统证书库句柄, 以在后面查找根证书数据.
    hSystemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
        MY_ENCODING,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"Root");
    if (!hSystemStore)
    {
        LocalFree(AuthSignData.pSignerInfo);
        CertCloseStore(AuthSignData.hCertStore, 0);
        return bReturn;
    }
    // 生成多签名列表以通过迭代枚举.
    SignDataChain.push_back(AuthSignData);
    // 获取并插入嵌套签名者信息节点.
    GetNestedSignerInfo(AuthSignData.pSignerInfo, AuthSignData.dwObjSize,
        SignDataChain);
    for (list<SIGNDATA_HANDLE>::iterator iter = SignDataChain.begin();
        iter != SignDataChain.end(); iter++)
    {
        PCCERT_CONTEXT      pOrigContext   = NULL;
        PCCERT_CONTEXT      pCurrContext   = NULL;
        LPCSTR              szObjId        = NULL;
        PCMSG_SIGNER_INFO   pCounterSigner = NULL;
        CERT_INFO           CertInfo;
        CERT_NODE_INFO      CertNodeInfo;
        SIGN_NODE_INFO      SignNodeInfo;

        GetAuthedAttribute(iter->pSignerInfo);
        GetCounterSignerInfo(iter->pSignerInfo, &pCounterSigner);
        // 计算签名时间戳.
        if (pCounterSigner)
        {
            bReturn = GetCounterSignerData(pCounterSigner,
                SignNodeInfo.CounterSign.signerName,
                SignNodeInfo.CounterSign.timeStamp,
                SignNodeInfo.CounterSign.mailAddress);
        }
        else
        {
            bReturn = GetGeneralizedTimeStamp(iter->pSignerInfo,
                SignNodeInfo.CounterSign.timeStamp);
        }
        // 计算摘要算法.
        szObjId = iter->pSignerInfo->HashAlgorithm.pszObjId;
        bReturn = CalculateDigestAlgorithm(szObjId,
            SignNodeInfo.digestAlgorithm);
        // 计算签名版本.
        bReturn = CalculateSignVersion(iter->pSignerInfo->dwVersion,
            SignNodeInfo.version);
        CertInfo.Issuer = iter->pSignerInfo->Issuer;
        CertInfo.SerialNumber = iter->pSignerInfo->SerialNumber;
        // 查找第一个证书Context信息.
        pCurrContext = NULL;
        pCurrContext = CertFindCertificateInStore(iter->hCertStore,
            MY_ENCODING,
            0,
            CERT_FIND_ISSUER_NAME,
            (PVOID)&iter->pSignerInfo->Issuer,
            NULL);
        while (pCurrContext)
        {
            PCERT_INFO pCertInfo = pCurrContext->pCertInfo;
            // 计算证书签名算法.
            szObjId = pCertInfo->SignatureAlgorithm.pszObjId;
            bReturn = CalculateCertAlgorithm(szObjId, CertNodeInfo.signAlgorithm);
            // 计算证书序列号.
            bReturn = CalculateSignSerial(pCertInfo->SerialNumber.pbData,
                pCertInfo->SerialNumber.cbData,
                CertNodeInfo.serial);
            // 计算签名证书版本.
            bReturn = CalculateSignVersion(pCertInfo->dwVersion,
                CertNodeInfo.version);
            // 获取使用者名称.
            bReturn = GetStringFromCertContext(pCurrContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                CertNodeInfo.subjectName);
            // 获取颁发者名称.
            bReturn = GetStringFromCertContext(pCurrContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                CertNodeInfo.issuerName);
            // 计算签名证书指纹.
            bReturn = CalculateHashOfBytes(pCurrContext->pbCertEncoded,
                CALG_SHA1,
                pCurrContext->cbCertEncoded,
                CertNodeInfo.thumbprint);
            // 提取吊销列表分发点.
            bReturn = CalculateCertCRLpoint(pCertInfo->cExtension,
                pCertInfo->rgExtension,
                CertNodeInfo.CRLpoint);
            // 获取证书有效期范围.
            CertNodeInfo.notbefore = TimeToString(&pCertInfo->NotBefore);
            CertNodeInfo.notafter = TimeToString(&pCertInfo->NotAfter);
            SignNodeInfo.CertNodeChain.push_back(CertNodeInfo);
            pOrigContext = pCurrContext;
            pCurrContext = CertFindCertificateInStore(iter->hCertStore,
                MY_ENCODING,
                0,
                CERT_FIND_SUBJECT_NAME,
                (PVOID)&pCertInfo->Issuer,
                NULL);
            // 根证书通常不包含在PE文件的证书库中, 需在系统证书库中查找.
            if (!pCurrContext)
            {
                pCurrContext = CertFindCertificateInStore(hSystemStore,
                    MY_ENCODING,
                    0,
                    CERT_FIND_SUBJECT_NAME,
                    (PVOID)&pCertInfo->Issuer,
                    NULL);
            }
            if (!pCurrContext)
            {
                break;
            }
            // 部分证书的颁发者和使用者相同, 跳出.
            if (CertComparePublicKeyInfo(MY_ENCODING,
                &pCurrContext->pCertInfo->SubjectPublicKeyInfo,
                &pOrigContext->pCertInfo->SubjectPublicKeyInfo))
            {
                CertFreeCertificateContext(pCurrContext);
                break;
            }
            CertFreeCertificateContext(pOrigContext);
            pOrigContext = NULL;
        }
        signChain.push_back(SignNodeInfo);
        bReturn = TRUE;
        if (pCounterSigner) LocalFree(pCounterSigner);
        if (iter->hCertStore) CertCloseStore(iter->hCertStore, 0);
        if (iter->pSignerInfo) LocalFree(iter->pSignerInfo);
        if (pOrigContext) CertFreeCertificateContext(pOrigContext);
    }
    if (hSystemStore) CertCloseStore(hSystemStore, 0);
    return bReturn;
}

BOOL MyCryptCalcFileHash(HANDLE FileHandle, PBYTE *szBuffer, DWORD *HashSize)
{
    if (!szBuffer || !HashSize)
    {
        return FALSE;
    }
    *HashSize = 0x00;
    // 获取哈希所需大小.
    CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, NULL, 0x00);
    if (0 == *HashSize)
    {
        // 哈希为0意味着发生错误.
        return FALSE;
    }
    // 分配内存.
    *szBuffer = (PBYTE)calloc(*HashSize, 1);
    // 精确计算哈希值.
    if (!CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, *szBuffer, 0x00))
    {
        free(*szBuffer);
        return FALSE;
    }
    return TRUE;
}

BOOL CheckFileDigitalSignature(LPCWSTR filePath, BOOL bNoRevocation,
    LPCWSTR catPath,
    std::wstring & catFile,
    std::string & signType,
    std::list<SIGN_NODE_INFO> & signChain)
{
    HCATINFO        CatContext  = NULL;
    PVOID           Context     = NULL;
    HANDLE          FileHandle  = NULL;
    PBYTE           szBuffer    = NULL;
    DWORD           dwHashSize  = 0x00;
    UINT            uiCatCount  = 0x00;
    CATALOG_INFO    InfoStruct  = { 0 };
    BOOL            bReturn     = FALSE;
    std::wstring    targPath;

    catFile.clear();
    signType.clear();
    InfoStruct.cbStruct = sizeof(CATALOG_INFO);
    // 获取签名验证的环境结构.
    if (!CryptCATAdminAcquireContext(&Context, NULL, 0))
    {
        return FALSE;
    }
    while (!catPath)
    {
        FileHandle = CreateFileW(filePath, GENERIC_READ,
            7,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL);
        if (INVALID_HANDLE_VALUE == FileHandle)
        {
            CryptCATAdminReleaseContext(Context, 0);
            return FALSE;
        }
        // 计算文件哈希.
        if (!MyCryptCalcFileHash(FileHandle, &szBuffer, &dwHashSize))
        {
            CryptCATAdminReleaseContext(Context, 0);
            CloseHandle(FileHandle);
            break;
        }
        CloseHandle(FileHandle);
        // 获取目录环境结构.
        HCATINFO *p = NULL;
        for (;;)
        {
            CatContext = CryptCATAdminEnumCatalogFromHash(Context,
                szBuffer,
                dwHashSize,
                0,
                p);
            p = &CatContext;
            if (!CatContext)
            {
                break;
            }
            uiCatCount++;
        }
        for (UINT uiIter = 0; uiIter < uiCatCount; uiIter++)
        {
            CatContext = CryptCATAdminEnumCatalogFromHash(Context,
                szBuffer,
                dwHashSize,
                0,
                &CatContext);
        }
        free(szBuffer);
        break;
    }
    // 如果不能获取信息.
    if (CatContext &&
        !CryptCATCatalogInfoFromContext(CatContext, &InfoStruct, 0))
    {
        // 释放环境结构并设置环境结构指针为空.
        CryptCATAdminReleaseCatalogContext(Context, CatContext, 0);
        CatContext = NULL;
    }
    if (!CatContext && !catPath)
    {
        signType = "embedded";
        catFile  = L"";
        targPath = filePath;
    }
    else
    {
        signType = "cataloged";
        catFile  = CatContext ? InfoStruct.wszCatalogFile : catPath;
        targPath = catFile;
    }
    // 获取签名证书信息.
    bReturn = GetSignerCertificateInfo(targPath.c_str(), signChain);
    // 释放环境结构.
    if (CatContext)
    {
        CryptCATAdminReleaseCatalogContext(Context, CatContext, 0);
    }
    // 释放内存.
    CryptCATAdminReleaseContext(Context, 0);
    return bReturn;
}

INT wmain(INT argc, WCHAR *argv[])
{
    INT     argCount   = 0x00;
    LPWSTR  *szArgList = NULL;
    
    szArgList = CommandLineToArgvW(GetCommandLineW(), &argCount);
    if (argCount < 2)
    {
        std::cout << "Parameter error!" << endl;
        std::cout << "Usage: PESignAnalyzer.exe filepath" << endl;
        return 1;
    }
    std::wstring targetFile = szArgList[1];
    CertificateCheck(targetFile.c_str());
    return 0;
}
