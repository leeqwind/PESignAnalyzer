/**
 * COPYRIGHT NOTICE & DESCRIPTION
 *
 * Source: PESignAnalyzer.cpp
 * Author: leeqwind
 * E-mail: leeqw.live@outlook.com
 * Notice: This program can retrieve signature information from PE
 *         files which signed by a/some certificate(s) on Windows.
 *         Supporting multi-signed information and certificates chain.
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
    std::string SignerName;
    std::string MailAddress;
    std::string TimeStamp;
} SIGN_COUNTER_SIGN, *PSIGN_COUNTER_SIGN;

/// Per certificate node.
typedef struct _CERT_NODE_INFO {
    std::string SubjectName;
    std::string IssuerName;
    std::string Version;
    std::string Serial;
    std::string Thumbprint;
    std::string NotBefore;
    std::string NotAfter;
    std::string SignAlgorithm;
    std::wstring CRLpoint;
} CERT_NODE_INFO, *PCERT_NODE_INFO;

/// Per signature node.
typedef struct _SIGN_NODE_INFO {
    std::string DigestAlgorithm;
    std::string Version;
    SIGN_COUNTER_SIGN CounterSign;
    std::list<CERT_NODE_INFO> CertChain;
} SIGN_NODE_INFO, *PSIGN_NODE_INFO;

typedef struct _SIGNDATA_HANDLE {
    DWORD dwObjSize;
    PCMSG_SIGNER_INFO pSignerInfo;
    HCERTSTORE hCertStoreHandle;
} SIGNDATA_HANDLE, *PSIGNDATA_HANDLE;

BOOL MyCryptMsgGetParam(
    HCRYPTMSG hCryptMsg,
    DWORD dwParamType,
    DWORD dwIndex,
    PVOID *pParam,
    DWORD *dwOutSize
) {
    BOOL  bReturn = FALSE;
    DWORD dwSize  = 0;
    if (!pParam)
    {
        return FALSE;
    }
    // Get size
    bReturn = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, NULL, &dwSize);
    if (!bReturn)
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
    bReturn = CryptMsgGetParam(hCryptMsg, dwParamType, dwIndex, *pParam, &dwSize);
    if (!bReturn)
    {
        return FALSE;
    }
    if (dwOutSize)
    {
        *dwOutSize = dwSize;
    }
    return TRUE;
}

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
BOOL GetNestedSignerInfo(
    CONST PSIGNDATA_HANDLE AuthSignData,
    std::list<SIGNDATA_HANDLE> & NestedChain
) {
    BOOL        bSucceed    = FALSE;
    BOOL        bReturn     = FALSE;
    HCRYPTMSG   hNestedMsg  = NULL;
    PBYTE       pbCurrData  = NULL;
    PBYTE       pbNextData  = NULL;
    DWORD       n           = 0x00;
    DWORD       cbCurrData  = 0x00;

    if (!AuthSignData->pSignerInfo)
    {
        return FALSE;
    }
    __try
    {
        // Traverse and look for a nested signature.
        for (n = 0; n < AuthSignData->pSignerInfo->UnauthAttrs.cAttr; n++)
        {
            if (!lstrcmpA(AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId,
                szOID_NESTED_SIGNATURE))
            {
                break;
            }
        }
        // Cannot find a nested signature attribute.
        if (n >= AuthSignData->pSignerInfo->UnauthAttrs.cAttr)
        {
            bSucceed = FALSE;
            __leave;
        }
        pbCurrData = AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData;
        cbCurrData = AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData;
        hNestedMsg = CryptMsgOpenToDecode(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            0,
            0,
            NULL,
            0
        );
        if (!hNestedMsg) // Fatal Error
        {
            bSucceed = FALSE;
            __leave;
        }
        // Multiple nested signatures just add one attr in UnauthAttrs
        // list of the main signature pointing to the first nested si-
        // gnature. Every nested signature exists side by side in an 8
        // bytes aligned way. According to the size of major signature
        // parse the nested signatures one by one.
        while (pbCurrData > (BYTE *)AuthSignData->pSignerInfo &&
            pbCurrData < (BYTE *)AuthSignData->pSignerInfo + AuthSignData->dwObjSize)
        {
            SIGNDATA_HANDLE NestedHandle = { 0 };
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
            // Big Endian -> Little Endian
            cbCurrData = XCH_WORD_LITEND(*(WORD *)(pbCurrData + 2)) + 4;
            pbNextData = pbCurrData;
            pbNextData += _8BYTE_ALIGN(cbCurrData, (ULONG_PTR)pbCurrData);
            bReturn = CryptMsgUpdate(hNestedMsg, pbCurrData, cbCurrData, TRUE);
            pbCurrData = pbNextData;
            if (!bReturn)
            {
                continue;
            }
            bReturn = MyCryptMsgGetParam(hNestedMsg, CMSG_SIGNER_INFO_PARAM,
                0,
                (PVOID *)&NestedHandle.pSignerInfo,
                &NestedHandle.dwObjSize
            );
            if (!bReturn)
            {
                continue;
            }
            NestedHandle.hCertStoreHandle = CertOpenStore(CERT_STORE_PROV_MSG,
                PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                0,
                0,
                hNestedMsg
            );
            bSucceed = TRUE;
            NestedChain.push_back(NestedHandle);
        }
    }
    __finally
    {
        if (hNestedMsg) CryptMsgClose(hNestedMsg);
    }
    return bSucceed;
}

BOOL GetAuthedAttribute(
    PCMSG_SIGNER_INFO pSignerInfo
) {
    BOOL    bSucceed   = FALSE;
    DWORD   dwObjSize  = 0x00;
    DWORD   n          = 0x00;

    __try
    {
        for (n = 0; n < pSignerInfo->AuthAttrs.cAttr; n++)
        {
            if (!lstrcmpA(pSignerInfo->AuthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign))
            {
                bSucceed = TRUE;
                break;
            }
        }
    }
    __finally
    {
    }
    return bSucceed;
}

// http://support.microsoft.com/kb/323809
BOOL GetCounterSignerInfo(
    PCMSG_SIGNER_INFO pSignerInfo,
    PCMSG_SIGNER_INFO *pTargetSigner
) {
    BOOL    bSucceed   = FALSE;
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
            if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RSA_counterSign))
            {
                break;
            }
        }
        if (n >= pSignerInfo->UnauthAttrs.cAttr)
        {
            bSucceed = FALSE;
            __leave;
        }
        bReturn = CryptDecodeObject(MY_ENCODING,
            PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            NULL,
            &dwObjSize
        );
        if (!bReturn)
        {
            bSucceed = FALSE;
            __leave;
        }
        *pTargetSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwObjSize);
        if (!*pTargetSigner)
        {
            bSucceed = FALSE;
            __leave;
        }
        bReturn = CryptDecodeObject(MY_ENCODING,
            PKCS7_SIGNER_INFO,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
            pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
            0,
            (PVOID)*pTargetSigner,
            &dwObjSize
        );
        if (!bReturn)
        {
            bSucceed = FALSE;
            __leave;
        }
        bSucceed = TRUE;
    }
    __finally
    {
    }
    return bSucceed;
}

std::string TimeToString(
    FILETIME *pftIn,
    SYSTEMTIME *pstIn = NULL
) {
    SYSTEMTIME st = { 0 };
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
        pstIn->wSecond
    );
    return std::string(szBuffer);
}

BOOL GetCounterSignerData(
    CONST PCMSG_SIGNER_INFO SignerInfo,
    SIGN_COUNTER_SIGN & CounterSign
) {
    BOOL        bReturn  = FALSE;
    DWORD       n        = 0x00;
    DWORD       dwData   = 0x00;
    FILETIME    lft, ft;
    SYSTEMTIME  st;

    // Find szOID_RSA_signingTime OID.
    for (n = 0; n < SignerInfo->AuthAttrs.cAttr; n++)
    {
        if (!lstrcmpA(SignerInfo->AuthAttrs.rgAttr[n].pszObjId, szOID_RSA_signingTime))
        {
            break;
        }
    }
    if (n >= SignerInfo->AuthAttrs.cAttr)
    {
        return FALSE;
    }
    // Decode and get FILETIME structure.
    dwData = sizeof(ft);
    bReturn = CryptDecodeObject(MY_ENCODING,
        szOID_RSA_signingTime,
        SignerInfo->AuthAttrs.rgAttr[n].rgValue[0].pbData,
        SignerInfo->AuthAttrs.rgAttr[n].rgValue[0].cbData,
        0,
        (PVOID)&ft,
        &dwData
    );
    if (!bReturn)
    {
        return FALSE;
    }
    // Convert.
    FileTimeToLocalFileTime(&ft, &lft);
    FileTimeToSystemTime(&lft, &st);
    CounterSign.TimeStamp = TimeToString(NULL, &st);
    return TRUE;
}

BOOL SafeToReadNBytes(
    DWORD dwSize,
    DWORD dwStart,
    DWORD dwRequestSize
) {
    return dwSize - dwStart >= dwRequestSize;
}

void ParseDERType(
    BYTE bIn,
    INT & iType,
    INT & iClass
) {
    iType = bIn & 0x3F;
    iClass = bIn >> 6;
}

DWORD ReadNumberFromNBytes(
    PBYTE pbSignature,
    DWORD dwStart,
    DWORD dwRequestSize
) {
    DWORD dwNumber = 0;
    for (DWORD i = 0; i < dwRequestSize; i++)
    {
        dwNumber = dwNumber * 0x100 + pbSignature[dwStart + i];
    }
    return dwNumber;
}

BOOL ParseDERSize(
    PBYTE pbSignature,
    DWORD dwSize,
    DWORD & dwSizefound,
    DWORD & dwBytesParsed
) {
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

BOOL ParseDERFindType(
    INT iTypeSearch,
    PBYTE pbSignature,
    DWORD dwSize,
    DWORD & dwPositionFound,
    DWORD & dwLengthFound,
    DWORD & dwPositionError,
    INT & iTypeError
) {
    DWORD   dwPosition      = 0;
    DWORD   dwSizeFound     = 0;
    DWORD   dwBytesParsed   = 0;
    INT     iType           = 0;
    INT     iClass          = 0;

    iTypeError      = -1;
    dwPositionFound = 0;
    dwLengthFound   = 0;
    dwPositionError = 0;
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
                dwSizeFound,
                dwBytesParsed))
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
                dwSizeFound,
                dwBytesParsed))
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

BOOL GetGeneralizedTimeStamp(
    PCMSG_SIGNER_INFO pSignerInfo,
    std::string & TimeStamp
) {
    BOOL        bSucceed        = FALSE;
    BOOL        bReturn         = FALSE;
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
        if (!lstrcmpA(pSignerInfo->UnauthAttrs.rgAttr[n].pszObjId, szOID_RFC3161_counterSign))
        {
            break;
        }
    }
    if (n >= pSignerInfo->UnauthAttrs.cAttr)
    {
        return FALSE;
    }
    bReturn = ParseDERFindType(0x04,
        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData,
        pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].cbData,
        dwPositionFound,
        dwLengthFound,
        dwPositionError,
        iTypeError
    );
    if (!bReturn)
    {
        return FALSE;
    }
    PBYTE pbOctetString = &pSignerInfo->UnauthAttrs.rgAttr[n].rgValue[0].pbData[dwPositionFound];
    bReturn = ParseDERFindType(0x18, pbOctetString, dwLengthFound,
        dwPositionFound,
        dwLengthFound,
        dwPositionError,
        iTypeError
    );
    if (!bReturn)
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
        &wSecond,
        &wMilliseconds
    );
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
    TimeStamp = TimeToString(NULL, &lst);
    return TRUE;
}

INT IsCharacterToStrip(
    INT Character
) {
    return 0 == Character || '\t' == Character || '\n' == Character || '\r' == Character;
}

VOID StripString(
    std::string & StrArg
) {
    StrArg.erase(remove_if(StrArg.begin(), StrArg.end(), IsCharacterToStrip), StrArg.end());
}

BOOL GetStringFromCertContext(
    PCCERT_CONTEXT pCertContext,
    DWORD Type,
    DWORD Flag,
    std::string & String
) {
    DWORD dwData      = 0x00;
    LPSTR pszTempName = NULL;

    dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, NULL, 0);
    if (!dwData)
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
    dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, pszTempName, dwData);
    if (!dwData)
    {
        LocalFree(pszTempName);
        return FALSE;
    }
    String = std::string(pszTempName);
    StripString(String);
    LocalFree(pszTempName);
    return TRUE;
}

BOOL CalculateSignVersion(
    DWORD dwVersion,
    std::string & Version
) {
    switch (dwVersion)
    {
    case CERT_V1:
        Version = "V1";
        break;
    case CERT_V2:
        Version = "V2";
        break;
    case CERT_V3:
        Version = "V3";
        break;
    default:
        Version = "Unknown";
        break;
    }
    StripString(Version);
    return TRUE;
}

BOOL CalculateDigestAlgorithm(
    LPCSTR pszObjId,
    std::string & Algorithm
) {
    if (!pszObjId)
    {
        Algorithm = "Unknown";
    }
    else if (!strcmp(pszObjId, szOID_OIWSEC_sha1))
    {
        Algorithm = "SHA1";
    }
    else if (!strcmp(pszObjId, szOID_RSA_MD5))
    {
        Algorithm = "MD5";
    }
    else if (!strcmp(pszObjId, szOID_NIST_sha256))
    {
        Algorithm = "SHA256";
    }
    else
    {
        Algorithm = std::string(pszObjId);
    }
    StripString(Algorithm);
    return TRUE;
}

BOOL CalculateCertAlgorithm(
    LPCSTR pszObjId,
    std::string & Algorithm
) {
    if (!pszObjId)
    {
        Algorithm = "Unknown";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA1RSA))
    {
        Algorithm = "sha1RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_sha1RSASign))
    {
        Algorithm = "sha1RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD5RSA))
    {
        Algorithm = "md5RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_OIWSEC_md5RSA))
    {
        Algorithm = "md5RSA(OIW)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_MD2RSA))
    {
        Algorithm = "md2RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA256RSA))
    {
        Algorithm = "sha256RSA(RSA)";
    }
    else
    {
        Algorithm = pszObjId;
    }
    StripString(Algorithm);
    return TRUE;
}

#define SHA1LEN  20
#define BUFSIZE  2048
#define MD5LEN   16

BOOL CalculateHashOfBytes(
    BYTE *pbBinary,
    ALG_ID Algid,
    DWORD dwBinary,
    std::string & Hash
) {
    BOOL        bReturn             = FALSE;
    DWORD       dwLastError         = 0;
    HCRYPTPROV  hProv               = 0;
    HCRYPTHASH  hHash               = 0;
    DWORD       cbHash              = 0;
    BYTE        rgbHash[SHA1LEN]    = { 0 };
    CHAR        hexbyte[3]          = { 0 };
    CONST CHAR  rgbDigits[]         = "0123456789abcdef";
    std::string CalcHash;

    bReturn = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    if (!bReturn)
    {
        dwLastError = GetLastError();
        return FALSE;
    }
    bReturn = CryptCreateHash(hProv, Algid, 0, 0, &hHash);
    if (!bReturn)
    {
        dwLastError = GetLastError();
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    bReturn = CryptHashData(hHash, pbBinary, dwBinary, 0);
    if (!bReturn)
    {
        dwLastError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
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
    bReturn = CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);
    if (!bReturn)
    {
        dwLastError = GetLastError();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    for (DWORD i = 0; i < cbHash; i++)
    {
        hexbyte[0] = rgbDigits[rgbHash[i] >> 4];
        hexbyte[1] = rgbDigits[rgbHash[i] & 0xf];
        CalcHash.append(hexbyte);
    }
    Hash = CalcHash;
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return TRUE;
}

BOOL CalculateCertCRLpoint(
    DWORD cExtensions,
    CERT_EXTENSION rgExtensions[],
    std::wstring & CRLpoint
) {
    BOOL                    bReturn         = FALSE;
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
    bReturn = CryptDecodeObject(MY_ENCODING, szOID_CRL_DIST_POINTS,
        pe->Value.pbData,
        pe->Value.cbData,
        CRYPT_DECODE_NOCOPY_FLAG,
        pCRLDistPoint, &ulDataLen
    );
    if (!bReturn)
    {
        return FALSE;
    }
    for (ULONG idx = 0; idx < pCRLDistPoint->cDistPoint; idx++)
    {
        dpn = &pCRLDistPoint->rgDistPoint[idx].DistPointName;
        for (ULONG ulAltEntry = 0; ulAltEntry < dpn->FullName.cAltEntry; ulAltEntry++)
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

BOOL CalculateSignSerial(
    BYTE *pbData,
    DWORD cbData,
    std::string & Serial
) {
    BOOL    bReturn         = FALSE;
    DWORD   dwSize          = 0x400;
    BYTE    abSerial[0x400] = { 0 };
    CHAR    NameBuff[0x400] = { 0 };

    Serial.clear();
    for (UINT uiIter = 0; uiIter < cbData && uiIter < 0x400; uiIter++)
    {
        abSerial[uiIter] = pbData[cbData - 1 - uiIter];
    }
    bReturn = CryptBinaryToStringA(abSerial, cbData, CRYPT_STRING_HEX, NameBuff, &dwSize);
    if (!bReturn)
    {
        return FALSE;
    }
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
    Serial = std::string(NameBuff);
    StripString(Serial);
    return TRUE;
}

// Getting Signer Signature Information.
// If return TRUE, it will continue for caller;
// else, jump out the while loop.
BOOL GetSignerSignatureInfo(
    CONST HCERTSTORE hSystemStore,
    CONST HCERTSTORE hCertStore,
    CONST PCCERT_CONTEXT pOrigContext,
    PCCERT_CONTEXT & pCurrContext,
    SIGN_NODE_INFO & SignNode
) {
    BOOL            bReturn   = FALSE;
    PCERT_INFO      pCertInfo = pCurrContext->pCertInfo;
    LPCSTR          szObjId   = NULL;
    CERT_NODE_INFO  CertNode;

    // Get certificate algorithm.
    szObjId = pCertInfo->SignatureAlgorithm.pszObjId;
    bReturn = CalculateCertAlgorithm(szObjId, CertNode.SignAlgorithm);
    // Get certificate serial.
    bReturn = CalculateSignSerial(pCertInfo->SerialNumber.pbData,
        pCertInfo->SerialNumber.cbData,
        CertNode.Serial
    );
    // Get certificate version.
    bReturn = CalculateSignVersion(pCertInfo->dwVersion, CertNode.Version);
    // Get certficate subject.
    bReturn = GetStringFromCertContext(pCurrContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        CertNode.SubjectName
    );
    // Get certificate issuer.
    bReturn = GetStringFromCertContext(pCurrContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        CertNode.IssuerName
    );
    // Get certificate thumbprint.
    bReturn = CalculateHashOfBytes(pCurrContext->pbCertEncoded,
        CALG_SHA1,
        pCurrContext->cbCertEncoded,
        CertNode.Thumbprint
    );
    // Get certificate CRL point.
    bReturn = CalculateCertCRLpoint(pCertInfo->cExtension,
        pCertInfo->rgExtension,
        CertNode.CRLpoint
    );
    // Get certificate validity.
    CertNode.NotBefore = TimeToString(&pCertInfo->NotBefore);
    CertNode.NotAfter  = TimeToString(&pCertInfo->NotAfter);

    SignNode.CertChain.push_back(CertNode);

    // Get next certificate link node.
    pCurrContext = CertFindCertificateInStore(hCertStore,
        MY_ENCODING,
        0,
        CERT_FIND_SUBJECT_NAME,
        (PVOID)&pCertInfo->Issuer,
        NULL
    );
    // Root certificate is always included pe file certstore,
    // We can find it in system certstore.
    if (!pCurrContext)
    {
        pCurrContext = CertFindCertificateInStore(hSystemStore,
            MY_ENCODING,
            0,
            CERT_FIND_SUBJECT_NAME,
            (PVOID)&pCertInfo->Issuer,
            NULL
        );
    }
    if (!pCurrContext)
    {
        return FALSE;
    }
    // Sometimes issuer is equal to subject. Jump out if so.
    return CertComparePublicKeyInfo(MY_ENCODING,
        &pCurrContext->pCertInfo->SubjectPublicKeyInfo,
        &pOrigContext->pCertInfo->SubjectPublicKeyInfo
    ) == FALSE;
}

// Getting Signer Certificate Information.
BOOL GetSignerCertificateInfo(
    LPCWSTR FileName,
    std::list<SIGN_NODE_INFO> & SignChain
) {
    BOOL            bSucceed        = FALSE;
    BOOL            bReturn         = FALSE;
    HCERTSTORE      hSystemStore    = NULL;
    SIGNDATA_HANDLE AuthSignData    = { 0 };
    std::list<SIGNDATA_HANDLE> SignDataChain;

    SignChain.clear();
    // Open system certstore handle, in order to find root certificate.
    hSystemStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, MY_ENCODING,
        NULL,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"Root"
    );
    if (!hSystemStore)
    {
        INT error = GetLastError();
        return FALSE;
    }
    // Query file auth signature and cert store Object.
    HCRYPTMSG hAuthCryptMsg = NULL;
    DWORD dwEncoding = 0x00;
    bReturn = CryptQueryObject(CERT_QUERY_OBJECT_FILE, FileName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        NULL,
        NULL,
        &AuthSignData.hCertStoreHandle,
        &hAuthCryptMsg,
        NULL
    );
    if (!bReturn)
    {
        INT error = GetLastError();
        CertCloseStore(hSystemStore, 0);
        return FALSE;
    }
    // Get signer information pointer.
    bReturn = MyCryptMsgGetParam(hAuthCryptMsg, CMSG_SIGNER_INFO_PARAM,
        0,
        (PVOID *)&AuthSignData.pSignerInfo,
        &AuthSignData.dwObjSize
    );
    CryptMsgClose(hAuthCryptMsg);
    hAuthCryptMsg = NULL;
    if (!bReturn)
    {
        INT error = GetLastError();
        CertCloseStore(AuthSignData.hCertStoreHandle, 0);
        CertCloseStore(hSystemStore, 0);
        return FALSE;
    }

    // Get and append nested signature information.
    SignDataChain.push_back(AuthSignData);
    bReturn = GetNestedSignerInfo(&AuthSignData, SignDataChain);

    list<SIGNDATA_HANDLE>::iterator iter = SignDataChain.begin();
    for (; iter != SignDataChain.end(); iter++)
    {
        PCCERT_CONTEXT      pOrigContext   = NULL;
        PCCERT_CONTEXT      pCurrContext   = NULL;
        LPCSTR              szObjId        = NULL;
        PCMSG_SIGNER_INFO   pCounterSigner = NULL;
        SIGN_NODE_INFO      SignNode;

        GetAuthedAttribute(iter->pSignerInfo);
        // Get signature timestamp.
        GetCounterSignerInfo(iter->pSignerInfo, &pCounterSigner);
        if (pCounterSigner)
        {
            bReturn = GetCounterSignerData(pCounterSigner, SignNode.CounterSign);
        }
        else
        {
            bReturn = GetGeneralizedTimeStamp(iter->pSignerInfo,
                SignNode.CounterSign.TimeStamp
            );
        }
        // Get digest algorithm.
        szObjId = iter->pSignerInfo->HashAlgorithm.pszObjId;
        bReturn = CalculateDigestAlgorithm(szObjId, SignNode.DigestAlgorithm);
        // Get signature version.
        bReturn = CalculateSignVersion(iter->pSignerInfo->dwVersion, SignNode.Version);
        // Find the first certificate Context information.
        pCurrContext = CertFindCertificateInStore(iter->hCertStoreHandle,
            MY_ENCODING,
            0,
            CERT_FIND_ISSUER_NAME,
            (PVOID)&iter->pSignerInfo->Issuer,
            NULL
        );
        bReturn = (pCurrContext != NULL);
        while (bReturn)
        {
            pOrigContext = pCurrContext;
            // Get every signer signature information.
            bReturn = GetSignerSignatureInfo(hSystemStore, iter->hCertStoreHandle,
                pOrigContext,
                pCurrContext,
                SignNode
            );
            CertFreeCertificateContext(pOrigContext);
        }
        if (pCurrContext) CertFreeCertificateContext(pCurrContext);
        if (pCounterSigner) LocalFree(pCounterSigner);
        if (iter->pSignerInfo) LocalFree(iter->pSignerInfo);
        if (iter->hCertStoreHandle) CertCloseStore(iter->hCertStoreHandle, 0);
        bSucceed = TRUE;
        SignChain.push_back(SignNode);
    }
    CertCloseStore(hSystemStore, 0);
    return bSucceed;
}

BOOL MyCryptCalcFileHash(
    HANDLE FileHandle,
    PBYTE *szBuffer,
    DWORD *HashSize
) {
    BOOL bReturn = FALSE;
    if (!szBuffer || !HashSize)
    {
        return FALSE;
    }
    *HashSize = 0x00;
    // Get size.
    bReturn = CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, NULL, 0x00);
    if (0 == *HashSize) // HashSize being zero means fatal error.
    {
        return FALSE;
    }
    *szBuffer = (PBYTE)calloc(*HashSize, 1);
    bReturn = CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, *szBuffer, 0x00);
    if (!bReturn)
    {
        free(*szBuffer);
    }
    return bReturn;
}

BOOL CheckFileDigitalSignature(
    LPCWSTR FilePath,
    LPCWSTR CataPath,
    std::wstring & CataFile,
    std::string & SignType,
    std::list<SIGN_NODE_INFO> & SignChain
) {
    PVOID   Context = NULL;
    BOOL    bReturn = FALSE;

    CataFile = CataPath ? CataPath : L"";
    SignType = "embedded";

    do
    {
        // Skip getting catalog Context if CataPath is specified.
        if (CataPath)
        {
            break;
        }
        // Acquire signature Context structure.
        bReturn = CryptCATAdminAcquireContext(&Context, NULL, 0);
        if (!bReturn)
        {
            break;
        }
        // Open the specified file handle to get the file hash.
        HANDLE FileHandle = CreateFileW(FilePath, GENERIC_READ,
            7,
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            NULL
        );
        if (INVALID_HANDLE_VALUE == FileHandle)
        {
            break;
        }
        // Calculate file hash.
        DWORD dwHashSize = 0x00;
        PBYTE szBuffer   = NULL;
        bReturn = MyCryptCalcFileHash(FileHandle, &szBuffer, &dwHashSize);
        CloseHandle(FileHandle);
        if (!bReturn)
        {
            break;
        }
        // Get catalog Context structure.
        UINT     uiCataLimit = 0x00;
        HCATINFO CataContext = NULL;
        do
        {
            // Probe catalog Context structure layer.
            CataContext = CryptCATAdminEnumCatalogFromHash(Context,
                szBuffer,
                dwHashSize,
                0,
                uiCataLimit == 0 ? NULL : &CataContext
            );
            uiCataLimit++;
        } while (CataContext);
        uiCataLimit--;
        for (UINT uiIter = 0; uiIter < uiCataLimit; uiIter++)
        {
            // Get specified catalog Context structure.
            CataContext = CryptCATAdminEnumCatalogFromHash(Context,
                szBuffer,
                dwHashSize,
                0,
                &CataContext
            );
        }
        free(szBuffer);
        if (!CataContext)
        {
            break;
        }
        // Get catalog information.
        CATALOG_INFO CataInfo = { 0 };
        CataInfo.cbStruct = sizeof(CATALOG_INFO);
        bReturn = CryptCATCatalogInfoFromContext(CataContext, &CataInfo, 0);
        if (bReturn)
        {
            CataFile = CataInfo.wszCatalogFile;
        }
        // Release catalog Context structure.
        bReturn = CryptCATAdminReleaseCatalogContext(Context, CataContext, 0);
        CataContext = NULL;
    } while (FALSE);
    if (Context)
    {
        // Release signature Context structure.
        bReturn = CryptCATAdminReleaseContext(Context, 0);
        Context = NULL;
    }

    // Get certificate information.
    bReturn = GetSignerCertificateInfo(FilePath, SignChain);
    if (!bReturn && !CataFile.empty())
    {
        // If we cannot get embedded signature information, we
        // just attempt to get cataloged signature information
        // if it has catalog or catalog is specified.
        SignType = "cataloged";
        bReturn = GetSignerCertificateInfo(CataFile.c_str(), SignChain);
    }
    return bReturn;
}

INT wmain(INT argc, WCHAR *argv[])
{
    if (argc != 2)
    {
        std::cout << "Parameter error!" << endl;
        std::cout << "Usage: PESignAnalyzer.exe filepath" << endl;
        return 0x01;
    }

    BOOL            bReturn     = FALSE;
    PWCHAR          pwzFilePath = NULL;
    std::wstring    CataFile;
    std::string     SignType;
    std::list<SIGN_NODE_INFO> SignChain;

    pwzFilePath = argv[1];
    std::wcout << L"filepath: " << pwzFilePath << endl;
    bReturn = CheckFileDigitalSignature(pwzFilePath, NULL, CataFile, SignType, SignChain);
    if (!bReturn)
    {
        std::cout << "signtype: " << "none" << endl;
        return 0x01;
    }
    std::cout  << "signtype: "              << SignType << endl;
    std::wcout << L"catafile: "             << CataFile << endl;
    std::cout  << "-----------------------" << endl;
    UINT idx = 0;
    std::list<SIGN_NODE_INFO>::iterator iter = SignChain.begin();
    for (; iter != SignChain.end(); iter++)
    {
        std::cout << "[ The "               << ++idx << " Sign Info ]" << endl;
        std::cout << "timestamp:       "    << iter->CounterSign.TimeStamp << endl;
        std::cout << "version:         "    << iter->Version << endl;
        std::cout << "digestAlgorithm: "    << iter->DigestAlgorithm << endl;

        std::list<CERT_NODE_INFO>::iterator iter1 = iter->CertChain.begin();
        for (; iter1 != iter->CertChain.end(); iter1++)
        {
            std::cout  <<  " |--" <<  "-------------------" << endl;
            std::cout  <<  " |- " <<  "subject:       " << iter1->SubjectName << endl;
            std::cout  <<  " |- " <<  "issuer:        " << iter1->IssuerName << endl;
            std::cout  <<  " |- " <<  "serial:        " << iter1->Serial << endl;
            std::cout  <<  " |- " <<  "thumbprint:    " << iter1->Thumbprint << endl;
            std::cout  <<  " |- " <<  "signAlgorithm: " << iter1->SignAlgorithm << endl;
            std::cout  <<  " |- " <<  "version:       " << iter1->Version << endl;
            std::cout  <<  " |- " <<  "notbefore:     " << iter1->NotBefore << endl;
            std::cout  <<  " |- " <<  "notafter:      " << iter1->NotAfter << endl;
            std::wcout << L" |- " << L"CRLpoint:      " << iter1->CRLpoint << endl;
        }
        std::cout << "-----------------------" << endl;
    }
    return 0x00;
}
