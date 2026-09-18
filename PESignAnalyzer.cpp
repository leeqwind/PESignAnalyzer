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
#include <vector>

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
#pragma comment(lib, "Advapi32.lib")

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
    *pParam = NULL;
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
        LocalFree(*pParam);
        *pParam = NULL;
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
    (((offset + base + 7) & ~((ULONG_PTR)0x7)) - (base & ~((ULONG_PTR)0x7)))

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
    DWORD       cbRemaining = 0x00;

    if (!AuthSignData || !AuthSignData->pSignerInfo)
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
        PCRYPT_ATTRIBUTE pNestedAttr =
            &AuthSignData->pSignerInfo->UnauthAttrs.rgAttr[n];
        if (!pNestedAttr->rgValue || pNestedAttr->cValue == 0)
        {
            __leave;
        }
        for (DWORD valueIndex = 0; valueIndex < pNestedAttr->cValue; valueIndex++)
        {
            pbCurrData = pNestedAttr->rgValue[valueIndex].pbData;
            cbRemaining = pNestedAttr->rgValue[valueIndex].cbData;
            if (!pbCurrData)
            {
                continue;
            }
            // Nested signatures can be stored side by side with 8-byte
            // alignment. Never read beyond the current attribute value.
            while (cbRemaining > 0)
            {
                SIGNDATA_HANDLE NestedHandle = { 0 };
                const DWORD cbHeader = 6 + sizeof(SG_SignedData);
                if (cbRemaining < cbHeader ||
                    memcmp(pbCurrData, SG_ProtoCoded, sizeof(SG_ProtoCoded)) ||
                    memcmp(pbCurrData + 6, SG_SignedData, sizeof(SG_SignedData)))
                {
                    break;
                }

                cbCurrData = ((DWORD)pbCurrData[2] << 8) |
                    (DWORD)pbCurrData[3];
                if (cbCurrData > MAXDWORD - 4)
                {
                    break;
                }
                cbCurrData += 4;
                if (cbCurrData > cbRemaining)
                {
                    break;
                }

                if (hNestedMsg)
                {
                    CryptMsgClose(hNestedMsg);
                    hNestedMsg = NULL;
                }
                hNestedMsg = CryptMsgOpenToDecode(
                    X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                    0, 0, 0, NULL, 0
                );
                if (!hNestedMsg)
                {
                    __leave;
                }

                bReturn = CryptMsgUpdate(hNestedMsg, pbCurrData,
                    cbCurrData, TRUE);
                if (bReturn)
                {
                    bReturn = MyCryptMsgGetParam(hNestedMsg,
                        CMSG_SIGNER_INFO_PARAM,
                        0,
                        (PVOID *)&NestedHandle.pSignerInfo,
                        &NestedHandle.dwObjSize
                    );
                }
                if (bReturn && NestedHandle.pSignerInfo)
                {
                    NestedHandle.hCertStoreHandle = CertOpenStore(
                        CERT_STORE_PROV_MSG,
                        PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
                        0, 0, hNestedMsg
                    );
                    if (NestedHandle.hCertStoreHandle)
                    {
                        bSucceed = TRUE;
                        NestedChain.push_back(NestedHandle);
                    }
                    else
                    {
                        LocalFree(NestedHandle.pSignerInfo);
                    }
                }

                if (cbRemaining == cbCurrData)
                {
                    break;
                }
                ULONG_PTR cbAdvance = _8BYTE_ALIGN(cbCurrData,
                    (ULONG_PTR)pbCurrData);
                if (cbAdvance < cbCurrData || cbAdvance > cbRemaining)
                {
                    break;
                }
                pbNextData = pbCurrData + cbAdvance;
                cbRemaining -= (DWORD)cbAdvance;
                pbCurrData = pbNextData;
            }
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
            LocalFree(*pTargetSigner);
            *pTargetSigner = NULL;
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
    return dwStart <= dwSize && dwRequestSize <= dwSize - dwStart;
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
    if (dwSize < 1)
    {
        return FALSE;
    }
    if (pbSignature[0] >= 0x80 &&
        !SafeToReadNBytes(dwSize, 1, pbSignature[0] & 0x7F))
    {
        return FALSE;
    }
    if (pbSignature[0] < 0x80)
    {
        dwSizefound = pbSignature[0];
        dwBytesParsed = 1;
    }
    else
    {
        DWORD cbLengthBytes = pbSignature[0] & 0x7F;
        if (cbLengthBytes > sizeof(DWORD))
        {
            return FALSE;
        }
        dwSizefound = ReadNumberFromNBytes(pbSignature, 1, cbLengthBytes);
        dwBytesParsed = 1 + cbLengthBytes;
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
    BOOL        bReturn         = FALSE;
    DWORD       dwPositionFound = 0;
    DWORD       dwLengthFound   = 0;
    DWORD       dwPositionError = 0;
    DWORD       n               = 0;
    INT         iTypeError      = 0;
    SYSTEMTIME  sst, lst;
    FILETIME    fft, lft;
    CHAR        szBuffer[256]   = { 0 };

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
    if (dwLengthFound >= sizeof(szBuffer))
    {
        return FALSE;
    }
    memcpy_s(szBuffer, sizeof(szBuffer), (CHAR *)&(pbOctetString[dwPositionFound]), dwLengthFound);
    szBuffer[dwLengthFound] = 0;
    int iFields = _snscanf_s(szBuffer, (int)_countof(szBuffer), "%04d%02d%02d%02d%02d%02d.%03dZ",
        &wYear,
        &wMonth,
        &wDay,
        &wHour,
        &wMinute,
        &wSecond,
        &wMilliseconds
    );
    if (iFields < 6)
    {
        iFields = _snscanf_s(szBuffer, (int)_countof(szBuffer), "%04d%02d%02d%02d%02d%02dZ",
            &wYear,
            &wMonth,
            &wDay,
            &wHour,
            &wMinute,
            &wSecond
        );
        if (iFields < 6)
        {
            return FALSE;
        }
        wMilliseconds = 0;
    }
    if (wYear < 1970 || wYear > 9999 || wMonth < 1 || wMonth > 12 ||
        wDay < 1 || wDay > 31 || wHour > 23 || wMinute > 59 || wSecond > 59)
    {
        return FALSE;
    }
    sst.wYear         = (WORD)wYear;
    sst.wMonth        = (WORD)wMonth;
    sst.wDay          = (WORD)wDay;
    sst.wHour         = (WORD)wHour;
    sst.wMinute       = (WORD)wMinute;
    sst.wSecond       = (WORD)wSecond;
    sst.wMilliseconds = (WORD)wMilliseconds;
    if (!SystemTimeToFileTime(&sst, &fft))
    {
        return FALSE;
    }
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
    BOOL  bResult     = FALSE;

    dwData = CertGetNameStringA(pCertContext, Type, Flag, NULL, NULL, 0);
    if (!dwData)
    {
        return FALSE;
    }
    pszTempName = (LPSTR)LocalAlloc(LPTR, dwData * sizeof(CHAR));
    if (!pszTempName)
    {
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
    else if (!strcmp(pszObjId, szOID_NIST_sha384))
    {
        Algorithm = "SHA384";
    }
    else if (!strcmp(pszObjId, szOID_NIST_sha512))
    {
        Algorithm = "SHA512";
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
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA384RSA))
    {
        Algorithm = "sha384RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_RSA_SHA512RSA))
    {
        Algorithm = "sha512RSA(RSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_ECDSA_SHA1))
    {
        Algorithm = "sha1ECDSA(ECDSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_ECDSA_SHA256))
    {
        Algorithm = "sha256ECDSA(ECDSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_ECDSA_SHA384))
    {
        Algorithm = "sha384ECDSA(ECDSA)";
    }
    else if (0 == strcmp(pszObjId, szOID_ECDSA_SHA512))
    {
        Algorithm = "sha512ECDSA(ECDSA)";
    }
    else
    {
        Algorithm = pszObjId;
    }
    StripString(Algorithm);
    return TRUE;
}

#define SHA1LEN    20
#define SHA256LEN  32
#define SHA384LEN  48
#define SHA512LEN  64
#define BUFSIZE    2048
#define MD5LEN     16
#define MAX_HASHLEN 64

BOOL CalculateHashOfBytes(
    BYTE *pbBinary,
    ALG_ID Algid,
    DWORD dwBinary,
    std::string & Hash
) {
    BOOL        bReturn             = FALSE;
    HCRYPTPROV  hProv               = 0;
    HCRYPTHASH  hHash               = 0;
    DWORD       cbHash              = 0;
    BYTE        rgbHash[MAX_HASHLEN] = { 0 };
    CHAR        hexbyte[3]          = { 0 };
    CONST CHAR  rgbDigits[]         = "0123456789abcdef";
    std::string CalcHash;

    bReturn = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (!bReturn)
    {
        // Fallback to PROV_RSA_FULL if PROV_RSA_AES is not available
        bReturn = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
        if (!bReturn)
        {
            return FALSE;
        }
    }
    bReturn = CryptCreateHash(hProv, Algid, 0, 0, &hHash);
    if (!bReturn)
    {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    bReturn = CryptHashData(hHash, pbBinary, dwBinary, 0);
    if (!bReturn)
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }
    switch (Algid)
    {
    case CALG_SHA1:
        cbHash = SHA1LEN;
        break;
    case CALG_MD5:
        cbHash = MD5LEN;
        break;
    case CALG_SHA_256:
        cbHash = SHA256LEN;
        break;
    case CALG_SHA_384:
        cbHash = SHA384LEN;
        break;
    case CALG_SHA_512:
        cbHash = SHA512LEN;
        break;
    default:
    {
        // Query the actual hash size
        DWORD dwParamSize = sizeof(cbHash);
        bReturn = CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHash, &dwParamSize, 0);
        if (!bReturn || cbHash == 0 || cbHash > MAX_HASHLEN)
        {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return FALSE;
        }
        break;
    }
    }
    hexbyte[2] = '\0';
    bReturn = CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0);
    if (!bReturn)
    {
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
    PCRL_DIST_POINTS_INFO   pCRLDistPoint   = NULL;
    PCRL_DIST_POINT_NAME    dpn             = NULL;
    PCERT_EXTENSION         pe              = NULL;
    ULONG                   ulDataLen       = 0;

    CRLpoint.clear();
    pe = CertFindExtension(szOID_CRL_DIST_POINTS, cExtensions, rgExtensions);
    if (!pe)
    {
        return FALSE;
    }
    // First query required size
    bReturn = CryptDecodeObject(MY_ENCODING, szOID_CRL_DIST_POINTS,
        pe->Value.pbData,
        pe->Value.cbData,
        CRYPT_DECODE_NOCOPY_FLAG,
        NULL, &ulDataLen
    );
    if (!bReturn || ulDataLen == 0)
    {
        return FALSE;
    }
    // Allocate from heap to avoid stack overflow
    pCRLDistPoint = (PCRL_DIST_POINTS_INFO)LocalAlloc(LPTR, ulDataLen);
    if (!pCRLDistPoint)
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
        LocalFree(pCRLDistPoint);
        return FALSE;
    }
    std::wstring csProperty;
    for (ULONG idx = 0; idx < pCRLDistPoint->cDistPoint; idx++)
    {
        dpn = &pCRLDistPoint->rgDistPoint[idx].DistPointName;
        for (ULONG ulAltEntry = 0; ulAltEntry < dpn->FullName.cAltEntry; ulAltEntry++)
        {
            if (!csProperty.empty() && dpn->FullName.rgAltEntry[ulAltEntry].pwszURL)
            {
                csProperty += L";";
            }
            if (dpn->FullName.rgAltEntry[ulAltEntry].pwszURL)
            {
                csProperty += dpn->FullName.rgAltEntry[ulAltEntry].pwszURL;
            }
        }
    }
    CRLpoint = csProperty;
    LocalFree(pCRLDistPoint);
    return TRUE;
}

BOOL CalculateSignSerial(
    BYTE *pbData,
    DWORD cbData,
    std::string & Serial
) {
    BOOL  bReturn = FALSE;
    DWORD dwSize  = 0;

    Serial.clear();
    if (!pbData || cbData == 0)
    {
        return FALSE;
    }
    std::vector<BYTE> abSerial(cbData);
    for (DWORD uiIter = 0; uiIter < cbData; uiIter++)
    {
        abSerial[uiIter] = pbData[cbData - 1 - uiIter];
    }
    bReturn = CryptBinaryToStringA(&abSerial[0], cbData,
        CRYPT_STRING_HEX, NULL, &dwSize);
    if (!bReturn)
    {
        return FALSE;
    }
    std::vector<CHAR> NameBuff(dwSize + 1, 0);
    DWORD dwBufferSize = (DWORD)NameBuff.size();
    bReturn = CryptBinaryToStringA(&abSerial[0], cbData,
        CRYPT_STRING_HEX, &NameBuff[0], &dwBufferSize);
    if (!bReturn)
    {
        return FALSE;
    }
    DWORD dwIter2 = 0;
    for (DWORD dwIter1 = 0;
        dwIter1 < dwBufferSize && NameBuff[dwIter1] != '\0';
        dwIter1++)
    {
        if (!isspace((unsigned char)NameBuff[dwIter1]))
        {
            NameBuff[dwIter2++] = NameBuff[dwIter1];
        }
    }
    NameBuff[dwIter2] = '\0';
    Serial = std::string(&NameBuff[0]);
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
    PCERT_INFO      pCertInfo = pCurrContext->pCertInfo;
    LPCSTR          szObjId   = NULL;
    CERT_NODE_INFO  CertNode;

    // Get certificate algorithm.
    szObjId = pCertInfo->SignatureAlgorithm.pszObjId;
    if (!CalculateCertAlgorithm(szObjId, CertNode.SignAlgorithm))
    {
        CertNode.SignAlgorithm = "Unknown";
    }
    // Get certificate serial.
    if (!CalculateSignSerial(pCertInfo->SerialNumber.pbData,
        pCertInfo->SerialNumber.cbData,
        CertNode.Serial
    )) {
        CertNode.Serial = "";
    }
    // Get certificate version.
    if (!CalculateSignVersion(pCertInfo->dwVersion, CertNode.Version))
    {
        CertNode.Version = "Unknown";
    }
    // Get certficate subject.
    if (!GetStringFromCertContext(pCurrContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        CertNode.SubjectName
    )) {
        CertNode.SubjectName = "";
    }
    // Get certificate issuer.
    if (!GetStringFromCertContext(pCurrContext,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        CERT_NAME_ISSUER_FLAG,
        CertNode.IssuerName
    )) {
        CertNode.IssuerName = "";
    }
    // Get certificate thumbprint.
    if (!CalculateHashOfBytes(pCurrContext->pbCertEncoded,
        CALG_SHA1,
        pCurrContext->cbCertEncoded,
        CertNode.Thumbprint
    )) {
        CertNode.Thumbprint = "";
    }
    // Get certificate CRL point.
    CalculateCertCRLpoint(pCertInfo->cExtension,
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
    // The system root store is optional. Embedded signature parsing must
    // continue to work when the current-user store is unavailable.
    if (!pCurrContext && hSystemStore)
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
        if (hSystemStore) CertCloseStore(hSystemStore, 0);
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
        if (hSystemStore) CertCloseStore(hSystemStore, 0);
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
        CERT_INFO           SignerCertInfo = { 0 };

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
        CalculateDigestAlgorithm(szObjId, SignNode.DigestAlgorithm);
        // Get signature version.
        CalculateSignVersion(iter->pSignerInfo->dwVersion, SignNode.Version);
        // Match both issuer and serial number so another certificate issued
        // by the same CA cannot be mistaken for the signer certificate.
        SignerCertInfo.Issuer = iter->pSignerInfo->Issuer;
        SignerCertInfo.SerialNumber = iter->pSignerInfo->SerialNumber;
        pCurrContext = CertFindCertificateInStore(iter->hCertStoreHandle,
            MY_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            &SignerCertInfo,
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
        if (!SignNode.CertChain.empty())
        {
            bSucceed = TRUE;
            SignChain.push_back(SignNode);
        }
    }
    if (hSystemStore) CertCloseStore(hSystemStore, 0);
    return bSucceed;
}

BOOL MyCryptCalcFileHash(
    HANDLE FileHandle,
    PBYTE *szBuffer,
    DWORD *HashSize
) {
    BOOL bReturn = FALSE;
    if (!szBuffer || !HashSize || INVALID_HANDLE_VALUE == FileHandle)
    {
        return FALSE;
    }
    *szBuffer = NULL;
    *HashSize = 0x00;
    // Get size. Note: Many Windows Crypto APIs return FALSE
    // when querying the required buffer size (ERROR_INSUFFICIENT_BUFFER),
    // but still output the correct size. So only check HashSize output here.
    CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, NULL, 0x00);
    if (0 == *HashSize) // HashSize being zero means fatal error.
    {
        return FALSE;
    }
    *szBuffer = (PBYTE)calloc(*HashSize, 1);
    if (!*szBuffer)
    {
        *HashSize = 0;
        return FALSE;
    }
    bReturn = CryptCATAdminCalcHashFromFileHandle(FileHandle, HashSize, *szBuffer, 0x00);
    if (!bReturn)
    {
        free(*szBuffer);
        *szBuffer = NULL;
        *HashSize = 0;
    }
    return bReturn;
}

typedef BOOL (WINAPI *PFN_CRYPTCATADMINACQUIRECONTEXT2)(
    HCATADMIN *, const GUID *, PCWSTR, PCCERT_STRONG_SIGN_PARA, DWORD);

BOOL MyCryptCATAdminAcquireContext(
    HCATADMIN *Context,
    LPCWSTR HashAlgorithm
) {
    if (!Context)
    {
        return FALSE;
    }
    *Context = NULL;
    if (HashAlgorithm)
    {
        HMODULE hWintrust = GetModuleHandleW(L"wintrust.dll");
        PFN_CRYPTCATADMINACQUIRECONTEXT2 pAcquireContext2 = hWintrust ?
            (PFN_CRYPTCATADMINACQUIRECONTEXT2)GetProcAddress(hWintrust,
                "CryptCATAdminAcquireContext2") : NULL;
        if (pAcquireContext2)
        {
            return pAcquireContext2(Context, NULL, HashAlgorithm, NULL, 0);
        }
        // Windows versions before AcquireContext2 only support the legacy
        // default catalog hash algorithm.
        if (lstrcmpiW(HashAlgorithm, L"SHA1") != 0)
        {
            return FALSE;
        }
    }
    return CryptCATAdminAcquireContext(Context, NULL, 0);
}

BOOL AnalyzeFileDigitalSignature(
    LPCWSTR FilePath,
    LPCWSTR CataPath,
    std::wstring & CataFile,
    std::string & SignType,
    std::list<SIGN_NODE_INFO> & SignChain
) {
    HCATADMIN Context     = NULL;
    BOOL    bReturn      = FALSE;
    BOOL    bHasCatalog  = FALSE;

    CataFile = CataPath ? CataPath : L"";
    SignType = "embedded";

    if (CataPath)
    {
        bHasCatalog = !CataFile.empty();
    }
    else
    {
        LPCWSTR HashAlgorithms[] = { L"SHA256", L"SHA1" };
        for (UINT hashIndex = 0;
            hashIndex < _countof(HashAlgorithms) && !bHasCatalog;
            hashIndex++)
        {
            do
            {
                // Acquire a catalog context for the requested hash algorithm.
                bReturn = MyCryptCATAdminAcquireContext(&Context,
                    HashAlgorithms[hashIndex]);
                if (!bReturn)
                {
                    break;
                }
        // Open the specified file handle to get the file hash.
        HANDLE FileHandle = CreateFileW(FilePath, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
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
        FileHandle = INVALID_HANDLE_VALUE;
        if (!bReturn || !szBuffer || 0 == dwHashSize)
        {
            if (szBuffer) free(szBuffer);
            break;
        }
        // Enumerate catalogs by passing the previous returned context back to
        // the API. The API advances and releases the previous enumeration
        // context; retain the last successfully resolved catalog path.
        HCATINFO CataContext = NULL;
        CataContext = CryptCATAdminEnumCatalogFromHash(Context,
            szBuffer,
            dwHashSize,
            0,
            &CataContext
        );
        while (CataContext)
        {
            CATALOG_INFO CataInfo = { 0 };
            CataInfo.cbStruct = sizeof(CATALOG_INFO);
            if (CryptCATCatalogInfoFromContext(CataContext, &CataInfo, 0))
            {
                CataFile = CataInfo.wszCatalogFile;
                bHasCatalog = !CataFile.empty();
            }
            CataContext = CryptCATAdminEnumCatalogFromHash(Context,
                szBuffer,
                dwHashSize,
                0,
                &CataContext
            );
        }
        free(szBuffer);
        szBuffer = NULL;
            } while (FALSE);
            if (Context)
            {
                CryptCATAdminReleaseContext(Context, 0);
                Context = NULL;
            }
        }
    }

    // Get certificate information.
    bReturn = GetSignerCertificateInfo(FilePath, SignChain);
    if (!bReturn && bHasCatalog)
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
    bReturn = AnalyzeFileDigitalSignature(pwzFilePath, NULL, CataFile, SignType, SignChain);
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
