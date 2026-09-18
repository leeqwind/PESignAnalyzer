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
#include <list>
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
#pragma comment(lib, "Advapi32.lib")

#define PESIGNANALYZER_VERSION "1.3.0"

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

enum REVOCATION_MODE {
    REVOCATION_NONE,
    REVOCATION_CACHE,
    REVOCATION_ONLINE
};

static CONST ALG_ID CATALOG_HASH_ALGORITHMS[] = {
    CALG_SHA_256, CALG_SHA1, CALG_SHA_384, CALG_SHA_512
};

typedef struct _VERIFY_RESULT {
    std::string ContentDigest;
    std::string CmsSignature;
    std::string CertificateChain;
    std::string TimeStamp;
    std::string Revocation;
    std::string Overall;
    DWORD Error;
} VERIFY_RESULT, *PVERIFY_RESULT;

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
    _snprintf_s(szBuffer, 256, "%04u/%02u/%02u %02u:%02u:%02u",
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
    int iFields = _snscanf_s(szBuffer, (int)_countof(szBuffer), "%04lu%02lu%02lu%02lu%02lu%02lu.%03luZ",
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
        iFields = _snscanf_s(szBuffer, (int)_countof(szBuffer), "%04lu%02lu%02lu%02lu%02lu%02luZ",
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

BOOL ReadDERElement(
    CONST BYTE *Data,
    DWORD DataSize,
    DWORD & Offset,
    BYTE & Tag,
    CONST BYTE * & Value,
    DWORD & ValueSize
) {
    if (!Data || Offset >= DataSize)
    {
        return FALSE;
    }
    Tag = Data[Offset++];
    if (Offset >= DataSize)
    {
        return FALSE;
    }
    BYTE lengthByte = Data[Offset++];
    if ((lengthByte & 0x80) == 0)
    {
        ValueSize = lengthByte;
    }
    else
    {
        DWORD lengthBytes = lengthByte & 0x7f;
        if (lengthBytes == 0 || lengthBytes > sizeof(DWORD) ||
            lengthBytes > DataSize - Offset)
        {
            return FALSE;
        }
        ValueSize = 0;
        for (DWORD index = 0; index < lengthBytes; index++)
        {
            if (ValueSize > (MAXDWORD - Data[Offset]) / 256)
            {
                return FALSE;
            }
            ValueSize = ValueSize * 256 + Data[Offset++];
        }
    }
    if (ValueSize > DataSize - Offset)
    {
        return FALSE;
    }
    Value = Data + Offset;
    Offset += ValueSize;
    return TRUE;
}

ALG_ID DigestAlgorithmFromDEROID(CONST BYTE *Oid, DWORD OidSize)
{
    static CONST BYTE OidMd5[] =
        { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05 };
    static CONST BYTE OidSha1[] =
        { 0x2b, 0x0e, 0x03, 0x02, 0x1a };
    static CONST BYTE OidSha256[] =
        { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
    static CONST BYTE OidSha384[] =
        { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
    static CONST BYTE OidSha512[] =
        { 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };

#define MATCH_DER_OID(value) \
    (OidSize == sizeof(value) && memcmp(Oid, value, sizeof(value)) == 0)
    if (MATCH_DER_OID(OidMd5)) return CALG_MD5;
    if (MATCH_DER_OID(OidSha1)) return CALG_SHA1;
    if (MATCH_DER_OID(OidSha256)) return CALG_SHA_256;
    if (MATCH_DER_OID(OidSha384)) return CALG_SHA_384;
    if (MATCH_DER_OID(OidSha512)) return CALG_SHA_512;
#undef MATCH_DER_OID
    return 0;
}

BOOL ParseAuthenticodeDigest(
    CONST BYTE *Content,
    DWORD ContentSize,
    ALG_ID & Algorithm,
    std::vector<BYTE> & Digest
) {
    BYTE tag = 0;
    CONST BYTE *value = NULL;
    DWORD valueSize = 0;
    DWORD offset = 0;
    if (!ReadDERElement(Content, ContentSize, offset, tag, value, valueSize) ||
        tag != 0x30 || offset != ContentSize)
    {
        return FALSE;
    }

    CONST BYTE *root = value;
    DWORD rootSize = valueSize;
    DWORD rootOffset = 0;
    // Skip SpcAttributeTypeAndOptionalValue.
    if (!ReadDERElement(root, rootSize, rootOffset, tag, value, valueSize) ||
        tag != 0x30)
    {
        return FALSE;
    }
    // Decode DigestInfo.
    if (!ReadDERElement(root, rootSize, rootOffset, tag, value, valueSize) ||
        tag != 0x30 || rootOffset != rootSize)
    {
        return FALSE;
    }
    CONST BYTE *digestInfo = value;
    DWORD digestInfoSize = valueSize;
    DWORD digestOffset = 0;
    if (!ReadDERElement(digestInfo, digestInfoSize, digestOffset,
        tag, value, valueSize) || tag != 0x30)
    {
        return FALSE;
    }
    CONST BYTE *algorithmInfo = value;
    DWORD algorithmInfoSize = valueSize;
    DWORD algorithmOffset = 0;
    if (!ReadDERElement(algorithmInfo, algorithmInfoSize, algorithmOffset,
        tag, value, valueSize) || tag != 0x06)
    {
        return FALSE;
    }
    Algorithm = DigestAlgorithmFromDEROID(value, valueSize);
    if (!Algorithm)
    {
        return FALSE;
    }
    if (!ReadDERElement(digestInfo, digestInfoSize, digestOffset,
        tag, value, valueSize) || tag != 0x04 || digestOffset != digestInfoSize)
    {
        return FALSE;
    }
    Digest.assign(value, value + valueSize);
    return !Digest.empty();
}

BOOL FindCatalogMemberInDER(
    CONST BYTE * Data,
    DWORD DataSize,
    CONST std::vector<BYTE> & Digest,
    DWORD Depth = 0
) {
    if (!Data || Digest.empty() || Depth > 32) return FALSE;
    DWORD offset = 0;
    while (offset < DataSize)
    {
        BYTE tag = 0;
        CONST BYTE *value = NULL;
        DWORD valueSize = 0;
        if (!ReadDERElement(Data, DataSize, offset, tag, value, valueSize))
            return FALSE;
        if (tag == 0x30)
        {
            DWORD childOffset = 0;
            BYTE childTag = 0;
            CONST BYTE *childValue = NULL;
            DWORD childSize = 0;
            if (ReadDERElement(value, valueSize, childOffset, childTag,
                    childValue, childSize) && childTag == 0x04 &&
                childSize == Digest.size() &&
                memcmp(childValue, &Digest[0], Digest.size()) == 0)
            {
                BYTE secondTag = 0;
                CONST BYTE *secondValue = NULL;
                DWORD secondSize = 0;
                if (ReadDERElement(value, valueSize, childOffset, secondTag,
                        secondValue, secondSize) && secondTag == 0x31)
                    return TRUE;
            }
        }
        if ((tag & 0x20) &&
            FindCatalogMemberInDER(value, valueSize, Digest, Depth + 1))
            return TRUE;
    }
    return FALSE;
}

BOOL CalculateAuthenticodeHash(
    LPCWSTR FileName,
    ALG_ID Algorithm,
    std::vector<BYTE> & Digest
) {
    BOOL result = FALSE;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    std::vector<BYTE> fileData;
    Digest.clear();

    fileHandle = CreateFileW(FileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        return FALSE;
    }
    LARGE_INTEGER fileSize = { 0 };
    if (!GetFileSizeEx(fileHandle, &fileSize) || fileSize.QuadPart <= 0 ||
        fileSize.QuadPart > MAXDWORD)
    {
        goto Cleanup;
    }
    fileData.resize((size_t)fileSize.QuadPart);
    DWORD bytesRead = 0;
    if (!ReadFile(fileHandle, &fileData[0], (DWORD)fileData.size(),
        &bytesRead, NULL) || bytesRead != fileData.size())
    {
        goto Cleanup;
    }

    if (fileData.size() < sizeof(IMAGE_DOS_HEADER)) goto Cleanup;
    PIMAGE_DOS_HEADER dosHeader =
        (PIMAGE_DOS_HEADER)&fileData[0];
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE || dosHeader->e_lfanew < 0)
        goto Cleanup;
    size_t ntOffset = (size_t)dosHeader->e_lfanew;
    if (ntOffset > fileData.size() - sizeof(DWORD) -
        sizeof(IMAGE_FILE_HEADER)) goto Cleanup;
    if (*(DWORD *)(&fileData[ntOffset]) != IMAGE_NT_SIGNATURE) goto Cleanup;

    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)
        (&fileData[ntOffset + sizeof(DWORD)]);
    size_t optionalOffset = ntOffset + sizeof(DWORD) +
        sizeof(IMAGE_FILE_HEADER);
    if (fileHeader->SizeOfOptionalHeader < sizeof(WORD) ||
        optionalOffset > fileData.size() - fileHeader->SizeOfOptionalHeader)
        goto Cleanup;

    WORD optionalMagic = *(WORD *)(&fileData[optionalOffset]);
    size_t checkSumOffset = 0;
    size_t certificateDirectoryOffset = 0;
    DWORD numberOfRvaAndSizes = 0;
    if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        if (fileHeader->SizeOfOptionalHeader <
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            (IMAGE_DIRECTORY_ENTRY_SECURITY + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            goto Cleanup;
        PIMAGE_OPTIONAL_HEADER32 optionalHeader =
            (PIMAGE_OPTIONAL_HEADER32)&fileData[optionalOffset];
        checkSumOffset = optionalOffset +
            offsetof(IMAGE_OPTIONAL_HEADER32, CheckSum);
        certificateDirectoryOffset = optionalOffset +
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
        numberOfRvaAndSizes = optionalHeader->NumberOfRvaAndSizes;
    }
    else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        if (fileHeader->SizeOfOptionalHeader <
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            (IMAGE_DIRECTORY_ENTRY_SECURITY + 1) * sizeof(IMAGE_DATA_DIRECTORY))
            goto Cleanup;
        PIMAGE_OPTIONAL_HEADER64 optionalHeader =
            (PIMAGE_OPTIONAL_HEADER64)&fileData[optionalOffset];
        checkSumOffset = optionalOffset +
            offsetof(IMAGE_OPTIONAL_HEADER64, CheckSum);
        certificateDirectoryOffset = optionalOffset +
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) +
            IMAGE_DIRECTORY_ENTRY_SECURITY * sizeof(IMAGE_DATA_DIRECTORY);
        numberOfRvaAndSizes = optionalHeader->NumberOfRvaAndSizes;
    }
    else
    {
        goto Cleanup;
    }
    if (numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY ||
        checkSumOffset + sizeof(DWORD) > certificateDirectoryOffset ||
        certificateDirectoryOffset + sizeof(IMAGE_DATA_DIRECTORY) >
            fileData.size())
        goto Cleanup;

    PIMAGE_DATA_DIRECTORY certificateDirectory = (PIMAGE_DATA_DIRECTORY)
        &fileData[certificateDirectoryOffset];
    size_t digestEnd = fileData.size();
    if (certificateDirectory->Size)
    {
        if (certificateDirectory->VirtualAddress <
                certificateDirectoryOffset + sizeof(IMAGE_DATA_DIRECTORY) ||
            certificateDirectory->VirtualAddress > fileData.size() ||
            certificateDirectory->Size > fileData.size() -
                certificateDirectory->VirtualAddress)
            goto Cleanup;
        digestEnd = certificateDirectory->VirtualAddress;
    }
    else if (certificateDirectory->VirtualAddress != 0)
    {
        goto Cleanup;
    }

    if (!CryptAcquireContext(&provider, NULL, NULL, PROV_RSA_AES,
        CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(provider, Algorithm, 0, 0, &hash))
    {
        goto Cleanup;
    }
    if (!CryptHashData(hash, &fileData[0], (DWORD)checkSumOffset, 0) ||
        !CryptHashData(hash, &fileData[checkSumOffset + sizeof(DWORD)],
            (DWORD)(certificateDirectoryOffset - checkSumOffset -
                sizeof(DWORD)), 0) ||
        !CryptHashData(hash,
            &fileData[certificateDirectoryOffset +
                sizeof(IMAGE_DATA_DIRECTORY)],
            (DWORD)(digestEnd -
                certificateDirectoryOffset -
                sizeof(IMAGE_DATA_DIRECTORY)), 0))
        goto Cleanup;
    DWORD hashSize = 0;
    DWORD parameterSize = sizeof(hashSize);
    if (!CryptGetHashParam(hash, HP_HASHSIZE, (PBYTE)&hashSize,
        &parameterSize, 0) || hashSize == 0)
    {
        goto Cleanup;
    }
    Digest.resize(hashSize);
    if (!CryptGetHashParam(hash, HP_HASHVAL, &Digest[0], &hashSize, 0))
    {
        Digest.clear();
        goto Cleanup;
    }
    result = TRUE;

Cleanup:
    if (hash) CryptDestroyHash(hash);
    if (provider) CryptReleaseContext(provider, 0);
    if (fileHandle != INVALID_HANDLE_VALUE) CloseHandle(fileHandle);
    return result;
}

PCCERT_CONTEXT FindSignerCertificate(
    HCERTSTORE CertStore,
    PCMSG_SIGNER_INFO SignerInfo
) {
    if (!CertStore || !SignerInfo)
    {
        return NULL;
    }
    CERT_INFO findInfo = { 0 };
    findInfo.Issuer = SignerInfo->Issuer;
    findInfo.SerialNumber = SignerInfo->SerialNumber;
    return CertFindCertificateInStore(CertStore, MY_ENCODING, 0,
        CERT_FIND_SUBJECT_CERT, &findInfo, NULL);
}

BOOL VerifyCmsSigner(
    HCRYPTMSG Message,
    PCCERT_CONTEXT SignerCertificate
) {
    if (!Message || !SignerCertificate)
    {
        return FALSE;
    }
    CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA verify = { 0 };
    verify.cbSize = sizeof(verify);
    verify.dwSignerIndex = 0;
    verify.dwSignerType = CMSG_VERIFY_SIGNER_CERT;
    verify.pvSigner = (PVOID)SignerCertificate;
    return CryptMsgControl(Message, 0,
        CMSG_CTRL_VERIFY_SIGNATURE_EX, &verify);
}

BOOL VerifySignerChain(
    PCCERT_CONTEXT SignerCertificate,
    HCERTSTORE AdditionalStore,
    REVOCATION_MODE Revocation,
    CONST FILETIME * VerificationTime,
    BOOL TimeStampPolicy,
    std::string & ChainStatus,
    std::string & RevocationStatus
) {
    CERT_CHAIN_PARA chainParameters = { 0 };
    CERT_CHAIN_POLICY_PARA policyParameters = { 0 };
    CERT_CHAIN_POLICY_STATUS policyStatus = { 0 };
    PCCERT_CHAIN_CONTEXT chain = NULL;
    LPSTR usageOid = TimeStampPolicy ?
        (LPSTR)szOID_PKIX_KP_TIMESTAMP_SIGNING :
        (LPSTR)szOID_PKIX_KP_CODE_SIGNING;

    chainParameters.cbSize = sizeof(chainParameters);
    chainParameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    chainParameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    chainParameters.RequestedUsage.Usage.rgpszUsageIdentifier = &usageOid;
    DWORD chainFlags = 0;
    if (Revocation != REVOCATION_NONE)
    {
        chainFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
            CERT_CHAIN_REVOCATION_ACCUMULATIVE_TIMEOUT;
        if (Revocation == REVOCATION_CACHE)
        {
            chainFlags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY |
                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
        }
    }
    if (!CertGetCertificateChain(NULL, SignerCertificate,
        (LPFILETIME)VerificationTime, AdditionalStore, &chainParameters,
        chainFlags, NULL, &chain))
    {
        ChainStatus = "error";
        RevocationStatus = Revocation == REVOCATION_NONE ?
            "not_checked" : "unknown";
        return FALSE;
    }

    DWORD trustErrors = chain->TrustStatus.dwErrorStatus;
    if (Revocation == REVOCATION_NONE)
    {
        RevocationStatus = "not_checked";
    }
    else if (trustErrors & CERT_TRUST_IS_REVOKED)
    {
        RevocationStatus = "revoked";
    }
    else if (trustErrors & (CERT_TRUST_REVOCATION_STATUS_UNKNOWN |
        CERT_TRUST_IS_OFFLINE_REVOCATION))
    {
        RevocationStatus = "unknown";
    }
    else
    {
        RevocationStatus = "good";
    }

    policyParameters.cbSize = sizeof(policyParameters);
    policyStatus.cbSize = sizeof(policyStatus);
    LPCSTR policy = TimeStampPolicy ? CERT_CHAIN_POLICY_AUTHENTICODE_TS :
        CERT_CHAIN_POLICY_AUTHENTICODE;
    BOOL policyCall = CertVerifyCertificateChainPolicy(policy, chain,
        &policyParameters, &policyStatus);
    BOOL trusted = policyCall && policyStatus.dwError == ERROR_SUCCESS;
    ChainStatus = trusted ? "trusted" : "untrusted";
    CertFreeCertificateChain(chain);
    if (!trusted && Revocation != REVOCATION_NONE &&
        RevocationStatus == "unknown")
    {
        std::string noRevocationChain;
        std::string ignoredRevocation;
        if (VerifySignerChain(SignerCertificate, AdditionalStore,
            REVOCATION_NONE, VerificationTime, TimeStampPolicy,
            noRevocationChain, ignoredRevocation))
        {
            ChainStatus = "trusted";
            return TRUE;
        }
    }
    return trusted;
}

void MergeRevocationStatus(
    CONST std::string & AdditionalStatus,
    std::string & Status
) {
    if (Status == "revoked" || AdditionalStatus == "revoked")
        Status = "revoked";
    else if (Status == "unknown" || AdditionalStatus == "unknown")
        Status = "unknown";
    else if (Status == "good" || AdditionalStatus == "good")
        Status = "good";
    else
        Status = "not_checked";
}

BOOL VerifyRfc3161TimeStamp(
    PCMSG_SIGNER_INFO SignerInfo,
    HCERTSTORE AdditionalStore,
    REVOCATION_MODE Revocation,
    FILETIME & SigningTime,
    std::string & TimeStampStatus,
    std::string & RevocationStatus
) {
    if (!SignerInfo) return FALSE;
    for (DWORD attributeIndex = 0;
        attributeIndex < SignerInfo->UnauthAttrs.cAttr; attributeIndex++)
    {
        PCRYPT_ATTRIBUTE attribute =
            &SignerInfo->UnauthAttrs.rgAttr[attributeIndex];
        if (!attribute->pszObjId ||
            lstrcmpA(attribute->pszObjId, szOID_RFC3161_counterSign) != 0)
            continue;
        TimeStampStatus = "invalid";
        for (DWORD valueIndex = 0; valueIndex < attribute->cValue;
            valueIndex++)
        {
            PCRYPT_TIMESTAMP_CONTEXT timeStampContext = NULL;
            PCCERT_CONTEXT timeStampSigner = NULL;
            HCERTSTORE timeStampStore = NULL;
            BOOL verified = CryptVerifyTimeStampSignature(
                attribute->rgValue[valueIndex].pbData,
                attribute->rgValue[valueIndex].cbData,
                SignerInfo->EncryptedHash.pbData,
                SignerInfo->EncryptedHash.cbData,
                AdditionalStore, &timeStampContext, &timeStampSigner,
                &timeStampStore);
            if (verified) TimeStampStatus = "untrusted";
            if (verified && timeStampContext &&
                timeStampContext->pTimeStamp && timeStampSigner)
            {
                std::string chainStatus;
                std::string timeStampRevocation;
                SigningTime = timeStampContext->pTimeStamp->ftTime;
                BOOL trusted = VerifySignerChain(timeStampSigner,
                    timeStampStore ? timeStampStore : AdditionalStore,
                    Revocation, &SigningTime, TRUE, chainStatus,
                    timeStampRevocation);
                MergeRevocationStatus(timeStampRevocation, RevocationStatus);
                if (trusted) TimeStampStatus = "valid";
            }
            if (timeStampStore) CertCloseStore(timeStampStore, 0);
            if (timeStampSigner)
                CertFreeCertificateContext(timeStampSigner);
            if (timeStampContext) CryptMemFree(timeStampContext);
            if (TimeStampStatus == "valid") return TRUE;
        }
        return FALSE;
    }
    TimeStampStatus = "absent";
    return FALSE;
}

BOOL GetSignerSigningTime(
    PCMSG_SIGNER_INFO SignerInfo,
    FILETIME & SigningTime
) {
    if (!SignerInfo) return FALSE;
    for (DWORD index = 0; index < SignerInfo->AuthAttrs.cAttr; index++)
    {
        PCRYPT_ATTRIBUTE attribute = &SignerInfo->AuthAttrs.rgAttr[index];
        if (!attribute->pszObjId ||
            lstrcmpA(attribute->pszObjId, szOID_RSA_signingTime) != 0 ||
            attribute->cValue == 0)
            continue;
        DWORD dataSize = sizeof(SigningTime);
        return CryptDecodeObject(MY_ENCODING, szOID_RSA_signingTime,
            attribute->rgValue[0].pbData,
            attribute->rgValue[0].cbData, 0, &SigningTime, &dataSize);
    }
    return FALSE;
}

BOOL VerifyLegacyTimeStamp(
    HCRYPTMSG Message,
    PCMSG_SIGNER_INFO SignerInfo,
    HCERTSTORE AdditionalStore,
    REVOCATION_MODE Revocation,
    FILETIME & SigningTime,
    std::string & TimeStampStatus,
    std::string & RevocationStatus
) {
    if (!Message || !SignerInfo) return FALSE;
    for (DWORD attributeIndex = 0;
        attributeIndex < SignerInfo->UnauthAttrs.cAttr; attributeIndex++)
    {
        PCRYPT_ATTRIBUTE attribute =
            &SignerInfo->UnauthAttrs.rgAttr[attributeIndex];
        if (!attribute->pszObjId ||
            lstrcmpA(attribute->pszObjId, szOID_RSA_counterSign) != 0)
            continue;
        TimeStampStatus = "invalid";
        PBYTE encodedSigner = NULL;
        DWORD encodedSignerSize = 0;
        if (!MyCryptMsgGetParam(Message, CMSG_ENCODED_SIGNER, 0,
            (PVOID *)&encodedSigner, &encodedSignerSize))
            return FALSE;
        for (DWORD valueIndex = 0; valueIndex < attribute->cValue;
            valueIndex++)
        {
            PCMSG_SIGNER_INFO counterSigner = NULL;
            DWORD counterSignerSize = 0;
            if (!CryptDecodeObject(MY_ENCODING, PKCS7_SIGNER_INFO,
                attribute->rgValue[valueIndex].pbData,
                attribute->rgValue[valueIndex].cbData, 0, NULL,
                &counterSignerSize))
                continue;
            counterSigner = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR,
                counterSignerSize);
            if (!counterSigner) continue;
            PCCERT_CONTEXT counterCertificate = NULL;
            BOOL decoded = CryptDecodeObject(MY_ENCODING,
                PKCS7_SIGNER_INFO, attribute->rgValue[valueIndex].pbData,
                attribute->rgValue[valueIndex].cbData, 0, counterSigner,
                &counterSignerSize);
            if (decoded)
                counterCertificate = FindSignerCertificate(AdditionalStore,
                    counterSigner);
            BOOL verified = decoded && counterCertificate &&
                CryptMsgVerifyCountersignatureEncodedEx(0, MY_ENCODING,
                    encodedSigner, encodedSignerSize,
                    attribute->rgValue[valueIndex].pbData,
                    attribute->rgValue[valueIndex].cbData,
                    CMSG_VERIFY_SIGNER_CERT,
                    (PVOID)counterCertificate, 0, NULL) &&
                GetSignerSigningTime(counterSigner, SigningTime);
            if (verified)
            {
                TimeStampStatus = "untrusted";
                std::string chainStatus;
                std::string timeStampRevocation;
                BOOL trusted = VerifySignerChain(counterCertificate,
                    AdditionalStore, Revocation, &SigningTime, TRUE,
                    chainStatus, timeStampRevocation);
                MergeRevocationStatus(timeStampRevocation, RevocationStatus);
                if (trusted) TimeStampStatus = "valid";
            }
            if (counterCertificate)
                CertFreeCertificateContext(counterCertificate);
            LocalFree(counterSigner);
            if (TimeStampStatus == "valid") break;
        }
        LocalFree(encodedSigner);
        return TimeStampStatus == "valid";
    }
    TimeStampStatus = "absent";
    return FALSE;
}

void FinalizeVerification(VERIFY_RESULT & Verification)
{
    BOOL acceptableTimeStamp = Verification.TimeStamp == "valid" ||
        Verification.TimeStamp == "absent";
    if (Verification.ContentDigest == "valid" &&
        Verification.CmsSignature == "valid" &&
        Verification.CertificateChain == "trusted" &&
        acceptableTimeStamp && Verification.Revocation != "revoked" &&
        Verification.Revocation != "unknown")
    {
        Verification.Overall = "valid";
    }
    else if (Verification.ContentDigest == "valid" &&
        Verification.CmsSignature == "valid" &&
        Verification.CertificateChain == "trusted" &&
        acceptableTimeStamp && Verification.Revocation == "unknown")
    {
        Verification.Overall = "indeterminate";
    }
    else
    {
        Verification.Overall = "invalid";
    }
}

BOOL VerifyEmbeddedAuthenticode(
    LPCWSTR FileName,
    REVOCATION_MODE Revocation,
    VERIFY_RESULT & Verification
) {
    Verification.ContentDigest = "error";
    Verification.CmsSignature = "error";
    Verification.CertificateChain = "error";
    Verification.TimeStamp = "not_checked";
    Verification.Revocation = Revocation == REVOCATION_NONE ?
        "not_checked" : "unknown";
    Verification.Overall = "invalid";
    Verification.Error = ERROR_SUCCESS;

    HCERTSTORE certStore = NULL;
    HCRYPTMSG message = NULL;
    PCMSG_SIGNER_INFO signerInfo = NULL;
    PCCERT_CONTEXT signerCertificate = NULL;
    PBYTE content = NULL;
    DWORD contentSize = 0;
    DWORD encoding = 0;
    FILETIME signingTime = { 0 };
    BOOL hasTrustedTimeStamp = FALSE;
    std::string signerRevocation;
    BOOL query = CryptQueryObject(CERT_QUERY_OBJECT_FILE, FileName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, NULL, NULL,
        &certStore, &message, NULL);
    if (!query)
    {
        Verification.Error = GetLastError();
        return FALSE;
    }

    BOOL success = MyCryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
        (PVOID *)&signerInfo, NULL);
    if (!success || !signerInfo)
    {
        Verification.Error = GetLastError();
        goto Cleanup;
    }
    signerCertificate = FindSignerCertificate(certStore, signerInfo);
    if (!signerCertificate)
    {
        Verification.Error = (DWORD)CRYPT_E_SIGNER_NOT_FOUND;
        goto Cleanup;
    }
    if (VerifyCmsSigner(message, signerCertificate))
    {
        Verification.CmsSignature = "valid";
    }
    else
    {
        Verification.CmsSignature = "invalid";
        Verification.Error = GetLastError();
    }

    success = MyCryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0,
        (PVOID *)&content, &contentSize);
    if (success && content)
    {
        ALG_ID algorithm = 0;
        std::vector<BYTE> expectedDigest;
        std::vector<BYTE> actualDigest;
        if (ParseAuthenticodeDigest(content, contentSize, algorithm,
            expectedDigest))
        {
            if (CalculateAuthenticodeHash(FileName, algorithm, actualDigest))
            {
                Verification.ContentDigest = expectedDigest == actualDigest ?
                    "valid" : "invalid";
            }
        }
    }

    hasTrustedTimeStamp = VerifyRfc3161TimeStamp(signerInfo, certStore,
        Revocation, signingTime, Verification.TimeStamp,
        Verification.Revocation);
    if (Verification.TimeStamp == "absent")
    {
        hasTrustedTimeStamp = VerifyLegacyTimeStamp(message, signerInfo,
            certStore, Revocation, signingTime, Verification.TimeStamp,
            Verification.Revocation);
    }
    signerRevocation = Revocation == REVOCATION_NONE ?
        "not_checked" : "unknown";
    VerifySignerChain(signerCertificate, certStore, Revocation,
        hasTrustedTimeStamp ? &signingTime : NULL, FALSE,
        Verification.CertificateChain, signerRevocation);
    MergeRevocationStatus(signerRevocation, Verification.Revocation);
    FinalizeVerification(Verification);

Cleanup:
    if (content) LocalFree(content);
    if (signerCertificate) CertFreeCertificateContext(signerCertificate);
    if (signerInfo) LocalFree(signerInfo);
    if (message) CryptMsgClose(message);
    if (certStore) CertCloseStore(certStore, 0);
    return TRUE;
}

BOOL VerifyCatalogAuthenticode(
    LPCWSTR FileName,
    LPCWSTR CatalogName,
    REVOCATION_MODE Revocation,
    VERIFY_RESULT & Verification
) {
    Verification.ContentDigest = "error";
    Verification.CmsSignature = "error";
    Verification.CertificateChain = "error";
    Verification.TimeStamp = "not_checked";
    Verification.Revocation = Revocation == REVOCATION_NONE ?
        "not_checked" : "unknown";
    Verification.Overall = "invalid";
    Verification.Error = ERROR_SUCCESS;

    HCERTSTORE certStore = NULL;
    HCRYPTMSG message = NULL;
    PCMSG_SIGNER_INFO signerInfo = NULL;
    PCCERT_CONTEXT signerCertificate = NULL;
    PBYTE content = NULL;
    DWORD contentSize = 0;
    DWORD encoding = 0;
    FILETIME signingTime = { 0 };
    BOOL hasTrustedTimeStamp = FALSE;
    std::string signerRevocation;
    std::vector<BYTE> digest;

    BOOL query = CryptQueryObject(CERT_QUERY_OBJECT_FILE, CatalogName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, NULL, NULL,
        &certStore, &message, NULL);
    if (!query)
    {
        Verification.Error = GetLastError();
        return FALSE;
    }
    if (!MyCryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0,
        (PVOID *)&signerInfo, NULL) || !signerInfo)
    {
        Verification.Error = GetLastError();
        goto Cleanup;
    }
    signerCertificate = FindSignerCertificate(certStore, signerInfo);
    if (!signerCertificate)
    {
        Verification.Error = (DWORD)CRYPT_E_SIGNER_NOT_FOUND;
        goto Cleanup;
    }
    Verification.CmsSignature = VerifyCmsSigner(message, signerCertificate) ?
        "valid" : "invalid";

    if (!MyCryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0,
        (PVOID *)&content, &contentSize) || !content)
        goto Cleanup;
    Verification.ContentDigest = "invalid";
    for (size_t index = 0;
        index < sizeof(CATALOG_HASH_ALGORITHMS) /
            sizeof(CATALOG_HASH_ALGORITHMS[0]); index++)
    {
        if (CalculateAuthenticodeHash(FileName,
                CATALOG_HASH_ALGORITHMS[index], digest) &&
            FindCatalogMemberInDER(content, contentSize, digest))
        {
            Verification.ContentDigest = "valid";
            break;
        }
    }

    hasTrustedTimeStamp = VerifyRfc3161TimeStamp(signerInfo, certStore,
        Revocation, signingTime, Verification.TimeStamp,
        Verification.Revocation);
    if (Verification.TimeStamp == "absent")
    {
        hasTrustedTimeStamp = VerifyLegacyTimeStamp(message, signerInfo,
            certStore, Revocation, signingTime, Verification.TimeStamp,
            Verification.Revocation);
    }
    signerRevocation = Revocation == REVOCATION_NONE ?
        "not_checked" : "unknown";
    VerifySignerChain(signerCertificate, certStore, Revocation,
        hasTrustedTimeStamp ? &signingTime : NULL, FALSE,
        Verification.CertificateChain, signerRevocation);
    MergeRevocationStatus(signerRevocation, Verification.Revocation);
    FinalizeVerification(Verification);

Cleanup:
    if (content) LocalFree(content);
    if (signerCertificate) CertFreeCertificateContext(signerCertificate);
    if (signerInfo) LocalFree(signerInfo);
    if (message) CryptMsgClose(message);
    if (certStore) CertCloseStore(certStore, 0);
    return TRUE;
}

BOOL ReadFileData(LPCWSTR FileName, std::vector<BYTE> & Data)
{
    Data.clear();
    HANDLE fileHandle = CreateFileW(FileName, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE) return FALSE;
    LARGE_INTEGER fileSize = { 0 };
    BOOL result = GetFileSizeEx(fileHandle, &fileSize) &&
        fileSize.QuadPart > 0 && fileSize.QuadPart <= MAXDWORD;
    if (result)
    {
        Data.resize((size_t)fileSize.QuadPart);
        DWORD bytesRead = 0;
        result = ReadFile(fileHandle, &Data[0], (DWORD)Data.size(),
            &bytesRead, NULL) && bytesRead == Data.size();
    }
    CloseHandle(fileHandle);
    if (!result) Data.clear();
    return result;
}

BOOL CatalogContainsAnyDigest(
    LPCWSTR CatalogName,
    CONST std::vector<std::vector<BYTE> > & Digests
) {
    std::vector<BYTE> catalogData;
    if (!ReadFileData(CatalogName, catalogData)) return FALSE;
    BOOL possibleMatch = FALSE;
    for (size_t offset = 0; offset < catalogData.size() && !possibleMatch;
        offset++)
    {
        if (catalogData[offset] != 0x04) continue;
        DWORD elementOffset = (DWORD)offset;
        BYTE tag = 0;
        CONST BYTE *value = NULL;
        DWORD valueSize = 0;
        if (!ReadDERElement(&catalogData[0], (DWORD)catalogData.size(),
            elementOffset, tag, value, valueSize) ||
            elementOffset >= catalogData.size() ||
            catalogData[elementOffset] != 0x31)
            continue;
        for (size_t digestIndex = 0; digestIndex < Digests.size();
            digestIndex++)
        {
            if (valueSize == Digests[digestIndex].size() &&
                memcmp(value, &Digests[digestIndex][0], valueSize) == 0)
            {
                possibleMatch = TRUE;
                break;
            }
        }
    }
    if (!possibleMatch) return FALSE;

    HCERTSTORE certStore = NULL;
    HCRYPTMSG message = NULL;
    PBYTE content = NULL;
    DWORD contentSize = 0;
    DWORD encoding = 0;
    BOOL query = CryptQueryObject(CERT_QUERY_OBJECT_FILE, CatalogName,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED |
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, &encoding, NULL, NULL,
        &certStore, &message, NULL);
    BOOL found = query && MyCryptMsgGetParam(message, CMSG_CONTENT_PARAM, 0,
        (PVOID *)&content, &contentSize);
    if (found)
    {
        found = FALSE;
        for (size_t index = 0; index < Digests.size(); index++)
        {
            if (FindCatalogMemberInDER(content, contentSize, Digests[index]))
            {
                found = TRUE;
                break;
            }
        }
    }
    if (content) LocalFree(content);
    if (message) CryptMsgClose(message);
    if (certStore) CertCloseStore(certStore, 0);
    return found;
}

BOOL FindCatalogInDirectory(
    CONST std::wstring & Directory,
    CONST std::vector<std::vector<BYTE> > & Digests,
    std::wstring & CatalogName
) {
    WIN32_FIND_DATAW findData = { 0 };
    std::wstring pattern = Directory + L"\\*.cat";
    HANDLE findHandle = FindFirstFileW(pattern.c_str(), &findData);
    if (findHandle != INVALID_HANDLE_VALUE)
    {
        do
        {
            if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            {
                std::wstring candidate = Directory + L"\\" +
                    findData.cFileName;
                if (CatalogContainsAnyDigest(candidate.c_str(), Digests))
                {
                    CatalogName = candidate;
                    FindClose(findHandle);
                    return TRUE;
                }
            }
        } while (FindNextFileW(findHandle, &findData));
        FindClose(findHandle);
    }
    return FALSE;
}

BOOL FindCatalogForFile(
    LPCWSTR FileName,
    std::wstring & CatalogName
) {
    CatalogName.clear();
    std::vector<std::vector<BYTE> > digests;
    for (size_t index = 0;
        index < sizeof(CATALOG_HASH_ALGORITHMS) /
            sizeof(CATALOG_HASH_ALGORITHMS[0]); index++)
    {
        std::vector<BYTE> digest;
        if (CalculateAuthenticodeHash(FileName,
            CATALOG_HASH_ALGORITHMS[index], digest))
            digests.push_back(digest);
    }
    if (digests.empty()) return FALSE;

    WCHAR windowsDirectory[MAX_PATH] = { 0 };
    UINT windowsLength = GetWindowsDirectoryW(windowsDirectory, MAX_PATH);
    if (!windowsLength || windowsLength >= MAX_PATH) return FALSE;
    std::wstring catalogRoot = windowsDirectory;
    catalogRoot += L"\\System32\\CatRoot";

    PVOID oldRedirection = NULL;
    BOOL redirectionDisabled = Wow64DisableWow64FsRedirection(
        &oldRedirection);
    BOOL found = FindCatalogInDirectory(catalogRoot, digests, CatalogName);
    if (!found)
    {
        WIN32_FIND_DATAW findData = { 0 };
        std::wstring pattern = catalogRoot + L"\\*";
        HANDLE findHandle = FindFirstFileW(pattern.c_str(), &findData);
        if (findHandle != INVALID_HANDLE_VALUE)
        {
            do
            {
                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                    lstrcmpW(findData.cFileName, L".") != 0 &&
                    lstrcmpW(findData.cFileName, L"..") != 0)
                {
                    std::wstring directory = catalogRoot + L"\\" +
                        findData.cFileName;
                    if (FindCatalogInDirectory(directory, digests,
                        CatalogName))
                    {
                        found = TRUE;
                        break;
                    }
                }
            } while (FindNextFileW(findHandle, &findData));
            FindClose(findHandle);
        }
    }
    if (redirectionDisabled)
        Wow64RevertWow64FsRedirection(oldRedirection);
    return found;
}

BOOL AnalyzeFileDigitalSignature(
    LPCWSTR FilePath,
    LPCWSTR CataPath,
    std::wstring & CataFile,
    std::string & SignType,
    std::list<SIGN_NODE_INFO> & SignChain
) {
    BOOL bReturn = FALSE;

    CataFile = CataPath ? CataPath : L"";
    SignType = "embedded";

    // Get certificate information.
    bReturn = GetSignerCertificateInfo(FilePath, SignChain);
    if (!bReturn && !CataPath && FindCatalogForFile(FilePath, CataFile))
    {
        SignType = "cataloged";
        bReturn = GetSignerCertificateInfo(CataFile.c_str(), SignChain);
    }
    else if (!bReturn && CataPath && *CataPath)
    {
        // If we cannot get embedded signature information, we
        // just attempt to get cataloged signature information
        // if it has catalog or catalog is specified.
        SignType = "cataloged";
        bReturn = GetSignerCertificateInfo(CataFile.c_str(), SignChain);
    }
    return bReturn;
}

VOID PrintUsage()
{
    std::cout
        << "PESignAnalyzer " PESIGNANALYZER_VERSION << endl
        << "Usage: PESignAnalyzer.exe [options] <file>" << endl
        << endl
        << "Options:" << endl
        << "  -c, --catalog <file>  Use a specific catalog as fallback." << endl
        << "      --embedded-only   Require an embedded signature." << endl
        << "      --verify          Verify the Authenticode signature." << endl
        << "      --revocation <mode>" << endl
        << "                        Revocation mode: none, cache, or online." << endl
        << "  -h, --help, /?        Show this help and exit." << endl
        << "  -V, --version         Show version information and exit." << endl
        << "      --                 Stop processing options." << endl;
}

INT CommandLineError(LPCWSTR Message)
{
    if (Message && *Message)
    {
        std::wcerr << L"Error: " << Message << endl << endl;
    }
    PrintUsage();
    return 0x02;
}

INT wmain(INT argc, WCHAR *argv[])
{
    LPCWSTR pwzFilePath = NULL;
    LPCWSTR pwzCatalogPath = NULL;
    BOOL bEmbeddedOnly = FALSE;
    BOOL bVerify = FALSE;
    BOOL bProcessOptions = TRUE;
    REVOCATION_MODE revocation = REVOCATION_NONE;

    for (INT index = 1; index < argc; index++)
    {
        LPCWSTR argument = argv[index];
        if (bProcessOptions && !lstrcmpW(argument, L"--"))
        {
            bProcessOptions = FALSE;
        }
        else if (bProcessOptions && (!lstrcmpW(argument, L"-h") ||
            !lstrcmpW(argument, L"--help") || !lstrcmpW(argument, L"/?")))
        {
            PrintUsage();
            return 0x00;
        }
        else if (bProcessOptions && (!lstrcmpW(argument, L"-V") ||
            !lstrcmpW(argument, L"--version")))
        {
            std::cout << "PESignAnalyzer " PESIGNANALYZER_VERSION << endl;
            return 0x00;
        }
        else if (bProcessOptions && (!lstrcmpW(argument, L"-c") ||
            !lstrcmpW(argument, L"--catalog")))
        {
            if (++index >= argc)
            {
                return CommandLineError(L"--catalog requires a file path.");
            }
            pwzCatalogPath = argv[index];
            if (!*pwzCatalogPath)
            {
                return CommandLineError(L"The catalog path cannot be empty.");
            }
        }
        else if (bProcessOptions &&
            !wcsncmp(argument, L"--catalog=", 10))
        {
            pwzCatalogPath = argument + 10;
            if (!*pwzCatalogPath)
            {
                return CommandLineError(L"The catalog path cannot be empty.");
            }
        }
        else if (bProcessOptions &&
            !lstrcmpW(argument, L"--embedded-only"))
        {
            bEmbeddedOnly = TRUE;
        }
        else if (bProcessOptions && !lstrcmpW(argument, L"--verify"))
        {
            bVerify = TRUE;
        }
        else if (bProcessOptions && !lstrcmpW(argument, L"--revocation"))
        {
            if (++index >= argc)
            {
                return CommandLineError(
                    L"--revocation requires none, cache, or online.");
            }
            if (!lstrcmpW(argv[index], L"none"))
            {
                revocation = REVOCATION_NONE;
            }
            else if (!lstrcmpW(argv[index], L"cache"))
            {
                revocation = REVOCATION_CACHE;
            }
            else if (!lstrcmpW(argv[index], L"online"))
            {
                revocation = REVOCATION_ONLINE;
            }
            else
            {
                return CommandLineError(
                    L"Invalid revocation mode; use none, cache, or online.");
            }
            bVerify = TRUE;
        }
        else if (bProcessOptions && argument[0] == L'-')
        {
            std::wstring message = L"Unknown option: ";
            message += argument;
            return CommandLineError(message.c_str());
        }
        else if (pwzFilePath)
        {
            return CommandLineError(L"Only one input file can be analyzed at a time.");
        }
        else
        {
            pwzFilePath = argument;
        }
    }

    if (!pwzFilePath)
    {
        return CommandLineError(L"An input file is required.");
    }
    if (bEmbeddedOnly && pwzCatalogPath)
    {
        return CommandLineError(
            L"--embedded-only cannot be combined with --catalog.");
    }
    if (bEmbeddedOnly)
    {
        pwzCatalogPath = L"";
    }

    BOOL            bReturn     = FALSE;
    std::wstring    CataFile;
    std::string     SignType;
    std::list<SIGN_NODE_INFO> SignChain;

    std::wcout << L"filepath: " << pwzFilePath << endl;
    bReturn = AnalyzeFileDigitalSignature(pwzFilePath, pwzCatalogPath,
        CataFile, SignType, SignChain);
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
    if (bVerify)
    {
        VERIFY_RESULT verification;
        if (SignType == "cataloged")
        {
            VerifyCatalogAuthenticode(pwzFilePath, CataFile.c_str(),
                revocation, verification);
        }
        else
        {
            VerifyEmbeddedAuthenticode(pwzFilePath, revocation,
                verification);
        }
        std::cout << "verification.contentDigest: "
            << verification.ContentDigest << endl;
        std::cout << "verification.cmsSignature: "
            << verification.CmsSignature << endl;
        std::cout << "verification.certificateChain: "
            << verification.CertificateChain << endl;
        std::cout << "verification.timestamp: "
            << verification.TimeStamp << endl;
        std::cout << "verification.revocation: "
            << verification.Revocation << endl;
        std::cout << "verification.overall: "
            << verification.Overall << endl;
        if (verification.Overall == "invalid") return 0x03;
        if (verification.Overall == "indeterminate") return 0x04;
    }
    return 0x00;
}
