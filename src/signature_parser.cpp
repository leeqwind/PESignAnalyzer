#include "internal.h"
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
    SYSTEMTIME *pstIn
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
