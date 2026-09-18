#include "internal.h"
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
