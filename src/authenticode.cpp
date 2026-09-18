#include "internal.h"
BOOL FindCatalogMemberInDER(
    CONST BYTE * Data,
    DWORD DataSize,
    CONST std::vector<BYTE> & Digest,
    DWORD Depth
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
