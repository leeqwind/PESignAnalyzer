#pragma once

#include <Windows.h>
#include <WinCrypt.h>

#include <list>
#include <string>

// Information attached to a signature timestamp/countersignature.
struct SIGN_COUNTER_SIGN {
    std::string SignerName;
    std::string MailAddress;
    std::string TimeStamp;
};
typedef SIGN_COUNTER_SIGN *PSIGN_COUNTER_SIGN;

// Metadata for one certificate in a signer's chain.
struct CERT_NODE_INFO {
    std::string SubjectName;
    std::string IssuerName;
    std::string Version;
    std::string Serial;
    std::string Thumbprint;
    std::string NotBefore;
    std::string NotAfter;
    std::string SignAlgorithm;
    std::wstring CRLpoint;
};
typedef CERT_NODE_INFO *PCERT_NODE_INFO;

// Metadata for one embedded or catalog signature.
struct SIGN_NODE_INFO {
    std::string DigestAlgorithm;
    std::string Version;
    SIGN_COUNTER_SIGN CounterSign;
    std::list<CERT_NODE_INFO> CertChain;
};
typedef SIGN_NODE_INFO *PSIGN_NODE_INFO;

enum REVOCATION_MODE {
    REVOCATION_NONE,
    REVOCATION_CACHE,
    REVOCATION_ONLINE
};

struct VERIFY_RESULT {
    std::string ContentDigest;
    std::string CmsSignature;
    std::string CertificateChain;
    std::string TimeStamp;
    std::string Revocation;
    std::string Overall;
    DWORD Error;
};
typedef VERIFY_RESULT *PVERIFY_RESULT;
