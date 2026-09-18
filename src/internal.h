#pragma once

#include "pesignanalyzer/analyzer.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <math.h>
#include <strsafe.h>
#include <vector>

#define MY_ENCODING (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)
#ifndef szOID_RFC3161_counterSign
#define szOID_RFC3161_counterSign "1.3.6.1.4.1.311.3.3.1"
#endif
#ifndef szOID_NESTED_SIGNATURE
#define szOID_NESTED_SIGNATURE "1.3.6.1.4.1.311.2.4.1"
#endif

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

struct SIGNDATA_HANDLE {
    DWORD dwObjSize;
    PCMSG_SIGNER_INFO pSignerInfo;
    HCERTSTORE hCertStoreHandle;
};
typedef SIGNDATA_HANDLE *PSIGNDATA_HANDLE;

static const ALG_ID CATALOG_HASH_ALGORITHMS[] = {
    CALG_SHA_256, CALG_SHA1, CALG_SHA_384, CALG_SHA_512
};

BOOL MyCryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, PVOID *, DWORD *);
BOOL GetNestedSignerInfo(PSIGNDATA_HANDLE const, std::list<SIGNDATA_HANDLE> &);
BOOL GetCounterSignerInfo(PCMSG_SIGNER_INFO, PCMSG_SIGNER_INFO *);
std::string TimeToString(FILETIME *, SYSTEMTIME * = NULL);
BOOL GetCounterSignerData(PCMSG_SIGNER_INFO const, SIGN_COUNTER_SIGN &);
BOOL ParseDERFindType(INT, PBYTE, DWORD, DWORD &, DWORD &, DWORD &, INT &);
BOOL GetGeneralizedTimeStamp(PCMSG_SIGNER_INFO, std::string &);
BOOL CalculateHashOfBytes(BYTE *, ALG_ID, DWORD, std::string &);
BOOL GetSignerCertificateInfo(LPCWSTR, std::list<SIGN_NODE_INFO> &);

BOOL ReadDERElement(const BYTE *, DWORD, DWORD &, BYTE &, const BYTE * &, DWORD &);
ALG_ID DigestAlgorithmFromDEROID(const BYTE *, DWORD);
BOOL ParseAuthenticodeDigest(const BYTE *, DWORD, ALG_ID &, std::vector<BYTE> &);

BOOL FindCatalogMemberInDER(const BYTE *, DWORD, const std::vector<BYTE> &, DWORD = 0);
BOOL CalculateAuthenticodeHash(LPCWSTR, ALG_ID, std::vector<BYTE> &);

BOOL FindCatalogForFile(LPCWSTR, std::wstring &);

using std::endl;
using std::list;
using std::remove_if;
