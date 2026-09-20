#pragma once

#include "analyzer/types.h"

#define PESIGNANALYZER_VERSION "1.3.0"

BOOL AnalyzeFileDigitalSignature(
    LPCWSTR filePath,
    LPCWSTR catalogPath,
    std::wstring &catalogFile,
    std::string &signType,
    std::list<SIGN_NODE_INFO> &signChain);

BOOL VerifyEmbeddedAuthenticode(
    LPCWSTR fileName,
    REVOCATION_MODE revocation,
    VERIFY_RESULT &verification);

BOOL VerifyCatalogAuthenticode(
    LPCWSTR fileName,
    LPCWSTR catalogName,
    REVOCATION_MODE revocation,
    VERIFY_RESULT &verification);