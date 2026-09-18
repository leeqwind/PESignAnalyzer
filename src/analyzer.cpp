#include "internal.h"
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
