#include "internal.h"
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
        << "      --                Stop processing options." << endl;
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
