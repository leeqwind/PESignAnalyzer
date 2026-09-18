#include "internal.h"
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
