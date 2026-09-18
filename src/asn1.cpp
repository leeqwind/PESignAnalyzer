#include "internal.h"
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
