// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_seckey_ios.h"
#include "pal_symmetric.h"
#include "pal_utilities.h"

CFDataRef AppleCryptoNative_SecKeyExport(SecKeyRef pKey, CFErrorRef *pErrorOut)
{
    return SecKeyCopyExternalRepresentation(pKey, pErrorOut);
}

SecKeyRef AppleCryptoNative_SecKeyImportEphemeral(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, CFErrorRef *pErrorOut)
{
    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, isPrivateKey ? kSecAttrKeyClassPrivate : kSecAttrKeyClassPublic);
   //  CFDictionarySetValue(attrs, kSecAttrKeySizeInBits, 0);

    CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, pbKeyBlob, cbKeyBlob, kCFAllocatorNull);
    SecKeyRef key = SecKeyCreateWithData(data, attrs, pErrorOut);
    CFRelease(data);
    CFRelease(attrs);
    return key;
}

int32_t AppleCryptoNative_SecKeyEncrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbCipherOut, int32_t *cbCipherLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbCipherOut == NULL || cbCipherLen == NULL || *cbCipherLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    SecPadding nativePadding;
    switch (padding)
    {
        case PAL_PaddingModeNone:
            nativePadding = kSecPaddingNone;
            break;
        case PAL_PaddingModePkcs1:
            nativePadding = kSecPaddingPKCS1;
            break;
        case PAL_PaddingModeOaep:
            nativePadding = kSecPaddingOAEP;
            break;
        default:
            return kErrorBadInput;
    }

    fprintf (stderr, "SEC KEY ENCRYPT: %d,%d - %p,%d - %p,%d", padding, nativePadding, pbData, cbData, pbCipherOut, *cbCipherLen);

    size_t cipherLen = *cbCipherLen;
    *pOSStatus = SecKeyEncrypt(key, nativePadding, pbData, (size_t)cbData, pbCipherOut, &cipherLen);

    fprintf (stderr, "SEC KEY ENCRYPT #1: %d - %ld\n", *pOSStatus, cipherLen);

    if (*pOSStatus == errSecParam && *cbCipherLen < SecKeyGetBlockSize(key))
    {
        return kErrorMaybeTooSmall;
    }

    *cbCipherLen = cipherLen;
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_SecKeyDecrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbPlainOut, int32_t *cbPlainLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbPlainOut == NULL || cbPlainLen == NULL || *cbPlainLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    SecPadding nativePadding;
    switch (padding)
    {
        case PAL_PaddingModeNone:
            nativePadding = kSecPaddingNone;
            break;
        case PAL_PaddingModePkcs1:
            nativePadding = kSecPaddingPKCS1;
            break;
        case PAL_PaddingModeOaep:
            nativePadding = kSecPaddingOAEP;
            break;
        default:
            return kErrorBadInput;
    }

    fprintf (stderr, "SEC KEY DECRYPT: %d,%d - %p,%d - %p,%d", padding, nativePadding, pbData, cbData, pbPlainOut, *cbPlainLen);

    size_t plainLen = *cbPlainLen;
    *pOSStatus = SecKeyDecrypt(key, nativePadding, pbData, (size_t)cbData, pbPlainOut, &plainLen);

    fprintf (stderr, "SEC KEY DECRYPT #1: %d - %ld\n", *pOSStatus, plainLen);

    if (*pOSStatus == errSecParam && *cbPlainLen < SecKeyGetBlockSize(key))
    {
        return kErrorMaybeTooSmall;
    }

    if (*pOSStatus != noErr)
    {
        return kErrorSeeError;
    }

    if (padding == PAL_PaddingModeNone && plainLen < *cbPlainLen)
    {
        int padLen = *cbPlainLen - plainLen;
        memmove(pbPlainOut+padLen, pbPlainOut, plainLen);
        memset(pbPlainOut, 0, padLen);
        return 1;
    }

    *cbPlainLen = plainLen;
    return 1;
}

int32_t AppleCryptoNative_SecKeySign(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbSigOut, int32_t *cbSigLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbSigOut == NULL || cbSigLen == NULL || *cbSigLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    SecPadding nativePadding;
    switch (padding)
    {
        case PAL_PaddingModeNone:
            nativePadding = kSecPaddingNone;
            break;
        case PAL_PaddingModePkcs1:
            nativePadding = kSecPaddingPKCS1SHA1;
            break;
        default:
            return kErrorBadInput;
    }

    size_t sigLen = *cbSigLen;
    *pOSStatus = SecKeyRawSign(key, nativePadding, pbData, cbData, pbSigOut, &sigLen);

    if (*pOSStatus == errSecParam && *cbSigLen < SecKeyGetBlockSize(key))
    {
        return kErrorMaybeTooSmall;
    }

    *cbSigLen = sigLen;
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_SecKeyVerify(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbSig, int32_t *cbSigLen, int32_t* pOSStatus)
{
    return AppleCryptoNative_SecKeyEncrypt(key, padding, pbData, cbData, pbSig, cbSigLen, pOSStatus);
}
