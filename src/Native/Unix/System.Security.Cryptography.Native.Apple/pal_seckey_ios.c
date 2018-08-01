// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
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

enum {
    TRANSFORM_ENCRYPT = 1,
    TRANSFORM_DECRYPT = 2
};
typedef int32_t NativeTransform;

static int32_t perform_transform(
    SecKeyRef key, NativeTransform transform, PAL_PaddingMode padding, const uint8_t* input, int32_t inputLen,
    uint8_t* output, int32_t *outputLen, int32_t* status, CFErrorRef *error)
{
    fprintf(
        stderr, "PERFORM TRANSFORM: %d,%d - %p,%d - %p,%d - %p,%p\n",
        transform, padding, input, inputLen, output, *outputLen, status, error);

    if (input == NULL || inputLen < 0 || output == NULL || outputLen == NULL || *outputLen < 0 ||
        status == NULL || error == NULL)
    {
        return kErrorBadInput;
    }

    *error = NULL;
    padding = PAL_PaddingModeNone;

    if (padding == PAL_PaddingModeNone)
    {
        int32_t retval;

        CFDataRef outputData = NULL; // CFDataCreateWithBytesNoCopy(NULL, output, *outputLen, kCFAllocatorNull);

        fprintf(stderr, "PERFORM TRANSFORM #1: %p\n", outputData);

        switch (transform)
        {
            case TRANSFORM_ENCRYPT:
                retval = AppleCryptoNative_RsaEncryptionPrimitive(key, input, inputLen, &outputData, error);
                break;
            case TRANSFORM_DECRYPT:
                retval = AppleCryptoNative_RsaDecryptionPrimitive(key, input, inputLen, &outputData, error);
                break;
            default:
                return kErrorUnknownState;
        }

        fprintf(stderr, "PERFORM TRANSFORM #2: %d - %p - %p\n", retval, outputData, *error);

        if (*error != NULL)
        {
            if (outputData != NULL)
            {
                CFRelease(outputData);
                outputData = NULL;
            }

            return kErrorSeeError;
        }

        if (output == NULL)
        {
            return kErrorUnknownState;
        }

        size_t outputDataLength = CFDataGetLength(outputData);
        fprintf(stderr, "PERFORM TRANSFORM #3: %ld,%d\n", outputDataLength, *outputLen);

        if (outputDataLength > *outputLen)
        {
            return kErrorMaybeTooSmall;            
        }

        memcpy(output, CFDataGetBytePtr(outputData), outputDataLength);
        *outputLen = outputDataLength;
        CFRelease(outputData);
        return 1;
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

    size_t tmpOutputLen = *outputLen;
    switch (transform)
    {
        case TRANSFORM_ENCRYPT:
            *status = SecKeyEncrypt(key, nativePadding, input, inputLen, output, &tmpOutputLen);
            break;
        case TRANSFORM_DECRYPT:
            *status = SecKeyDecrypt(key, nativePadding, input, inputLen, output, &tmpOutputLen);
            break;
        default:
            return kErrorUnknownState;
    }

    fprintf(stderr, "PERFORM TRANSPORT #4: %d - %d - %ld\n", nativePadding, *status, tmpOutputLen);

    if (*status == errSecParam && *outputLen < SecKeyGetBlockSize(key))
    {
        return kErrorMaybeTooSmall;
    }

    *outputLen = tmpOutputLen;
    return *status == noErr;
}

int32_t AppleCryptoNative_SecKeyEncrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbCipherOut, int32_t *cbCipherLen, int32_t* pOSStatus, CFErrorRef *pErrorOut)
{
    return perform_transform(
        key, TRANSFORM_ENCRYPT, padding, pbData, cbData, pbCipherOut, cbCipherLen, pOSStatus, pErrorOut);
}

int32_t AppleCryptoNative_SecKeyDecrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbPlainOut, int32_t *cbPlainLen, int32_t* pOSStatus, CFErrorRef *pErrorOut)
{
    return perform_transform(
        key, TRANSFORM_DECRYPT, padding, pbData, cbData, pbPlainOut, cbPlainLen, pOSStatus, pErrorOut);
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
    return AppleCryptoNative_SecKeyEncrypt(key, padding, pbData, cbData, pbSig, cbSigLen, pOSStatus, NULL);
}
