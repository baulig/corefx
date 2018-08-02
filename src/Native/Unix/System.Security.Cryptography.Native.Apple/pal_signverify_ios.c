// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_signverify.h"

static int32_t GenerateSignature(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash,
    PAL_HashAlgorithm hashAlgorithm, bool useHashAlgorithm,
    CFDataRef *pSignatureOut, int32_t *pOSStatus, CFErrorRef *pErrorOut)
{
    if (pSignatureOut != NULL)
        *pSignatureOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbDataHash == NULL || cbDataHash < 0 || pSignatureOut == NULL ||
        pOSStatus == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(NULL, pbDataHash, cbDataHash, kCFAllocatorNull);

    if (dataHash == NULL)
    {
        return kErrorUnknownState;
    }

    if (!useHashAlgorithm)
    {
        size_t outputLen = SecKeyGetBlockSize(privateKey) * 4;
        uint8_t *output = malloc(outputLen);
        if (output == NULL)
        {
            return kErrorUnknownState;
        }

        *pOSStatus = SecKeyRawSign(privateKey, kSecPaddingNone, pbDataHash, cbDataHash, output, &outputLen);

        if (*pOSStatus != noErr)
        {
            free(output);
            return kErrorSeeStatus;
        }

        *pSignatureOut = CFDataCreate(NULL, output, outputLen);
        free(output);

        if (*pSignatureOut == NULL)
        {
            return kErrorUnknownState;
        }

       return 1;
    }

    SecKeyAlgorithm algorithm;

    switch (hashAlgorithm)
    {
        case PAL_SHA1:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
            break;
        case PAL_SHA256:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
            break;
        case PAL_SHA384:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
            break;
        case PAL_SHA512:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
            break;
        default:
            return kErrorUnknownAlgorithm;
    }

    *pSignatureOut = SecKeyCreateSignature(privateKey, algorithm, dataHash, pErrorOut);

    if (*pErrorOut != NULL)
    {
        if (*pSignatureOut != NULL)
        {
            CFRelease(*pSignatureOut);
            *pSignatureOut = NULL;
        }

        return kErrorSeeError;
    }

    if (*pSignatureOut == NULL)
    {
        return kErrorUnknownState;
    }

    return 1;
}

int32_t AppleCryptoNative_GenerateSignature(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash,
    CFDataRef* pSignatureOut, int32_t *pOSStatus, CFErrorRef* pErrorOut)
{
    return GenerateSignature(
        privateKey, pbDataHash, cbDataHash, PAL_Unknown, false, pSignatureOut, pOSStatus, pErrorOut);
}

int32_t AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, PAL_HashAlgorithm hashAlgorithm,
    CFDataRef *pSignatureOut, int32_t *pOSStatus, CFErrorRef *pErrorOut)
{
    return GenerateSignature(
        privateKey, pbDataHash, cbDataHash, hashAlgorithm, true, pSignatureOut, pOSStatus, pErrorOut);
}

static int32_t VerifySignature(
    SecKeyRef publicKey, uint8_t* pbDataHash, int32_t cbDataHash, uint8_t* pbSignature, int32_t cbSignature,
    PAL_HashAlgorithm hashAlgorithm, bool useHashAlgorithm, int32_t *pOSStatus, CFErrorRef* pErrorOut)
{
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (publicKey == NULL || pbDataHash == NULL || cbDataHash < 0 || pbSignature == NULL ||
        cbSignature < 0 || pOSStatus == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    if (!useHashAlgorithm)
    {
        *pOSStatus = SecKeyRawVerify(publicKey, kSecPaddingNone, pbDataHash, cbDataHash, pbSignature, cbSignature);

        if (*pOSStatus != noErr)
        {
            return kErrorSeeStatus;
        }

       return 1;
    }

    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(NULL, pbDataHash, cbDataHash, kCFAllocatorNull);
    CFDataRef signature = CFDataCreateWithBytesNoCopy(NULL, pbSignature, cbSignature, kCFAllocatorNull);

    if (dataHash == NULL || signature == NULL)
    {
        return kErrorUnknownState;
    }

    SecKeyAlgorithm algorithm;

    switch (hashAlgorithm)
    {
        case PAL_SHA1:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
            break;
        case PAL_SHA256:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
            break;
        case PAL_SHA384:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
            break;
        case PAL_SHA512:
            algorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
            break;
        default:
            return kErrorUnknownAlgorithm;
    }

    return SecKeyVerifySignature(publicKey, algorithm, dataHash, signature, pErrorOut);
}


int32_t AppleCryptoNative_VerifySignature(
    SecKeyRef publicKey, uint8_t* pbDataHash, int32_t cbDataHash, uint8_t* pbSignature, int32_t cbSignature,
    int32_t *pOSStatus, CFErrorRef* pErrorOut)
{
    return VerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, PAL_Unknown, false, pOSStatus, pErrorOut);
}

int32_t AppleCryptoNative_VerifySignatureWithHashAlgorithm(
    SecKeyRef publicKey, uint8_t* pbDataHash, int32_t cbDataHash, uint8_t* pbSignature, int32_t cbSignature,
    PAL_HashAlgorithm hashAlgorithm, int32_t *pOSStatus, CFErrorRef* pErrorOut)
{
    return VerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, hashAlgorithm, true, pOSStatus, pErrorOut);
}
