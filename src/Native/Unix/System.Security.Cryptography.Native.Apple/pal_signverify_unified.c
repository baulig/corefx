// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_signverify_unified.h"
#include "pal_error.h"

int32_t AppleCryptoNative_UnifiedGenerateSignature(SecKeyRef privateKey,
                                                   uint8_t* pbDataHash,
                                                   int32_t cbDataHash,
                                                   PAL_HashAlgorithm hashAlgorithm,
                                                   bool useHashAlgorithm,
                                                   CFDataRef* pSignatureOut,
                                                   int32_t *pOSStatusOut,
                                                   CFErrorRef* pErrorOut)
{
    if (pSignatureOut != NULL)
        *pSignatureOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbDataHash == NULL || cbDataHash < 0 || pSignatureOut == NULL ||
        pOSStatusOut == NULL || pErrorOut == NULL)
    {
        return PAL_Error_BadInput;
    }

    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(NULL, pbDataHash, cbDataHash, kCFAllocatorNull);
    if (dataHash == NULL)
    {
        return PAL_Error_UnknownState;
    }

    fprintf (stderr, "UNIFIED GENERATE SIGNATURE: %p,%d - %d,%d\n",
             pbDataHash, cbDataHash, hashAlgorithm, useHashAlgorithm);

    SecKeyAlgorithm algorithm;

    if (!useHashAlgorithm)
    {
        algorithm = kSecKeyAlgorithmRSASignatureRaw;
        if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm))
        {
            fprintf(stderr, "UNIFIED GENERATE SIGNATURE #1!\n");
            algorithm = kSecKeyAlgorithmECDSASignatureDigestX962;

            if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm))
            {
                fprintf(stderr, "UNIFIED GENERATE SIGNATURE #2!\n");
                CFRelease(dataHash);
                return PAL_Error_UnknownAlgorithm;
            }
        }
    }
    else
    {
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
    }

    *pSignatureOut = SecKeyCreateSignature(privateKey, algorithm, dataHash, pErrorOut);

    fprintf(stderr, "UNIFIED GENERATE SIGNATURE #3: %p,%p\n", *pSignatureOut, *pErrorOut);

    int32_t ret;
    if (*pErrorOut != NULL || *pSignatureOut == NULL)
    {
        if (*pSignatureOut != NULL)
        {
            CFRelease(*pSignatureOut);
            *pSignatureOut = NULL;
        }

        ret = kErrorSeeError;
    }
    else
    {
        ret = 1;
    }

    CFRelease(dataHash);
    return ret;
}

int32_t AppleCryptoNative_UnifiedVerifySignature(SecKeyRef publicKey,
                                                 uint8_t* pbDataHash,
                                                 int32_t cbDataHash,
                                                 uint8_t* pbSignature,
                                                 int32_t cbSignature,
                                                 PAL_HashAlgorithm hashAlgorithm,
                                                 bool useHashAlgorithm,
                                                 int32_t *pOSStatusOut,
                                                 CFErrorRef* pErrorOut)
{
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (publicKey == NULL || pbDataHash == NULL || cbDataHash < 0 || pbSignature == NULL || cbSignature < 0 ||
        pOSStatusOut == NULL || pErrorOut == NULL)
        return PAL_Error_BadInput;

    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(NULL, pbDataHash, cbDataHash, kCFAllocatorNull);
    if (dataHash == NULL)
    {
        return PAL_Error_UnknownState;
    }

    CFDataRef signature = CFDataCreateWithBytesNoCopy(NULL, pbSignature, cbSignature, kCFAllocatorNull);
    if (signature == NULL)
    {
        CFRelease(dataHash);
        return PAL_Error_UnknownState;
    }

    SecKeyAlgorithm algorithm;
    if (!useHashAlgorithm)
    {
        algorithm = kSecKeyAlgorithmRSASignatureRaw;
        if (!SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeVerify, algorithm))
        {
            algorithm = kSecKeyAlgorithmECDSASignatureDigestX962;

            if (!SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeVerify, algorithm))
            {
                CFRelease(dataHash);
                return PAL_Error_UnknownAlgorithm;
            }
        }
    }
    else
    {
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
    }

    int32_t ret = SecKeyVerifySignature(publicKey, algorithm, dataHash, signature, pErrorOut);

    CFRelease(dataHash);
    CFRelease(signature);

    return ret;
}
