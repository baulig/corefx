// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_signverify_ios.h"

int32_t AppleCryptoNative_iOSGenerateSignature(SecKeyRef privateKey,
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

    int32_t ret = PAL_Error_Platform;

    // Available on iOS 2.0+, tvOS 9.0+, watchOS 2.0+

    if (!useHashAlgorithm)
    {
        size_t outputLen = SecKeyGetBlockSize(privateKey) * 4;
        uint8_t *output = malloc(outputLen);
        if (output == NULL)
        {
            CFRelease(dataHash);
            return kErrorUnknownState;
        }

        *pOSStatusOut = SecKeyRawSign(privateKey, kSecPaddingNone, pbDataHash, cbDataHash, output, &outputLen);

        if (*pOSStatusOut == noErr)
        {
            *pSignatureOut = CFDataCreate(NULL, output, outputLen);
            if (*pSignatureOut == NULL)
            {
                ret = kErrorUnknownState;
            }
            else
            {
                ret = 1;
            }
        }
        else
        {
            ret = kErrorSeeStatus;
        }

        free(output);
        CFRelease(dataHash);
        return ret;
    }

#if REQUIRE_IOS_SDK_VERSION(10,0)

    // We can also just remove this block as we're using the Unified API on iOS 10+.

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

#endif // REQUIRE_IOS_SDK_VERSION(10,0)

    CFRelease(dataHash);
    return ret;
}

int32_t AppleCryptoNative_iOSVerifySignature(SecKeyRef publicKey,
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

    int32_t ret = PAL_Error_Platform;

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

    if (!useHashAlgorithm)
    {
        *pOSStatusOut = SecKeyRawVerify(publicKey, kSecPaddingNone, pbDataHash, cbDataHash, pbSignature, cbSignature);

        CFRelease(dataHash);
        CFRelease(signature);

        switch (*pOSStatusOut)
        {
            case noErr:
                return 1;
            case -9809: // errSSLCrypto
                return 0;
            default:
                return kErrorSeeStatus;
        }
    }

#if REQUIRE_IOS_SDK_VERSION(10,0)

    // We can also just remove this block as we're using the Unified API on iOS 10+.

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

    ret = SecKeyVerifySignature(publicKey, algorithm, dataHash, signature, pErrorOut);

#endif // REQUIRE_IOS_SDK_VERSION(10,0)

    CFRelease(dataHash);
    CFRelease(signature);

    return ret;
}

