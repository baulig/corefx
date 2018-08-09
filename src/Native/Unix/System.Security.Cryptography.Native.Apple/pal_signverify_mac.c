// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_signverify_mac.h"
#include "pal_version.h"
#include "pal_error.h"

static int32_t ExecuteSignTransform(SecTransformRef signer, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut);
static int32_t ExecuteVerifyTransform(SecTransformRef verifier, CFErrorRef* pErrorOut);

static int32_t ConfigureSignVerifyTransform(
    SecTransformRef xform, CFDataRef cfDataHash, PAL_HashAlgorithm, bool useDigestAlgorithm, CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_MacGenerateSignature(SecKeyRef privateKey,
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

    SecTransformRef signer = SecSignTransformCreate(privateKey, pErrorOut);
    ret = PAL_Error_SeeError;

    if (signer != NULL)
    {
        if (*pErrorOut == NULL)
        {
            if (ConfigureSignVerifyTransform(signer, dataHash, hashAlgorithm, useHashAlgorithm, pErrorOut))
            {
                ret = ExecuteSignTransform(signer, pSignatureOut, pErrorOut);
            }
        }

        CFRelease(signer);
    }

    CFRelease(dataHash);
    return ret;
}

int32_t AppleCryptoNative_MacVerifySignature(SecKeyRef publicKey,
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

    SecTransformRef verifier = SecVerifyTransformCreate(publicKey, signature, pErrorOut);
    ret = PAL_Error_SeeError;

    if (verifier != NULL)
    {
        if (*pErrorOut == NULL)
        {
            if (ConfigureSignVerifyTransform(verifier, dataHash, hashAlgorithm, useHashAlgorithm, pErrorOut))
            {
                ret = ExecuteVerifyTransform(verifier, pErrorOut);
            }
        }

        CFRelease(verifier);
    }

    CFRelease(dataHash);
    CFRelease(signature);

    return ret;
}

static int32_t ExecuteSignTransform(SecTransformRef signer, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    assert(signer != NULL);
    assert(pSignatureOut != NULL);
    assert(pErrorOut != NULL);

    int32_t ret = INT_MIN;
    CFTypeRef signerResponse = SecTransformExecute(signer, pErrorOut);
    CFDataRef signature = NULL;

    if (signerResponse == NULL || *pErrorOut != NULL)
    {
        ret = PAL_Error_SeeError;
        goto cleanup;
    }

    if (CFGetTypeID(signerResponse) != CFDataGetTypeID())
    {
        ret = PAL_Error_UnknownState;
        goto cleanup;
    }

    signature = (CFDataRef)signerResponse;

    if (CFDataGetLength(signature) > 0)
    {
        // We're going to call CFRelease in cleanup, so this keeps it alive
        // to be interpreted by the managed code.
        CFRetain(signature);
        *pSignatureOut = signature;
        ret = 1;
    }
    else
    {
        ret = PAL_Error_UnknownState;
        *pSignatureOut = NULL;
    }

cleanup:
    if (signerResponse != NULL)
    {
        CFRelease(signerResponse);
    }

    return ret;
}

static int32_t ExecuteVerifyTransform(SecTransformRef verifier, CFErrorRef* pErrorOut)
{
    assert(verifier != NULL);
    assert(pErrorOut != NULL);

    int32_t ret = PAL_Error_SeeError;
    CFTypeRef verifierResponse = SecTransformExecute(verifier, pErrorOut);

    if (verifierResponse != NULL)
    {
        if (*pErrorOut == NULL)
        {
            ret = (verifierResponse == kCFBooleanTrue);
        }

        CFRelease(verifierResponse);
    }

    return ret;
}

static int32_t ConfigureSignVerifyTransform(SecTransformRef xform,
                                            CFDataRef cfDataHash,
                                            PAL_HashAlgorithm hashAlgorithm,
                                            bool includeHashAlgorithm,
                                            CFErrorRef* pErrorOut)
{
    if (!SecTransformSetAttribute(xform, kSecInputIsAttributeName, kSecInputIsDigest, pErrorOut))
    {
        return 0;
    }

    if (!SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfDataHash, pErrorOut))
    {
        return 0;
    }

    if (includeHashAlgorithm)
    {
        CFStringRef cfHashName = NULL;
        int32_t hashSize = 0;

        switch (hashAlgorithm)
        {
            case PAL_MD5:
                cfHashName = kSecDigestMD5;
                break;
            case PAL_SHA1:
                cfHashName = kSecDigestSHA1;
                break;
            case PAL_SHA256:
                cfHashName = kSecDigestSHA2;
                hashSize = 256;
                break;
            case PAL_SHA384:
                cfHashName = kSecDigestSHA2;
                hashSize = 384;
                break;
            case PAL_SHA512:
                cfHashName = kSecDigestSHA2;
                hashSize = 512;
                break;
            default:
                return PAL_Error_UnknownAlgorithm;
        }

        if (!SecTransformSetAttribute(xform, kSecDigestTypeAttribute, cfHashName, pErrorOut))
        {
            return 0;
        }

        if (hashSize != 0)
        {
            CFNumberRef cfHashSize = CFNumberCreate(NULL, kCFNumberIntType, &hashSize);

            if (cfHashSize == NULL)
            {
                return 0;
            }

            if (!SecTransformSetAttribute(xform, kSecDigestLengthAttribute, cfHashSize, pErrorOut))
            {
                CFRelease(cfHashSize);
                return 0;
            }

            CFRelease(cfHashSize);
        }
    }

    return 1;
}
