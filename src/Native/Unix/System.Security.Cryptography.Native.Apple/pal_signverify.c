// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_signverify.h"
#include "pal_version.h"
#include "pal_error.h"

#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#include "pal_signverify_unified.h"
#endif

#if REQUIRE_MAC_PLATFORM
#include "pal_signverify_mac.h"
#elif REQUIRE_IOS_PLATFORM
#include "pal_signverify_ios.h"
#endif

static bool UseUnifiedApi (void)
{
    // FIXME: check macOS version
    return true;
}


static int32_t GenerateSignature(SecKeyRef privateKey,
                                 uint8_t* pbDataHash,
                                 int32_t cbDataHash,
                                 PAL_HashAlgorithm hashAlgorithm,
                                 bool useHashAlgorithm,
                                 CFDataRef* pSignatureOut,
                                 int32_t *pOSStatusOut,
                                 CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_UnifiedGenerateSignature(
            privateKey, pbDataHash, cbDataHash, hashAlgorithm, useHashAlgorithm,
            pSignatureOut, pOSStatusOut, pErrorOut);
    }
#endif
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_MacGenerateSignature(
        privateKey, pbDataHash, cbDataHash, hashAlgorithm, useHashAlgorithm,
        pSignatureOut, pOSStatusOut, pErrorOut);
#elif REQUIRE_IOS_PLATFORM
    return AppleCryptoNative_iOSGenerateSignature(
        privateKey, pbDataHash, cbDataHash, hashAlgorithm, useHashAlgorithm,
        pSignatureOut, pOSStatusOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_GenerateSignature(SecKeyRef privateKey,
                                            uint8_t* pbDataHash,
                                            int32_t cbDataHash,
                                            CFDataRef* pSignatureOut,
                                            int32_t *pOSStatusOut,
                                            CFErrorRef* pErrorOut)
{
    return GenerateSignature(
        privateKey, pbDataHash, cbDataHash, PAL_Unknown, false, pSignatureOut, pOSStatusOut, pErrorOut);
}

int32_t AppleCryptoNative_GenerateSignatureWithHashAlgorithm(SecKeyRef privateKey,
                                                             uint8_t* pbDataHash,
                                                             int32_t cbDataHash,
                                                             PAL_HashAlgorithm hashAlgorithm,
                                                             CFDataRef* pSignatureOut,
                                                             int32_t *pOSStatusOut,
                                                             CFErrorRef* pErrorOut)
{
    return GenerateSignature(
        privateKey, pbDataHash, cbDataHash, hashAlgorithm, true, pSignatureOut, pOSStatusOut, pErrorOut);
}

static int32_t VerifySignature(SecKeyRef publicKey,
                               uint8_t* pbDataHash,
                               int32_t cbDataHash,
                               uint8_t* pbSignature,
                               int32_t cbSignature,
                               PAL_HashAlgorithm hashAlgorithm,
                               bool useHashAlgorithm,
                               int32_t *pOSStatusOut,
                               CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_UnifiedVerifySignature(
            publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature,
            hashAlgorithm, useHashAlgorithm, pOSStatusOut, pErrorOut);
    }
#endif
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_MacVerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature,
        hashAlgorithm, useHashAlgorithm, pOSStatusOut, pErrorOut);
#elif REQUIRE_IOS_PLATFORM
    return AppleCryptoNative_iOSVerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature,
        hashAlgorithm, useHashAlgorithm, pOSStatusOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_VerifySignatureWithHashAlgorithm(SecKeyRef publicKey,
                                                           uint8_t* pbDataHash,
                                                           int32_t cbDataHash,
                                                           uint8_t* pbSignature,
                                                           int32_t cbSignature,
                                                           PAL_HashAlgorithm hashAlgorithm,
                                                           int32_t *pOSStatusOut,
                                                           CFErrorRef* pErrorOut)
{
    return VerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, hashAlgorithm, true, pOSStatusOut, pErrorOut);
}

int32_t AppleCryptoNative_VerifySignature(SecKeyRef publicKey,
                                          uint8_t* pbDataHash,
                                          int32_t cbDataHash,
                                          uint8_t* pbSignature,
                                          int32_t cbSignature,
                                          int32_t *pOSStatusOut,
                                          CFErrorRef* pErrorOut)
{
    return VerifySignature(
        publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, PAL_Unknown, false, pOSStatusOut, pErrorOut);
}

