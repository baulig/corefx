// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include "pal_version.h"
#include "pal_error.h"

#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#include "pal_rsa_unified.h"
#endif

#if REQUIRE_MAC_PLATFORM
#include "pal_rsa_mac.h"
#endif

static bool UseUnifiedApi (void)
{
    // FIXME: check macOS version
    return true;
}

int32_t AppleCryptoNative_RsaDecryptPkcs(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedDecryptPkcs(privateKey, pbData, cbData, pDecryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM // macOS < 10.12
    return AppleCryptoNative_RsaMacDecryptPkcs(privateKey, pbData, cbData, pDecryptedOut, pErrorOut);
#else // iOS 9
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaEncryptPkcs(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedEncryptPkcs(publicKey, pbData, cbData, pEncryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacEncryptPkcs(publicKey, pbData, cbData, pEncryptedOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaEncryptionPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedEncryptionPrimitive(publicKey, pbData, cbData, pEncryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacEncryptionPrimitive(publicKey, pbData, cbData, pEncryptedOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaDecryptOaep(SecKeyRef privateKey,
                                         uint8_t* pbData,
                                         int32_t cbData,
                                         PAL_HashAlgorithm mfgAlgorithm,
                                         CFDataRef* pDecryptedOut,
                                         CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedDecryptOaep(privateKey, pbData, cbData, mfgAlgorithm, pDecryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacDecryptOaep(privateKey, pbData, cbData, mfgAlgorithm, pDecryptedOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaEncryptOaep(SecKeyRef publicKey,
                                         uint8_t* pbData,
                                         int32_t cbData,
                                         PAL_HashAlgorithm mgfAlgorithm,
                                         CFDataRef* pEncryptedOut,
                                         CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedEncryptOaep(publicKey, pbData, cbData, mgfAlgorithm, pEncryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacEncryptOaep(publicKey, pbData, cbData, mgfAlgorithm, pEncryptedOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaDecryptionPrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedDecryptionPrimitive(privateKey, pbData, cbData, pDecryptedOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacDecryptionPrimitive(privateKey, pbData, cbData, pDecryptedOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaSignaturePrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedSignaturePrimitive(privateKey, pbData, cbData, pSignatureOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacSignaturePrimitive(privateKey, pbData, cbData, pSignatureOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

int32_t AppleCryptoNative_RsaVerificationPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
    if (UseUnifiedApi ())
    {
        return AppleCryptoNative_RsaUnifiedVerificationPrimitive(publicKey, pbData, cbData, pSignatureOut, pErrorOut);
    }
#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)
#if REQUIRE_MAC_PLATFORM
    return AppleCryptoNative_RsaMacVerificationPrimitive(publicKey, pbData, cbData, pSignatureOut, pErrorOut);
#else
    return PAL_Error_Platform;
#endif
}

