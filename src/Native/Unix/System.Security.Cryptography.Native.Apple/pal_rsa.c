// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"

#if REQUIRE_MAC_SDK_VERSION(10_12) || REQUIRE_IOS_SDK_VERSION(10)

//
// These APIs are also available on iOS 10
//

static int32_t RsaPrimitive(SecKeyRef key,
                            const uint8_t* pbData,
                            int32_t cbData,
                            CFDataRef* pDataOut,
                            CFErrorRef* pErrorOut,
                            SecKeyAlgorithm algorithm,
                            CFDataRef func(SecKeyRef, SecKeyAlgorithm, CFDataRef, CFErrorRef*))
{
    if (pDataOut != NULL)
        *pDataOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (key == NULL || pbData == NULL || cbData < 0 || pDataOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    assert(func != NULL);

    CFDataRef input = CFDataCreateWithBytesNoCopy(NULL, pbData, cbData, kCFAllocatorNull);
    CFDataRef output = func(key, algorithm, input, pErrorOut);

    if (*pErrorOut != NULL)
    {
        if (output != NULL)
        {
            CFRelease(output);
            output = NULL;
        }

        return kErrorSeeError;
    }

    if (output == NULL)
    {
        return kErrorUnknownState;
    }

    *pDataOut = output;
    return 1;
}

int32_t AppleCryptoNative_RsaSignaturePrimitive(
    SecKeyRef privateKey, const uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    return RsaPrimitive(
        privateKey, pbData, cbData, pDataOut, pErrorOut, kSecKeyAlgorithmRSASignatureRaw, SecKeyCreateSignature);
}

int32_t AppleCryptoNative_RsaDecryptionPrimitive(
    SecKeyRef privateKey, const uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    return RsaPrimitive(
        privateKey, pbData, cbData, pDataOut, pErrorOut, kSecKeyAlgorithmRSAEncryptionRaw, SecKeyCreateDecryptedData);
}

int32_t AppleCryptoNative_RsaEncryptionPrimitive(
    SecKeyRef publicKey, const uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    return RsaPrimitive(
        publicKey, pbData, cbData, pDataOut, pErrorOut, kSecKeyAlgorithmRSAEncryptionRaw, SecKeyCreateEncryptedData);
}

int32_t AppleCryptoNative_RsaVerificationPrimitive(
    SecKeyRef publicKey, const uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    // Since there's not an API which will give back the still-padded signature block with
    // kSecAlgorithmRSASignatureRaw, use the encryption primitive to achieve the same result.
    return RsaPrimitive(
        publicKey, pbData, cbData, pDataOut, pErrorOut, kSecKeyAlgorithmRSAEncryptionRaw, SecKeyCreateEncryptedData);
}

#endif /* REQUIRE_MAC_SDK_VERSION(10_12) || REQUIRE_IOS_SDK_VERSION(10) */
