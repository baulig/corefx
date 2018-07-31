// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa_ios.h"

int32_t AppleCryptoNative_RsaGenerateKey(
    int32_t keySizeBits, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus)
{
    if (pPublicKey != NULL)
        *pPublicKey = NULL;
    if (pPrivateKey != NULL)
        *pPrivateKey = NULL;

    if (pPublicKey == NULL || pPrivateKey == NULL || pOSStatus == NULL)
        return kErrorBadInput;
    if (keySizeBits < 384 || keySizeBits > 16384)
        return -2;

    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 2, &kCFTypeDictionaryKeyCallBacks, NULL);

    CFNumberRef cfKeySizeValue = CFNumberCreate(NULL, kCFNumberIntType, &keySizeBits);
    OSStatus status;

    if (attributes != NULL && cfKeySizeValue != NULL)
    {
        CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, cfKeySizeValue);

        status = SecKeyGeneratePair(attributes, pPublicKey, pPrivateKey);
    }
    else
    {
        status = errSecAllocate;
    }

    if (attributes != NULL)
        CFRelease(attributes);
    if (cfKeySizeValue != NULL)
        CFRelease(cfKeySizeValue);

    *pOSStatus = status;
    return status == noErr;
}

int32_t AppleCryptoNative_RsaEncryptPkcs(
    SecKeyRef secKeyRef, uint8_t* pbData, int32_t cbData, uint8_t* pbCipherOut, size_t *cbCipherLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbCipherOut == NULL || cbCipherLen == NULL || *cbCipherLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    *pOSStatus = SecKeyEncrypt(secKeyRef, kSecPaddingPKCS1, pbData, cbData, pbCipherOut, cbCipherLen);
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_RsaEncryptOaep(
    SecKeyRef secKeyRef, uint8_t* pbData, int32_t cbData, uint8_t* pbCipherOut, size_t *cbCipherLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbCipherOut == NULL || cbCipherLen == NULL || *cbCipherLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    *pOSStatus = SecKeyEncrypt(secKeyRef, kSecPaddingOAEP, pbData, cbData, pbCipherOut, cbCipherLen);
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_RsaDecryptPkcs(
    SecKeyRef secKeyRef, uint8_t* pbData, int32_t cbData, uint8_t* pbPlainOut, size_t *cbPlainLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbPlainOut == NULL || cbPlainLen == NULL || *cbPlainLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    *pOSStatus = SecKeyDecrypt(secKeyRef, kSecPaddingPKCS1, pbData, cbData, pbPlainOut, cbPlainLen);
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_RsaDecryptOaep(
    SecKeyRef secKeyRef, uint8_t* pbData, int32_t cbData, uint8_t* pbPlainOut, size_t *cbPlainLen, int32_t* pOSStatus)
{
    if (pbData == NULL || cbData < 0 || pbPlainOut == NULL || cbPlainLen == NULL || *cbPlainLen < 0 || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    *pOSStatus = SecKeyDecrypt(secKeyRef, kSecPaddingOAEP, pbData, cbData, pbPlainOut, cbPlainLen);
    return *pOSStatus == noErr;
}

int32_t AppleCryptoNative_GenerateSignature(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    return AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
        privateKey, pbDataHash, cbDataHash, PAL_SHA1, pSignatureOut, pErrorOut);
}

int32_t AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, PAL_HashAlgorithm hashAlgorithm,
    CFDataRef *pSignatureOut, CFErrorRef *pErrorOut)
{
    if (pSignatureOut != NULL)
        *pSignatureOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbDataHash == NULL || cbDataHash < 0 || pSignatureOut == NULL ||
        pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(NULL, pbDataHash, cbDataHash, kCFAllocatorNull);

    if (dataHash == NULL)
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

    *pSignatureOut = SecKeyCreateSignature(privateKey, algorithm, dataHash, pErrorOut);
    return *pSignatureOut != NULL;
}
