// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa_mac.h"
#include "pal_seckey_mac.h"

static int32_t ExecuteCFDataTransform(
    SecTransformRef xform, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaGenerateKey(
    int32_t keySizeBits, SecKeychainRef tempKeychain, SecKeyRef* pPublicKey, SecKeyRef* pPrivateKey, int32_t* pOSStatus)
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
        CFDictionaryAddValue(attributes, kSecUseKeychain, tempKeychain);

        status = SecKeyGeneratePair(attributes, pPublicKey, pPrivateKey);

        if (status == noErr)
        {
            status = ExportImportKey(pPublicKey, kSecItemTypePublicKey);
        }

        if (status == noErr)
        {
            status = ExportImportKey(pPrivateKey, kSecItemTypePrivateKey);
        }
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

int32_t AppleCryptoNative_RsaDecryptPkcs(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut)
{
    if (pDecryptedOut != NULL)
        *pDecryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbData == NULL || cbData < 0 || pDecryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    int32_t ret = kErrorSeeError;
    SecTransformRef decryptor = SecDecryptTransformCreate(privateKey, pErrorOut);

    if (decryptor != NULL)
    {
        if (*pErrorOut == NULL)
        {
            ret = ExecuteCFDataTransform(decryptor, pbData, cbData, pDecryptedOut, pErrorOut);
        }

        CFRelease(decryptor);
    }

    return ret;
}

int32_t AppleCryptoNative_RsaEncryptPkcs(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut)
{
    if (pEncryptedOut != NULL)
        *pEncryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (publicKey == NULL || pbData == NULL || cbData < 0 || pEncryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    int32_t ret = kErrorSeeError;
    SecTransformRef encryptor = SecEncryptTransformCreate(publicKey, pErrorOut);

    if (encryptor != NULL)
    {
        if (*pErrorOut == NULL)
        {
            ret = ExecuteCFDataTransform(encryptor, pbData, cbData, pEncryptedOut, pErrorOut);
        }

        CFRelease(encryptor);
    }

    return ret;
}

int32_t AppleCryptoNative_RsaEncryptRaw(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut)
{
    if (pEncryptedOut != NULL)
        *pEncryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (publicKey == NULL || pbData == NULL || cbData < 0 || pEncryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    int32_t ret = kErrorSeeError;
    SecTransformRef encryptor = SecEncryptTransformCreate(publicKey, pErrorOut);

    if (encryptor == NULL)
    {
        return kErrorSeeError;
    }
    if (*pErrorOut != NULL)
    {
        CFRelease(encryptor);
        return kErrorSeeError;
    }

    if (!SecTransformSetAttribute(encryptor, kSecPaddingKey, kSecPaddingNoneKey, pErrorOut))
    {
        CFRelease(encryptor);
        return kErrorSeeError;
    }

    int32_t ret = ExecuteCFDataTransform(encryptor, pbData, cbData, pEncryptedOut, pErrorOut);
    CFRelease(encryptor);
    return ret;
}


#if REQUIRE_MAC_SDK_VERSION(10,8)

static int32_t ExecuteOaepTransform(SecTransformRef xform,
                                    uint8_t* pbData,
                                    int32_t cbData,
                                    PAL_HashAlgorithm algorithm,
                                    CFDataRef* pDataOut,
                                    CFErrorRef* pErrorOut)
{
    if (!SecTransformSetAttribute(xform, kSecPaddingKey, kSecPaddingOAEPKey, pErrorOut))
    {
        return kErrorSeeError;
    }

    // Documentation mentions kSecOAEPMGF1DigestAlgorithmAttributeName, but on the Apple platform
    // "SHA2" is an algorithm and the size is encoded separately. Since there doesn't seem to be
    // a second attribute to encode SHA2-256 vs SHA2-384, be limited to SHA-1.
    if (algorithm != PAL_SHA1)
    {
        return kErrorUnknownAlgorithm;
    }

    return ExecuteCFDataTransform(xform, pbData, cbData, pDataOut, pErrorOut);
}

int32_t AppleCryptoNative_RsaDecryptOaep(SecKeyRef privateKey,
                                         uint8_t* pbData,
                                         int32_t cbData,
                                         PAL_HashAlgorithm mfgAlgorithm,
                                         CFDataRef* pDecryptedOut,
                                         CFErrorRef* pErrorOut)
{
    if (pDecryptedOut != NULL)
        *pDecryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbData == NULL || cbData < 0 || pDecryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    int32_t ret = kErrorSeeError;
    SecTransformRef decryptor = SecDecryptTransformCreate(privateKey, pErrorOut);

    if (decryptor != NULL)
    {
        if (*pErrorOut == NULL)
        {
            ret = ExecuteOaepTransform(decryptor, pbData, cbData, mfgAlgorithm, pDecryptedOut, pErrorOut);
        }

        CFRelease(decryptor);
    }

    return ret;
}

int32_t AppleCryptoNative_RsaEncryptOaep(SecKeyRef publicKey,
                                         uint8_t* pbData,
                                         int32_t cbData,
                                         PAL_HashAlgorithm mgfAlgorithm,
                                         CFDataRef* pEncryptedOut,
                                         CFErrorRef* pErrorOut)
{
    if (pEncryptedOut != NULL)
        *pEncryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (publicKey == NULL || pbData == NULL || cbData < 0 || pEncryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    int32_t ret = kErrorSeeError;
    SecTransformRef encryptor = SecEncryptTransformCreate(publicKey, pErrorOut);

    if (encryptor != NULL)
    {
        if (*pErrorOut == NULL)
        {
            ret = ExecuteOaepTransform(encryptor, pbData, cbData, mgfAlgorithm, pEncryptedOut, pErrorOut);
        }

        CFRelease(encryptor);
    }

    return ret;
}

#endif /* REQUIRE_MAC_SDK_VERSION(10,8) */

int32_t AppleCryptoNative_RsaDecryptRaw(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut)
{
    if (pDecryptedOut != NULL)
        *pDecryptedOut = NULL;
    if (pErrorOut != NULL)
        *pErrorOut = NULL;

    if (privateKey == NULL || pbData == NULL || cbData < 0 || pDecryptedOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    SecTransformRef decryptor = SecDecryptTransformCreate(privateKey, pErrorOut);

    if (decryptor == NULL)
    {
        return kErrorSeeError;
    }
    if (*pErrorOut != NULL)
    {
        CFRelease(decryptor);
        return kErrorSeeError;
    }

    if (!SecTransformSetAttribute(decryptor, kSecPaddingKey, kSecPaddingNoneKey, pErrorOut))
    {
        CFRelease(decryptor);
        return kErrorSeeError;
    }

    int32_t ret = ExecuteCFDataTransform(decryptor, pbData, cbData, pDecryptedOut, pErrorOut);
    CFRelease(decryptor);
    return ret;
}



static int32_t ExecuteCFDataTransform(
    SecTransformRef xform, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut)
{
    if (xform == NULL || pbData == NULL || cbData < 0 || pDataOut == NULL || pErrorOut == NULL)
    {
        return kErrorBadInput;
    }

    *pDataOut = NULL;
    *pErrorOut = NULL;

    CFTypeRef xformOutput = NULL;
    CFDataRef cfData = NULL;
    int32_t ret = INT_MIN;

    cfData = CFDataCreateWithBytesNoCopy(NULL, pbData, cbData, kCFAllocatorNull);

    if (cfData == NULL)
    {
        // This probably means that there wasn't enough memory available, but no
        // particular failure cases are described.
        return kErrorUnknownState;
    }

    if (!SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfData, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    xformOutput = SecTransformExecute(xform, pErrorOut);

    if (xformOutput == NULL || *pErrorOut != NULL)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (CFGetTypeID(xformOutput) == CFDataGetTypeID())
    {
        CFDataRef cfDataOut = (CFDataRef)xformOutput;
        CFRetain(cfDataOut);
        *pDataOut = cfDataOut;
        ret = 1;
    }
    else
    {
        ret = kErrorUnknownState;
    }

cleanup:
    if (xformOutput != NULL)
    {
        CFRelease(xformOutput);
    }

    if (cfData != NULL)
    {
        CFRelease(cfData);
    }

    return ret;
}

