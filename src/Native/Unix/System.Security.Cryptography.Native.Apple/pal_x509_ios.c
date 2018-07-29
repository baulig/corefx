// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509_ios.h"
#include "pal_utilities.h"
#include "pal_random.h"
#include <dlfcn.h>
#include <pthread.h>

int32_t
AppleCryptoNative_X509GetPublicKey(SecCertificateRef cert, SecKeyRef* pPublicKeyOut, int32_t* pOSStatusOut)
{
    if (pPublicKeyOut != NULL)
        *pPublicKeyOut = NULL;
    if (pOSStatusOut != NULL)
        *pOSStatusOut = noErr;

    if (cert == NULL || pPublicKeyOut == NULL || pOSStatusOut == NULL)
        return kErrorBadInput;

    *pPublicKeyOut = SecCertificateCopyPublicKey(cert);
    return 1;
}

static OSStatus ImportCertificatePKCS12(CFDataRef cfData, CFStringRef cfPfxPassphrase, CFArrayRef *outItems)
{
    const void *keys[1], *values[1];
    OSStatus status;

    keys[0] = kSecImportExportPassphrase;
    values[0] = cfPfxPassphrase;

    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    if (options == NULL)
    {
        return errSecAllocate;
    }

    status = SecPKCS12Import(cfData, options, outItems);

    CFRelease(options);
    return status;
}

PAL_X509ContentType AppleCryptoNative_X509GetContentType(uint8_t* pbData, int32_t cbData)
{
    if (pbData == NULL || cbData < 0)
        return PAL_X509Unknown;

    CFDataRef cfData = CFDataCreateWithBytesNoCopy(NULL, pbData, cbData, kCFAllocatorNull);

    if (cfData == NULL)
        return PAL_X509Unknown;

    SecCertificateRef certref = SecCertificateCreateWithData(NULL, cfData);

    if (certref != NULL)
    {
        CFRelease(certref);
        return PAL_Certificate;
    }

    OSStatus osStatus = ImportCertificatePKCS12(cfData, NULL, NULL);
    if (osStatus == noErr || osStatus == errSecPassphraseRequired || osStatus == errSecPkcs12VerifyFailure || osStatus == errSecAuthFailed)
    {
            return PAL_Pkcs12;
    }

    return PAL_X509Unknown;
}


static int
export_certificate (void)
{
    // SecPSK12Import does not allow any empty passwords, so let's generate a random one.
    CFStringRef cfRandomPassword;
    const int RANDOM_SIZE = 32;
    int32_t ret, status;
    uint8_t pwBuffer [RANDOM_SIZE];
    uint8_t pwStringBuffer [RANDOM_SIZE << 1];
    int i;

    ret = AppleCryptoNative_GetRandomBytes(pwBuffer, RANDOM_SIZE, &status);
    if (!ret)
        return kErrorUnknownState;

    // Convert to String
    for (i = 0; i < RANDOM_SIZE; i++)
    {
        uint8_t hi, lo;

        hi = pwBuffer[i] >> 4;
        lo = pwBuffer[i] & 0x0f;

        pwStringBuffer[i<<1] = hi > 9 ? (0x57 + hi) : 0x30 + hi;
        pwStringBuffer[(i<<1)+1] = lo > 9 ? (0x57 + lo) : 0x30 + lo;
    }

    cfRandomPassword = CFStringCreateWithBytes(NULL, pwStringBuffer, RANDOM_SIZE << 1,kCFStringEncodingASCII, FALSE);
    if (cfRandomPassword == NULL)
    {
        // CFRelease(data);
        // *pOSStatus = errSecAllocate;
        return 0;
    }

    return 1;
}

static int32_t ProcessCertificateTypeReturn(CFArrayRef items, SecIdentityRef* pIdentityOut)
{
    assert(pIdentityOut != NULL && *pIdentityOut == NULL);

    if (items == NULL)
    {
        return kErrOutItemsNull;
    }

    CFIndex itemCount = CFArrayGetCount(items);

    if (itemCount == 0)
    {
        return kErrOutItemsEmpty;
    }

    if (itemCount != 1)
    {
        return kErrorUnknownState;
    }

    CFDictionaryRef itemDict = CFArrayGetValueAtIndex(items, 0);
    if (CFGetTypeID(itemDict) != CFDictionaryGetTypeID())
    {
        return kErrorUnknownState;
    }

    const void *identity = CFDictionaryGetValue(itemDict, kSecImportItemIdentity);
    if (identity == NULL)
    {
        return kErrOutNotFound;
    }

    CFRetain(identity);
    *pIdentityOut = (SecIdentityRef)CONST_CAST(void *, identity);

    /*
     * It also returns the certificate chain and trust object.
     *
     * const void *chain = CFDictionaryGetValue(firstItem, kSecImportItemCertChain);
     * const void *id = CFDictionaryGetValue(firstItem, kSecImportItemTrust);
     */

    return 1;
}

int32_t AppleCryptoNative_X509ImportCertificate(uint8_t* pbData,
                                                int32_t cbData,
                                                PAL_X509ContentType contentType,
                                                CFStringRef cfPfxPassphrase,
                                                SecCertificateRef* pCertOut,
                                                SecIdentityRef* pIdentityOut,
                                                int32_t* pOSStatus)
{
    CFArrayRef outItems = NULL;
    int32_t ret = 0;

    if (pCertOut != NULL)
        *pCertOut = NULL;
    if (pIdentityOut != NULL)
        *pIdentityOut = NULL;
    if (pOSStatus != NULL)
        *pOSStatus = noErr;

    if (pbData == NULL || cbData < 0 || pCertOut == NULL || pIdentityOut == NULL || pOSStatus == NULL)
    {
        return kErrorBadInput;
    }

    CFDataRef cfData = CFDataCreateWithBytesNoCopy(NULL, pbData, cbData, kCFAllocatorNull);
    if (cfData == NULL)
    {
        *pOSStatus = errSecAllocate;
        return 0;
    }

    if (contentType == PAL_Certificate)
    {
        SecCertificateRef certref = SecCertificateCreateWithData(NULL, cfData);

        if (certref != NULL)
        {
            CFRelease(certref);
            return PAL_Certificate;
        }

        return kErrorBadInput;
    }

    *pOSStatus = ImportCertificatePKCS12(cfData, cfPfxPassphrase, &outItems);

    if (*pOSStatus == noErr)
    {
        ret = ProcessCertificateTypeReturn(outItems, pIdentityOut);
    }

    if (outItems != NULL)
    {
        CFRelease(outItems);
        outItems = NULL;
    }

    return ret;
}

int32_t AppleCryptoNative_X509GetRawData(SecCertificateRef cert, CFDataRef* ppDataOut, int32_t* pOSStatus)
{
    if (ppDataOut != NULL)
        *ppDataOut = NULL;
    if (pOSStatus != NULL)
        *pOSStatus = noErr;

    if (cert == NULL || ppDataOut == NULL || pOSStatus == NULL)
        return kErrorBadInput;

    *ppDataOut = SecCertificateCopyData(cert);
    *pOSStatus = 0;
    return 1;
}

