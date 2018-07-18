// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509_ios.h"
#include "pal_utilities.h"
#include "pal_random.h"
#include <dlfcn.h>
#include <pthread.h>

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
    const void *keys[1], *values[1];
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

    keys[0] = kSecImportExportPassphrase;
    values[0] = cfPfxPassphrase;

    CFDataRef data = CFDataCreate(NULL, pbData, cbData);
    if (data == NULL)
    {
        *pOSStatus = errSecAllocate;
        return 0;
    }

    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    if (options == NULL)
    {
        CFRelease(data);
        *pOSStatus = errSecAllocate;
        return 0;
    }

    *pOSStatus = SecPKCS12Import(data, options, &outItems);

    if (*pOSStatus == noErr)
    {
        ret = ProcessCertificateTypeReturn(outItems, pIdentityOut);
    }

    CFRelease(data);
    CFRelease(options);
    if (outItems != NULL)
    {
        CFRelease(outItems);
        outItems = NULL;
    }

    return ret;
}

