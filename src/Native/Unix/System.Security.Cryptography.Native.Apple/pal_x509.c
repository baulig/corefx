// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509.h"
#include "pal_utilities.h"

int32_t AppleCryptoNative_X509CopyCertFromIdentity(SecIdentityRef identity, SecCertificateRef* pCertOut)
{
    if (pCertOut != NULL)
        *pCertOut = NULL;

    // This function handles null inputs for both identity and cert.
    return SecIdentityCopyCertificate(identity, pCertOut);
}

int32_t AppleCryptoNative_X509CopyPrivateKeyFromIdentity(SecIdentityRef identity, SecKeyRef* pPrivateKeyOut)
{
    if (pPrivateKeyOut != NULL)
        *pPrivateKeyOut = NULL;

    // This function handles null inputs for both identity and key
    return SecIdentityCopyPrivateKey(identity, pPrivateKeyOut);
}

int32_t
AppleCryptoNative_X509DemuxAndRetainHandle(CFTypeRef handle, SecCertificateRef* pCertOut, SecIdentityRef* pIdentityOut)
{
    if (pCertOut != NULL)
        *pCertOut = NULL;
    if (pIdentityOut != NULL)
        *pIdentityOut = NULL;

    if (handle == NULL || pCertOut == NULL || pIdentityOut == NULL)
        return kErrorBadInput;

    CFTypeID objectType = CFGetTypeID(handle);

    if (objectType == SecIdentityGetTypeID())
    {
        *pIdentityOut = (SecIdentityRef)CONST_CAST(void *, handle);
    }
    else if (objectType == SecCertificateGetTypeID())
    {
        *pCertOut = (SecCertificateRef)CONST_CAST(void *, handle);
    }
    else
    {
        return 0;
    }

    CFRetain(handle);
    return 1;
}


