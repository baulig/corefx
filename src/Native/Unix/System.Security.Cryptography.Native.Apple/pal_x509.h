// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"
#include "pal_compiler.h"

#include <Security/Security.h>

enum
{
    PAL_X509Unknown = 0,
    PAL_Certificate = 1,
    PAL_SerializedCert = 2,
    PAL_Pkcs12 = 3,
    PAL_SerializedStore = 4,
    PAL_Pkcs7 = 5,
    PAL_Authenticode = 6,
};
typedef uint32_t PAL_X509ContentType;

static const int32_t kErrOutItemsNull = -3;
static const int32_t kErrOutItemsEmpty = -2;
static const int32_t kErrOutNotFound = -4;



/*
Extract a SecKeyRef for the public key from the certificate handle.

Returns 1 on success, 0 on failure, any other value on invalid state.

Output:
pPublicKeyOut: Receives a CFRetain()ed SecKeyRef for the public key
pOSStatusOut: Receives the result of SecCertificateCopyPublicKey
*/
DLLEXPORT int32_t
AppleCryptoNative_X509GetPublicKey(SecCertificateRef cert, SecKeyRef* pPublicKeyOut, int32_t* pOSStatusOut);


/*
Extract the DER encoded value of a certificate (public portion only).

Returns 1 on success, 0 on failure, any other value indicates invalid state.

Output:
ppDataOut: Receives a CFDataRef with the exported blob
pOSStatus: Receives the result of SecItemExport
*/
DLLEXPORT int32_t AppleCryptoNative_X509GetRawData(SecCertificateRef cert, CFDataRef* ppDataOut, int32_t* pOSStatus);

/*
 Given a handle, determine if it represents a SecCertificateRef, SecIdentityRef, or other.
 If the handle is a certificate or identity it is CFRetain()ed (and must later be CFRelease()d).

 Returns 1 if the handle was a certificate or identity, 0 otherwise (other values on invalid state).

 Output:
 pCertOut: If handle is a certificate, receives handle, otherwise NULL
 pIdentityut: If handle is an identity, receives handle, otherwise NULL
 */
DLLEXPORT int32_t
AppleCryptoNative_X509DemuxAndRetainHandle(CFTypeRef handle, SecCertificateRef* pCertOut, SecIdentityRef* pIdentityOut);


/*
 Determines the data type of the provided input.

 Returns the data (format) type of the provided input, PAL_X509Unknown if it cannot be determined.
 */
DLLEXPORT PAL_X509ContentType AppleCryptoNative_X509GetContentType(uint8_t* pbData, int32_t cbData);


/*
 Extract a SecCertificateRef for the certificate from an identity handle.

 Returns the result of SecIdentityCopyCertificate.

 Output:
 pCertOut: Receives a SecCertificateRef for the certificate associated with the identity
 */
DLLEXPORT int32_t AppleCryptoNative_X509CopyCertFromIdentity(SecIdentityRef identity, SecCertificateRef* pCertOut);

/*
 Extract a SecKeyRef for the private key from an identity handle.

 Returns the result of SecIdentityCopyPrivateKey

 Output:
 pPrivateKeyOut: Receives a SecKeyRef for the private key associated with the identity
 */
DLLEXPORT int32_t AppleCryptoNative_X509CopyPrivateKeyFromIdentity(SecIdentityRef identity, SecKeyRef* pPrivateKeyOut);

