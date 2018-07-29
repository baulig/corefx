#pragma once

#include "pal_x509.h"

/*
Extract a SecKeyRef for the public key from the certificate handle.

Returns 1 on success, 0 on failure, any other value on invalid state.

Output:
pPublicKeyOut: Receives a CFRetain()ed SecKeyRef for the public key
pOSStatusOut: Receives the result of SecCertificateCopyPublicKey
*/
DLLEXPORT int32_t
AppleCryptoNative_X509GetPublicKey(SecCertificateRef cert, SecKeyRef* pPublicKeyOut, int32_t* pOSStatusOut);

DLLEXPORT int32_t AppleCryptoNative_X509ImportCertificate(uint8_t* pbData,
							  int32_t cbData,
							  PAL_X509ContentType contentType,
							  CFStringRef cfPfxPassphrase,
							  SecCertificateRef* pCertOut,
							  SecIdentityRef* pIdentityOut,
							  int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_X509GetRawData(SecCertificateRef cert, CFDataRef* ppDataOut, int32_t* pOSStatus);

