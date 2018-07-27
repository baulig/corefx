#pragma once

#include "pal_x509.h"

DLLEXPORT int32_t AppleCryptoNative_X509ImportCertificate(uint8_t* pbData,
							  int32_t cbData,
							  PAL_X509ContentType contentType,
							  CFStringRef cfPfxPassphrase,
							  SecCertificateRef* pCertOut,
							  SecIdentityRef* pIdentityOut,
							  int32_t* pOSStatus);

