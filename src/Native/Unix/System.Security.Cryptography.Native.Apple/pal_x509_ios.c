// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_x509_ios.h"
#include "pal_utilities.h"
#include <dlfcn.h>
#include <pthread.h>

int32_t AppleCryptoNative_X509ImportCertificate(uint8_t* pbData,
						int32_t cbData,
						PAL_X509ContentType contentType,
						CFStringRef cfPfxPassphrase,
						SecCertificateRef* pCertOut,
						SecIdentityRef* pIdentityOut,
						int32_t* pOSStatus)
{
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

	return kErrorBadInput;
}
