// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"
#include "pal_compiler.h"
#include "pal_version.h"

#include <Security/Security.h>

#if REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)

//
// New Unified APIs, which are available on macOS 10.12+ and iOS 10+.
//

/*
Apply an RSA private key to a signing operation on data which was already padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedSignaturePrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA private key to an encryption operation to emit data which is still padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedDecryptionPrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA public key to an encryption operation on data which was already padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedEncryptionPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA public key to a signing operation to emit data which is still padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedVerificationPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedEncryptPkcs(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pEncryptedOut, CFErrorRef* pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_RsaUnifiedDecryptPkcs(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDecryptedOut, CFErrorRef* pErrorOut);


#endif // REQUIRE_MAC_SDK_VERSION(10,12) || REQUIRE_IOS_SDK_VERSION(10,0)

