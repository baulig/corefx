// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_digest.h"
#include "pal_seckey.h"
#include "pal_compiler.h"
#include "pal_version.h"

#include <Security/Security.h>

DLLEXPORT int32_t AppleCryptoNative_SupportsRsaPrimitives(void);

/*
Apply an RSA private key to a signing operation on data which was already padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaSignaturePrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA private key to an encryption operation to emit data which is still padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaDecryptionPrimitive(
    SecKeyRef privateKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA public key to an encryption operation on data which was already padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaEncryptionPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);

/*
Apply an RSA public key to a signing operation to emit data which is still padded.

Follows pal_seckey return conventions.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaVerificationPrimitive(
    SecKeyRef publicKey, uint8_t* pbData, int32_t cbData, CFDataRef* pDataOut, CFErrorRef* pErrorOut);
