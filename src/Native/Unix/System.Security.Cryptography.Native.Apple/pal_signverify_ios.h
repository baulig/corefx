// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_signverify.h"


int32_t AppleCryptoNative_iOSGenerateSignature(SecKeyRef privateKey,
                                               uint8_t* pbDataHash,
                                               int32_t cbDataHash,
                                               PAL_HashAlgorithm hashAlgorithm,
                                               bool useHashAlgorithm,
                                               CFDataRef* pSignatureOut,
                                               int32_t *pOSStatusOut,
                                               CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_iOSVerifySignature(SecKeyRef publicKey,
                                             uint8_t* pbDataHash,
                                             int32_t cbDataHash,
                                             uint8_t* pbSignature,
                                             int32_t cbSignature,
                                             PAL_HashAlgorithm hashAlgorithm,
                                             bool useHashAlgorithm,
                                             int32_t *pOSStatusOut,
                                             CFErrorRef* pErrorOut);

