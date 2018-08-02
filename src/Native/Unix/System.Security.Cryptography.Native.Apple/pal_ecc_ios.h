// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_ecc.h"

/*
Generate an ECC keypair of the specified size.

Returns 1 on success, 0 on failure. On failure, *pOSStatus should carry the OS failure code.
*/
DLLEXPORT int32_t AppleCryptoNative_EccGenerateKey(int32_t keySizeBits,
                                                   SecKeyRef* pPublicKey,
                                                   SecKeyRef* pPrivateKey,
                                                   int32_t* pOSStatus);

