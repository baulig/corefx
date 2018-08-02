// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_seckey.h"
#include "pal_compiler.h"

#include <Security/Security.h>

/*
Get the keysize, in bits, of an ECC key.

Returns the keysize, in bits, of the ECC key, or 0 on error.
*/
DLLEXPORT uint64_t AppleCryptoNative_EccGetKeySizeInBits(SecKeyRef publicKey);
