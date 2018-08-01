// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include <pal_types.h>
#include "pal_compiler.h"

#include <Security/Security.h>

// Unless another interpretation is "obvious", pal_seckey functions return 1 on success.
// functions which represent a boolean return 0 on "successful false"
// otherwise functions will return one of the following return values:
static const int32_t kErrorBadInput = -1;
static const int32_t kErrorSeeError = -2;
static const int32_t kErrorUnknownAlgorithm = -3;
static const int32_t kErrorUnknownState = -4;
static const int32_t kErrorMaybeTooSmall = -5;

/*
For RSA and DSA this function returns the number of bytes in "the key", which corresponds to
the length of n/Modulus for RSA and for P in DSA.

For ECC the value should not be used.

0 is returned for invalid inputs.
*/
DLLEXPORT uint64_t AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(SecKeyRef publicKey);

