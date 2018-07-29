// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_seckey.h"

DLLEXPORT CFDataRef AppleCryptoNative_SecKeyExport(SecKeyRef pKey, CFErrorRef *pErrorOut);

DLLEXPORT SecKeyRef AppleCryptoNative_SecKeyImportEphemeral(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, CFErrorRef *pErrorOut);
