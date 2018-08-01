// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_seckey.h"
#include "pal_symmetric.h"

DLLEXPORT CFDataRef AppleCryptoNative_SecKeyExport(SecKeyRef pKey, CFErrorRef *pErrorOut);

DLLEXPORT SecKeyRef AppleCryptoNative_SecKeyImportEphemeral(
    uint8_t* pbKeyBlob, int32_t cbKeyBlob, int32_t isPrivateKey, CFErrorRef *pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_SecKeyEncrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbCipherOut, int32_t *cbCipherLen, int32_t* pOSStatus, CFErrorRef *pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_SecKeyDecrypt(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbPlainOut, int32_t *cbPlainLen, int32_t* pOSStatus, CFErrorRef *pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_SecKeySign(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbSigOut, int32_t *cbSigLen, int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_SecKeyVerify(
    SecKeyRef key, PAL_PaddingMode padding, const uint8_t* pbData, int32_t cbData,
    uint8_t* pbSig, int32_t *cbSigLen, int32_t* pOSStatus);
