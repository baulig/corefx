// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#pragma once

#include "pal_rsa.h"

/*
Generate a new RSA keypair with the specified key size, in bits.

Returns 1 on success, 0 on failure.  On failure, *pOSStatus should contain the OS reported error.
*/
DLLEXPORT int32_t AppleCryptoNative_RsaGenerateKey(int32_t keySizeBits,
                                                   SecKeyRef* pPublicKey,
                                                   SecKeyRef* pPrivateKey,
                                                   int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_RsaEncryptPkcs(SecKeyRef SecKeyRef,
                                                   uint8_t* pbData,
                                                   int32_t cbData,
                                                   uint8_t* pbCipherOut,
                                                   size_t *cbCipherLen,
                                                   int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_RsaEncryptOaep(SecKeyRef SecKeyRef,
                                                   uint8_t* pbData,
                                                   int32_t cbData,
                                                   uint8_t* pbCipherOut,
                                                   size_t *cbCipherLen,
                                                   int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_RsaDecryptPkcs(SecKeyRef secKeyRef,
                                                   uint8_t* pbData,
                                                   int32_t cbData,
                                                   uint8_t* pbPlainOut,
                                                   size_t *cbPlainLen,
                                                   int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_RsaDecryptOaep(SecKeyRef secKeyRef,
                                                   uint8_t* pbData,
                                                   int32_t cbData,
                                                   uint8_t* pbPlainOut,
                                                   size_t *cbPlainLen,
                                                   int32_t* pOSStatus);

DLLEXPORT int32_t AppleCryptoNative_GenerateSignature(SecKeyRef privateKey,
                                                      uint8_t* pbDataHash,
                                                      int32_t cbDataHash,
                                                      CFDataRef *pSignatureOut,
                                                      CFErrorRef *pErrorOut);

DLLEXPORT int32_t AppleCryptoNative_GenerateSignatureWithHashAlgorithm(SecKeyRef privateKey,
                                                                       uint8_t* pbDataHash,
                                                                       int32_t cbDataHash,
                                                                       PAL_HashAlgorithm hashAlgorithm,
                                                                       CFDataRef *pSignatureOut,
                                                                       CFErrorRef *pErrorOut);
