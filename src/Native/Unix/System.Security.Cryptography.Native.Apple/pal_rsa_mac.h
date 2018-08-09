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
                                                   SecKeychainRef tempKeychain,
                                                   SecKeyRef* pPublicKey,
                                                   SecKeyRef* pPrivateKey,
                                                   int32_t* pOSStatus);


int32_t AppleCryptoNative_RsaMacDecryptPkcs(SecKeyRef privateKey,
                                            uint8_t* pbData,
                                            int32_t cbData,
                                            CFDataRef* pDecryptedOut,
                                            CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacEncryptPkcs(SecKeyRef publicKey,
                                            uint8_t* pbData,
                                            int32_t cbData,
                                            CFDataRef* pEncryptedOut,
                                            CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacEncryptionPrimitive(SecKeyRef publicKey,
                                                    uint8_t* pbData,
                                                    int32_t cbData,
                                                    CFDataRef* pEncryptedOut,
                                                    CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacDecryptOaep(SecKeyRef privateKey,
                                            uint8_t* pbData,
                                            int32_t cbData,
                                            PAL_HashAlgorithm mfgAlgorithm,
                                            CFDataRef* pDecryptedOut,
                                            CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacEncryptOaep(SecKeyRef publicKey,
                                            uint8_t* pbData,
                                            int32_t cbData,
                                            PAL_HashAlgorithm mgfAlgorithm,
                                            CFDataRef* pEncryptedOut,
                                            CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacDecryptionPrimitive(SecKeyRef privateKey,
                                                    uint8_t* pbData,
                                                    int32_t cbData,
                                                    CFDataRef* pDecryptedOut,
                                                    CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacSignaturePrimitive(SecKeyRef privateKey,
                                                   uint8_t* pbData,
                                                   int32_t cbData,
                                                   CFDataRef* pSignatureOut,
                                                   CFErrorRef* pErrorOut);

int32_t AppleCryptoNative_RsaMacVerificationPrimitive(SecKeyRef publicKey,
                                                      uint8_t* pbData,
                                                      int32_t cbData,
                                                      CFDataRef* pSignatureOut,
                                                      CFErrorRef* pErrorOut);




