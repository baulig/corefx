// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Apple;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    public partial class RSA : AsymmetricAlgorithm
    {
        public static new RSA Create()
        {
            return new RSAImplementation.RSASecurityTransforms();
        }
    }
#endif

    internal static partial class RSAImplementation
    {
        partial class RSASecurityTransforms
        {
            public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                if (hash == null)
                    throw new ArgumentNullException(nameof(hash));
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw HashAlgorithmNameNullOrEmpty();
                if (padding == null)
                    throw new ArgumentNullException(nameof(padding));

                if (padding == RSASignaturePadding.Pkcs1)
                {
                    SecKeyPair keys = GetKeys();

                    if (keys.PrivateKey == null)
                    {
                        throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                    }

                    int expectedSize;
                    Interop.AppleCrypto.PAL_HashAlgorithm palAlgId =
                        PalAlgorithmFromAlgorithmName(hashAlgorithm, out expectedSize);

                    if (hash.Length != expectedSize)
                    {
                        // Windows: NTE_BAD_DATA ("Bad Data.")
                        // OpenSSL: RSA_R_INVALID_MESSAGE_LENGTH ("invalid message length")
                        throw new CryptographicException(
                            SR.Format(
                                SR.Cryptography_BadHashSize_ForAlgorithm,
                                hash.Length,
                                expectedSize,
                                hashAlgorithm.Name));
                    }

                    return Interop.AppleCrypto.GenerateSignature(
                        keys.PrivateKey,
                        hash,
                        palAlgId);
                }

                // A signature will always be the keysize (in ceiling-bytes) in length.
                int outputSize = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);
                byte[] output = new byte[outputSize];

                if (!TrySignHash(hash, output, hashAlgorithm, padding, out int bytesWritten))
                {
                    Debug.Fail("TrySignHash failed with a pre-allocated buffer");
                    throw new CryptographicException();
                }

                Debug.Assert(bytesWritten == outputSize);
                return output;
            }

            public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten)
            {
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                {
                    throw HashAlgorithmNameNullOrEmpty();
                }
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                RsaPaddingProcessor processor = null;

                if (padding.Mode == RSASignaturePaddingMode.Pss)
                {
                    processor = RsaPaddingProcessor.OpenProcessor(hashAlgorithm);
                }
                else if (padding != RSASignaturePadding.Pkcs1)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
                }

                SecKeyPair keys = GetKeys();

                if (keys.PrivateKey == null)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }

                int keySize = KeySize;
                int rsaSize = RsaPaddingProcessor.BytesRequiredForBitCount(keySize);

                if (processor == null)
                {
                    Interop.AppleCrypto.PAL_HashAlgorithm palAlgId =
                        PalAlgorithmFromAlgorithmName(hashAlgorithm, out int expectedSize);

                    if (hash.Length != expectedSize)
                    {
                        // Windows: NTE_BAD_DATA ("Bad Data.")
                        // OpenSSL: RSA_R_INVALID_MESSAGE_LENGTH ("invalid message length")
                        throw new CryptographicException(
                            SR.Format(
                                SR.Cryptography_BadHashSize_ForAlgorithm,
                                hash.Length,
                                expectedSize,
                                hashAlgorithm.Name));
                    }

                    if (destination.Length < rsaSize)
                    {
                        bytesWritten = 0;
                        return false;
                    }

                    return Interop.AppleCrypto.TryGenerateSignature(
                        keys.PrivateKey,
                        hash,
                        destination,
                        palAlgId,
                        out bytesWritten);
                }

                Debug.Assert(padding.Mode == RSASignaturePaddingMode.Pss);

                if (destination.Length < rsaSize)
                {
                    bytesWritten = 0;
                    return false;
                }

                byte[] rented = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> buf = new Span<byte>(rented, 0, rsaSize);
                processor.EncodePss(hash, buf, keySize);

                try
                {
                    return Interop.AppleCrypto.TryRsaSignaturePrimitive(keys.PrivateKey, buf, destination, out bytesWritten);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(buf);
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            public override bool VerifyHash(
                byte[] hash,
                byte[] signature,
                HashAlgorithmName hashAlgorithm,
                RSASignaturePadding padding)
            {
                if (hash == null)
                {
                    throw new ArgumentNullException(nameof(hash));
                }
                if (signature == null)
                {
                    throw new ArgumentNullException(nameof(signature));
                }

                return VerifyHash((ReadOnlySpan<byte>)hash, (ReadOnlySpan<byte>)signature, hashAlgorithm, padding);
            }

            public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                {
                    throw HashAlgorithmNameNullOrEmpty();
                }
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                if (padding == RSASignaturePadding.Pkcs1)
                {
                    Interop.AppleCrypto.PAL_HashAlgorithm palAlgId =
                        PalAlgorithmFromAlgorithmName(hashAlgorithm, out int expectedSize);
                    return Interop.AppleCrypto.VerifySignature(GetKeys().PublicKey, hash, signature, palAlgId);
                }
                else if (padding.Mode == RSASignaturePaddingMode.Pss)
                {
                    RsaPaddingProcessor processor = RsaPaddingProcessor.OpenProcessor(hashAlgorithm);
                    SafeSecKeyRefHandle publicKey = GetKeys().PublicKey;

                    int keySize = KeySize;
                    int rsaSize = RsaPaddingProcessor.BytesRequiredForBitCount(keySize);

                    if (signature.Length != rsaSize)
                    {
                        return false;
                    }

                    if (hash.Length != processor.HashLength)
                    {
                        return false;
                    }

                    byte[] rented = ArrayPool<byte>.Shared.Rent(rsaSize);
                    Span<byte> unwrapped = new Span<byte>(rented, 0, rsaSize);

                    try
                    {
                        if (!Interop.AppleCrypto.TryRsaVerificationPrimitive(
                            publicKey,
                            signature,
                            unwrapped,
                            out int bytesWritten))
                        {
                            Debug.Fail($"TryRsaVerificationPrimitive with a pre-allocated buffer");
                            throw new CryptographicException();
                        }

                        Debug.Assert(bytesWritten == rsaSize);
                        return processor.VerifyPss(hash, unwrapped, keySize);
                    }
                    finally
                    {
                        unwrapped.Clear();
                        ArrayPool<byte>.Shared.Return(rented);
                    }
                }

                throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
            }
        }
    }
}
