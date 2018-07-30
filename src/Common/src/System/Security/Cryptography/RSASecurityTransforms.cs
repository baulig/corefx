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
    internal static partial class RSAImplementation
    {
        public sealed partial class RSASecurityTransforms : RSA
        {
            private SecKeyPair _keys;

            public RSASecurityTransforms()
                : this(2048)
            {
            }

            public RSASecurityTransforms(int keySize)
            {
                KeySize = keySize;
            }

            internal RSASecurityTransforms(SafeSecKeyRefHandle publicKey)
            {
                SetKey(SecKeyPair.PublicOnly(publicKey));
            }

            internal RSASecurityTransforms(SafeSecKeyRefHandle publicKey, SafeSecKeyRefHandle privateKey)
            {
                SetKey(SecKeyPair.PublicPrivatePair(publicKey, privateKey));
            }

            public override KeySizes[] LegalKeySizes
            {
                get
                {
                    return new KeySizes[]
                    {
                        // All values are in bits.
                        // 1024 was achieved via experimentation.
                        // 1024 and 1024+8 both generated successfully, 1024-8 produced errSecParam.
                        new KeySizes(minSize: 1024, maxSize: 16384, skipSize: 8),
                    };
                }
            }

            public override int KeySize
            {
                get
                {
                    return base.KeySize;
                }
                set
                {
                    if (KeySize == value)
                        return;

                    // Set the KeySize before freeing the key so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    if (_keys != null)
                    {
                        _keys.Dispose();
                        _keys = null;
                    }
                }
            }

            protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
                AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

            protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
                AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

            protected override bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
                AsymmetricAlgorithmHelpers.TryHashData(data, destination, hashAlgorithm, out bytesWritten);

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    if (_keys != null)
                    {
                        _keys.Dispose();
                        _keys = null;
                    }
                }

                base.Dispose(disposing);
            }

            private static Interop.AppleCrypto.PAL_HashAlgorithm PalAlgorithmFromAlgorithmName(
                HashAlgorithmName hashAlgorithmName,
                out int hashSizeInBytes)
            {
                if (hashAlgorithmName == HashAlgorithmName.MD5)
                {
                    hashSizeInBytes = 128 >> 3;
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Md5;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA1)
                {
                    hashSizeInBytes = 160 >> 3;
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha1;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA256)
                {
                    hashSizeInBytes = 256 >> 3;
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha256;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA384)
                {
                    hashSizeInBytes = 384 >> 3;
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha384;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA512)
                {
                    hashSizeInBytes = 512 >> 3;
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha512;
                }

                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }

            internal SecKeyPair GetKeys()
            {
                SecKeyPair current = _keys;

                if (current != null)
                {
                    return current;
                }

                SafeSecKeyRefHandle publicKey;
                SafeSecKeyRefHandle privateKey;

                Interop.AppleCrypto.RsaGenerateKey(KeySizeValue, out publicKey, out privateKey);

                current = SecKeyPair.PublicPrivatePair(publicKey, privateKey);
                _keys = current;
                return current;
            }

            private void SetKey(SecKeyPair newKeyPair)
            {
                SecKeyPair current = _keys;
                _keys = newKeyPair;
                current?.Dispose();

                if (newKeyPair != null)
                {
                    KeySizeValue = Interop.AppleCrypto.GetSimpleKeySizeInBits(newKeyPair.PublicKey);
                }
            }

            public override RSAParameters ExportParameters(bool includePrivateParameters)
            {
                SecKeyPair keys = GetKeys();

                SafeSecKeyRefHandle keyHandle = includePrivateParameters ? keys.PrivateKey : keys.PublicKey;

                if (keyHandle == null)
                {
                    throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
                }

                DerSequenceReader keyReader = Interop.AppleCrypto.SecKeyExport(keyHandle, ref includePrivateParameters);
                RSAParameters parameters = new RSAParameters();

                if (includePrivateParameters)
                {
                    keyReader.ReadPkcs8Blob(ref parameters);
                }
                else
                {
                    // When exporting a key handle opened from a certificate, it seems to
                    // export as a PKCS#1 blob instead of an X509 SubjectPublicKeyInfo blob.
                    // So, check for that.
                    if (keyReader.PeekTag() == (byte)DerSequenceReader.DerTag.Integer)
                    {
                        keyReader.ReadPkcs1PublicBlob(ref parameters);
                    }
                    else
                    {
                        keyReader.ReadSubjectPublicKeyInfo(ref parameters);
                    }
                }

                return parameters;
            }

            public override void ImportParameters(RSAParameters parameters)
            {
                bool isPrivateKey = parameters.D != null;

                if (isPrivateKey)
                {
                    // Start with the private key, in case some of the private key fields
                    // don't match the public key fields.
                    //
                    // Public import should go off without a hitch.
                    SafeSecKeyRefHandle privateKey = ImportKey(parameters);

                    RSAParameters publicOnly = new RSAParameters
                    {
                        Modulus = parameters.Modulus,
                        Exponent = parameters.Exponent,
                    };

                    SafeSecKeyRefHandle publicKey;
                    try
                    {
                        publicKey = ImportKey(publicOnly);
                    }
                    catch
                    {
                        privateKey.Dispose();
                        throw;
                    }

                    SetKey(SecKeyPair.PublicPrivatePair(publicKey, privateKey));
                }
                else
                {
                    SafeSecKeyRefHandle publicKey = ImportKey(parameters);
                    SetKey(SecKeyPair.PublicOnly(publicKey));
                }
            }

            public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
            {
                if (data == null)
                {
                    throw new ArgumentNullException(nameof(data));
                }
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                // The size of encrypt is always the keysize (in ceiling-bytes)
                int outputSize = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);
                byte[] output = new byte[outputSize];

                if (!TryEncrypt(data, output, padding, out int bytesWritten))
                {
                    Debug.Fail($"TryEncrypt with a preallocated buffer should not fail");
                    throw new CryptographicException();
                }

                Debug.Assert(bytesWritten == outputSize);
                return output;
            }

            public override bool TryEncrypt(ReadOnlySpan<byte> data, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
            {
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                int rsaSize = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);

                if (destination.Length < rsaSize)
                {
                    bytesWritten = 0;
                    return false;
                }

                if (padding == RSAEncryptionPadding.Pkcs1 && data.Length > 0)
                {
                    const int Pkcs1PaddingOverhead = 11;
                    int maxAllowed = rsaSize - Pkcs1PaddingOverhead;

                    if (data.Length > maxAllowed)
                    {
                        throw new CryptographicException(
                            SR.Format(SR.Cryptography_Encryption_MessageTooLong, maxAllowed));
                    }

                    return Interop.AppleCrypto.TryRsaEncrypt(
                        GetKeys().PublicKey,
                        data,
                        destination,
                        padding,
                        out bytesWritten);
                }

                RsaPaddingProcessor processor;

                switch (padding.Mode)
                {
                    case RSAEncryptionPaddingMode.Pkcs1:
                        processor = null;
                        break;
                    case RSAEncryptionPaddingMode.Oaep:
                        processor = RsaPaddingProcessor.OpenProcessor(padding.OaepHashAlgorithm);
                        break;
                    default:
                        throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
                }

                byte[] rented = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> tmp = new Span<byte>(rented, 0, rsaSize);

                try
                {
                    if (processor != null)
                    {
                        processor.PadOaep(data, tmp);
                    }
                    else
                    {
                        Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Pkcs1);
                        RsaPaddingProcessor.PadPkcs1Encryption(data, tmp);
                    }

                    return Interop.AppleCrypto.TryRsaEncryptionPrimitive(
                        GetKeys().PublicKey,
                        tmp,
                        destination,
                        out bytesWritten);
                }
                finally
                {
                    tmp.Clear();
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
            {
                if (data == null)
                {
                    throw new ArgumentNullException(nameof(data));
                }
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                SecKeyPair keys = GetKeys();

                if (keys.PrivateKey == null)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }

                int modulusSizeInBytes = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);

                if (data.Length != modulusSizeInBytes)
                {
                    throw new CryptographicException(SR.Cryptography_RSA_DecryptWrongSize);
                }

                if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
                {
                    return Interop.AppleCrypto.RsaDecrypt(keys.PrivateKey, data, padding);
                }

                int maxOutputSize = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);
                byte[] rented = ArrayPool<byte>.Shared.Rent(maxOutputSize);
                Span<byte> contentsSpan = Span<byte>.Empty;

                try
                {
                    if (!TryDecrypt(keys.PrivateKey, data, rented, padding, out int bytesWritten))
                    {
                        Debug.Fail($"TryDecrypt returned false with a modulus-sized destination");
                        throw new CryptographicException();
                    }

                    contentsSpan = new Span<byte>(rented, 0, bytesWritten);
                    return contentsSpan.ToArray();
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(contentsSpan);
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            public override bool TryDecrypt(ReadOnlySpan<byte> data, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
            {
                if (padding == null)
                {
                    throw new ArgumentNullException(nameof(padding));
                }

                SecKeyPair keys = GetKeys();

                if (keys.PrivateKey == null)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }

                return TryDecrypt(keys.PrivateKey, data, destination, padding, out bytesWritten);
            }

            private bool TryDecrypt(
                SafeSecKeyRefHandle privateKey,
                ReadOnlySpan<byte> data,
                Span<byte> destination,
                RSAEncryptionPadding padding,
                out int bytesWritten)
            {
                Debug.Assert(privateKey != null);

                if (padding.Mode != RSAEncryptionPaddingMode.Pkcs1 &&
                    padding.Mode != RSAEncryptionPaddingMode.Oaep)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);
                }

                int modulusSizeInBytes = RsaPaddingProcessor.BytesRequiredForBitCount(KeySize);

                if (data.Length != modulusSizeInBytes)
                {
                    throw new CryptographicException(SR.Cryptography_RSA_DecryptWrongSize);
                }

                if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1 ||
                    padding == RSAEncryptionPadding.OaepSHA1)
                {
                    return Interop.AppleCrypto.TryRsaDecrypt(privateKey, data, destination, padding, out bytesWritten);
                }

                Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Oaep);
                RsaPaddingProcessor processor = RsaPaddingProcessor.OpenProcessor(padding.OaepHashAlgorithm);

                byte[] rented = ArrayPool<byte>.Shared.Rent(modulusSizeInBytes);
                Span<byte> unpaddedData = Span<byte>.Empty;

                try
                {
                    if (!Interop.AppleCrypto.TryRsaDecryptionPrimitive(privateKey, data, rented, out int paddedSize))
                    {
                        Debug.Fail($"Raw decryption failed with KeySize={KeySize} and a buffer length {rented.Length}");
                        throw new CryptographicException();
                    }

                    Debug.Assert(modulusSizeInBytes == paddedSize);
                    unpaddedData = new Span<byte>(rented, 0, paddedSize);
                    return processor.DepadOaep(unpaddedData, destination, out bytesWritten);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(unpaddedData);
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            private static SafeSecKeyRefHandle ImportKey(RSAParameters parameters)
            {
                bool isPrivateKey = parameters.D != null;
                byte[] pkcs1Blob = isPrivateKey ? parameters.ToPkcs1Blob() : parameters.ToSubjectPublicKeyInfo();

                return Interop.AppleCrypto.ImportEphemeralKey(pkcs1Blob, isPrivateKey);
            }
        }

        private static Exception HashAlgorithmNameNullOrEmpty() =>
            new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");
    }
}
