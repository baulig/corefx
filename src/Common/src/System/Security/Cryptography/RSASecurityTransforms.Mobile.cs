using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Apple;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    static partial class RSAImplementation
    {
        partial class RSASecurityTransforms
        {
            public override RSAParameters ExportParameters(bool includePrivateParameters)
            {
                SecKeyPair keys = GetKeys();

                SafeSecKeyRefHandle keyHandle = includePrivateParameters ? keys.PrivateKey : keys.PublicKey;

                if (keyHandle == null)
                {
                    throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
                }

                byte[] exported = Interop.AppleCrypto.SecKeyExport(keyHandle);
                DerSequenceReader keyReader = new DerSequenceReader(exported);
                RSAParameters parameters = new RSAParameters();

                if (keyReader.PeekTag() != (byte)DerSequenceReader.DerTag.Integer)
                {
                    throw new CryptographicException();
                }
                keyReader.ReadPkcs1PublicBlob(ref parameters);

                return parameters;
            }

            public override void ImportParameters(RSAParameters parameters)
            {
                throw new NotImplementedException ();
            }

            public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
            {
                throw new NotImplementedException ();
            }

            public override bool TryEncrypt(ReadOnlySpan<byte> data, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
            {
                throw new NotImplementedException ();
            }

            public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
            {
                throw new NotImplementedException ();
            }

            public override bool TryDecrypt(ReadOnlySpan<byte> data, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
            {
                throw new NotImplementedException ();
            }

            private bool TryDecrypt(
                SafeSecKeyRefHandle privateKey,
                ReadOnlySpan<byte> data,
                Span<byte> destination,
                RSAEncryptionPadding padding,
                out int bytesWritten)
            {
                throw new NotImplementedException ();
            }

            public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                throw new NotImplementedException ();
            }

            public override bool TrySignHash(ReadOnlySpan<byte> hash, Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten)
            {
                throw new NotImplementedException ();
            }

            public override bool VerifyHash(
                byte[] hash,
                byte[] signature,
                HashAlgorithmName hashAlgorithm,
                RSASignaturePadding padding)
            {
                throw new NotImplementedException ();
            }

            public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                throw new NotImplementedException ();
            }
        }
    }
}
