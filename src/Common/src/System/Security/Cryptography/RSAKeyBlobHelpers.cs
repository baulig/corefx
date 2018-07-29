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
    internal static class RsaKeyBlobHelpers
    {
        private const string RsaOid = "1.2.840.113549.1.1.1";

        // The PKCS#1 version blob for an RSA key based on 2 primes.
        private static readonly byte[] s_versionNumberBytes = { 0 };

        // The AlgorithmIdentifier structure for RSA contains an explicit NULL, for legacy/compat reasons.
        private static readonly byte[][] s_encodedRsaAlgorithmIdentifier =
            DerEncoder.ConstructSegmentedSequence(
                DerEncoder.SegmentedEncodeOid(new Oid(RsaOid)),
                // DER:NULL (0x05 0x00)
                new byte[][]
                {
                    new byte[] { (byte)DerSequenceReader.DerTag.Null },
                    new byte[] { 0 }, 
                    Array.Empty<byte>(),
                });

        internal static byte[] ToPkcs1Blob(this RSAParameters parameters)
        {
            if (parameters.Exponent == null || parameters.Modulus == null)
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);

            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
                }

                return DerEncoder.ConstructSequence(
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent));
            }

            if (parameters.P == null ||
                parameters.DP == null ||
                parameters.Q == null ||
                parameters.DQ == null ||
                parameters.InverseQ == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            return DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(s_versionNumberBytes),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.D),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.P),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Q),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DP),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DQ),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.InverseQ));
        }

        internal static void ReadPkcs8Blob(this DerSequenceReader reader, ref RSAParameters parameters)
        {
            // OneAsymmetricKey ::= SEQUENCE {
            //   version                   Version,
            //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
            //   privateKey                PrivateKey,
            //   attributes            [0] Attributes OPTIONAL,
            //   ...,
            //   [[2: publicKey        [1] PublicKey OPTIONAL ]],
            //   ...
            // }
            //
            // PrivateKeyInfo ::= OneAsymmetricKey
            //
            // PrivateKey ::= OCTET STRING

            int version = reader.ReadInteger();

            // We understand both version 0 and 1 formats,
            // which are now known as v1 and v2, respectively.
            if (version > 1)
            {
                throw new CryptographicException();
            }

            {
                // Ensure we're reading RSA
                DerSequenceReader algorithm = reader.ReadSequence();

                string algorithmOid = algorithm.ReadOidAsString();

                if (algorithmOid != RsaOid)
                {
                    throw new CryptographicException();
                }
            }

            byte[] privateKeyBytes = reader.ReadOctetString();
            // Because this was an RSA private key, the key format is PKCS#1.
            ReadPkcs1PrivateBlob(privateKeyBytes, ref parameters);

            // We don't care about the rest of the blob here, but it's expected to not exist.
        }

        internal static byte[] ToSubjectPublicKeyInfo(this RSAParameters parameters)
        {
            Debug.Assert(parameters.D == null);

            // SubjectPublicKeyInfo::= SEQUENCE  {
            //    algorithm AlgorithmIdentifier,
            //    subjectPublicKey     BIT STRING  }
            return DerEncoder.ConstructSequence(
                s_encodedRsaAlgorithmIdentifier,
                DerEncoder.SegmentedEncodeBitString(
                    parameters.ToPkcs1Blob()));
        }

        internal static void ReadSubjectPublicKeyInfo(this DerSequenceReader keyInfo, ref RSAParameters parameters)
        {
            // SubjectPublicKeyInfo::= SEQUENCE  {
            //    algorithm AlgorithmIdentifier,
            //    subjectPublicKey     BIT STRING  }
            DerSequenceReader algorithm = keyInfo.ReadSequence();
            string algorithmOid = algorithm.ReadOidAsString();

            if (algorithmOid != RsaOid)
            {
                throw new CryptographicException();
            }

            byte[] subjectPublicKeyBytes = keyInfo.ReadBitString();

            DerSequenceReader subjectPublicKey = new DerSequenceReader(subjectPublicKeyBytes);
            subjectPublicKey.ReadPkcs1PublicBlob(ref parameters);
        }

        internal static void ReadPkcs1PublicBlob(this DerSequenceReader subjectPublicKey, ref RSAParameters parameters)
        {
            parameters.Modulus = KeyBlobHelpers.TrimPaddingByte(subjectPublicKey.ReadIntegerBytes());
            parameters.Exponent = KeyBlobHelpers.TrimPaddingByte(subjectPublicKey.ReadIntegerBytes());

            if (subjectPublicKey.HasData)
                throw new CryptographicException();
        }

        private static void ReadPkcs1PrivateBlob(byte[] privateKeyBytes, ref RSAParameters parameters)
        {
            // RSAPrivateKey::= SEQUENCE {
            //    version Version,
            //    modulus           INTEGER,  --n
            //    publicExponent INTEGER,  --e
            //    privateExponent INTEGER,  --d
            //    prime1 INTEGER,  --p
            //    prime2 INTEGER,  --q
            //    exponent1 INTEGER,  --d mod(p - 1)
            //    exponent2 INTEGER,  --d mod(q - 1)
            //    coefficient INTEGER,  --(inverse of q) mod p
            //    otherPrimeInfos OtherPrimeInfos OPTIONAL
            // }
            DerSequenceReader privateKey = new DerSequenceReader(privateKeyBytes);
            int version = privateKey.ReadInteger();

            if (version != 0)
            {
                throw new CryptographicException();
            }

            parameters.Modulus = KeyBlobHelpers.TrimPaddingByte(privateKey.ReadIntegerBytes());
            parameters.Exponent = KeyBlobHelpers.TrimPaddingByte(privateKey.ReadIntegerBytes());

            int modulusLen = parameters.Modulus.Length;
            // Add one so that odd byte-length values (RSA 1032) get padded correctly.
            int halfModulus = (modulusLen + 1) / 2;

            parameters.D = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), modulusLen);
            parameters.P = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.Q = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DP = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DQ = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.InverseQ = KeyBlobHelpers.PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);

            if (privateKey.HasData)
            {
                throw new CryptographicException();
            }
        }
    }
}
