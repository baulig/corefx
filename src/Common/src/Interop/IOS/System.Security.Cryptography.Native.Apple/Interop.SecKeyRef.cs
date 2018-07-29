// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        private static readonly SafeCreateHandle s_nullExportString = new SafeCreateHandle();

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern ulong AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(SafeSecKeyRefHandle publicKey);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern SafeCFDataHandle AppleCryptoNative_SecKeyExport(SafeSecKeyRefHandle pKey, out SafeCFErrorHandle pErrorOut);

        internal static int GetSimpleKeySizeInBits(SafeSecKeyRefHandle publicKey)
        {
            ulong keySizeInBytes = AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(publicKey);

            checked
            {
                return (int)(keySizeInBytes * 8);
            }
        }

        internal static DerSequenceReader SecKeyExport(
            SafeSecKeyRefHandle key,
            bool exportPrivate)
        {
            byte[] exportedData;

            var cfData = AppleCryptoNative_SecKeyExport(key, out var cfError);
            using (cfData)
            using (cfError)
            {
                if (cfData.IsInvalid || !cfError.IsInvalid)
                {
                    throw CreateExceptionForCFError(cfError);
                }

                exportedData = CoreFoundation.CFGetData(cfData);
            }

            DerSequenceReader reader = new DerSequenceReader(exportedData);

            if (!exportPrivate)
            {
                return reader;
            }

            byte tag = reader.PeekTag();

            // PKCS#8 defines two structures, PrivateKeyInfo, which starts with an integer,
            // and EncryptedPrivateKey, which starts with an encryption algorithm (DER sequence).
            if (tag == (byte)DerSequenceReader.DerTag.Integer)
            {
                return reader;
            }

            const byte ConstructedSequence =
                DerSequenceReader.ConstructedFlag | (byte)DerSequenceReader.DerTag.Sequence;

            if (tag == ConstructedSequence)
            {
                // return ReadEncryptedPkcs8Blob(ExportPassword, reader);
            }

            Debug.Fail($"Data was neither PrivateKey or EncryptedPrivateKey: {tag:X2}");
            throw new CryptographicException();
        }
    }
}
