// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        private static readonly SafeCreateHandle s_nullExportString = new SafeCreateHandle();

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern SafeSecKeyRefHandle AppleCryptoNative_SecKeyImportEphemeral(
            byte[] pbKeyBlob,
            int cbKeyBlob,
            int isPrivateKey,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern ulong AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(SafeSecKeyRefHandle publicKey);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern SafeCFDataHandle AppleCryptoNative_SecKeyExport(
            SafeSecKeyRefHandle pKey,
            out SafeCFErrorHandle pErrorOut);

        internal static int GetSimpleKeySizeInBits(SafeSecKeyRefHandle publicKey)
        {
            ulong keySizeInBytes = AppleCryptoNative_SecKeyGetSimpleKeySizeInBytes(publicKey);

            checked
            {
                return (int)(keySizeInBytes * 8);
            }
        }

        internal static SafeSecKeyRefHandle ImportEphemeralKey(byte[] keyBlob, bool hasPrivateKey)
        {
            Debug.Assert(keyBlob != null);

            SafeSecKeyRefHandle keyHandle;
            SafeCFErrorHandle errorHandle;

            keyHandle = AppleCryptoNative_SecKeyImportEphemeral(
                keyBlob,
                keyBlob.Length,
                hasPrivateKey ? 1 : 0,
                out errorHandle);

            using (errorHandle)
            {
                if (keyHandle.IsInvalid || !errorHandle.IsInvalid)
                {
                    throw CreateExceptionForCFError(errorHandle);
                }
            }

            return keyHandle;
        }

        internal static byte[] SecKeyExport(SafeSecKeyRefHandle key)
        {
            var cfData = AppleCryptoNative_SecKeyExport(key, out var cfError);
            using (cfData)
            using (cfError)
            {
                if (cfData.IsInvalid || !cfError.IsInvalid)
                {
                    throw CreateExceptionForCFError(cfError);
                }

                return CoreFoundation.CFGetData(cfData);
            }
        }
    }
}
