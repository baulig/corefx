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
        [DllImport (Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_RsaGenerateKey")]
        private static extern int AppleCryptoNative_RsaGenerateKey (
            int keySizeInBits,
            SafeKeychainHandle keychain,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey,
            out int pOSStatus);

        internal static void RsaGenerateKey (
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey)
        {
            using (SafeTemporaryKeychainHandle tempKeychain = CreateTemporaryKeychain ()) {
                SafeSecKeyRefHandle keychainPublic;
                SafeSecKeyRefHandle keychainPrivate;
                int osStatus;

                int result = AppleCryptoNative_RsaGenerateKey (
                    keySizeInBits,
                    tempKeychain,
                    out keychainPublic,
                    out keychainPrivate,
                    out osStatus);

                if (result == 1) {
                    pPublicKey = keychainPublic;
                    pPrivateKey = keychainPrivate;
                    return;
                }

                using (keychainPrivate)
                using (keychainPublic) {
                    if (result == 0) {
                        throw CreateExceptionForOSStatus (osStatus);
                    }

                    Debug.Fail ($"Unexpected result from AppleCryptoNative_RsaGenerateKey: {result}");
                    throw new CryptographicException ();
                }
            }
        }
    }
}
