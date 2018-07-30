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
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaGenerateKey(
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaEncryptPkcs(
            SafeSecKeyRefHandle publicKey,
            ref byte pbData,
            int cbData,
            ref byte pbCipherOut,
            ref int cbCipherLen,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaEncryptOaep(
            SafeSecKeyRefHandle publicKey,
            ref byte pbData,
            int cbData,
            ref byte pbCipherOut,
            ref int cbCipherLen,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaDecryptPkcs(
            SafeSecKeyRefHandle publicKey,
            ref byte pbData,
            int cbData,
            ref byte pbPlainOut,
            ref int cbPlainLen,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaDecryptOaep(
            SafeSecKeyRefHandle publicKey,
            ref byte pbData,
            int cbData,
            ref byte pbPlainOut,
            ref int cbPlainLen,
            out int pOSStatus);

        internal static void RsaGenerateKey(
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey)
        {
            SafeSecKeyRefHandle keychainPublic;
            SafeSecKeyRefHandle keychainPrivate;
            int osStatus;

            int result = AppleCryptoNative_RsaGenerateKey(
                keySizeInBits,
                out keychainPublic,
                out keychainPrivate,
                out osStatus);

            if (result == 1)
            {
                pPublicKey = keychainPublic;
                pPrivateKey = keychainPrivate;
                return;
            }

            using (keychainPrivate)
            using (keychainPublic)
            {
                if (result == 0)
                {
                    throw CreateExceptionForOSStatus(osStatus);
                }

                Debug.Fail($"Unexpected result from AppleCryptoNative_RsaGenerateKey: {result}");
                throw new CryptographicException();
            }
        }

        internal static bool TryRsaEncrypt(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            int osStatus, result;
            bytesWritten = destination.Length;
            Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || padding.Mode == RSAEncryptionPaddingMode.Oaep);
            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                result = AppleCryptoNative_RsaEncryptPkcs(
                    publicKey,
                    ref MemoryMarshal.GetReference(source),
                    source.Length,
                    ref MemoryMarshal.GetReference(destination),
                    ref bytesWritten,
                    out osStatus);
            }
            else if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                result = AppleCryptoNative_RsaEncryptOaep(
                    publicKey,
                    ref MemoryMarshal.GetReference(source),
                    source.Length,
                    ref MemoryMarshal.GetReference(destination),
                    ref bytesWritten,
                    out osStatus);
            }
            else
            {
                throw new CryptographicException();
            }

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            if (result == 1)
            {
                return true;
            }

            Debug.Fail($"Unexpected result from AppleCryptoNative_RsaGenerateKey: {result}");
            throw new CryptographicException();
        }

        internal static bool TryRsaDecrypt(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            int osStatus, result;
            bytesWritten = destination.Length;
            Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || padding.Mode == RSAEncryptionPaddingMode.Oaep);
            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                result = AppleCryptoNative_RsaDecryptPkcs(
                    publicKey,
                    ref MemoryMarshal.GetReference(source),
                    source.Length,
                    ref MemoryMarshal.GetReference(destination),
                    ref bytesWritten,
                    out osStatus);
            }
            else if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                result = AppleCryptoNative_RsaDecryptOaep(
                    publicKey,
                    ref MemoryMarshal.GetReference(source),
                    source.Length,
                    ref MemoryMarshal.GetReference(destination),
                    ref bytesWritten,
                    out osStatus);
            }
            else
            {
                throw new CryptographicException();
            }

            if (result == 0)
            {
                throw CreateExceptionForOSStatus(osStatus);
            }

            if (result == 1)
            {
                return true;
            }

            Debug.Fail($"Unexpected result from AppleCryptoNative_RsaGenerateKey: {result}");
            throw new CryptographicException();
        }

        internal static byte[] RsaDecrypt(
            SafeSecKeyRefHandle privateKey,
            byte[] data,
            RSAEncryptionPadding padding)
        {
            throw new NotImplementedException();
        }
    }
}
