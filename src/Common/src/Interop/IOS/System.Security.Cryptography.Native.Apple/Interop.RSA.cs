// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
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
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_RsaGenerateKey(
            int keySizeInBits,
            out SafeSecKeyRefHandle pPublicKey,
            out SafeSecKeyRefHandle pPrivateKey,
            out int pOSStatus);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyEncrypt(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ref byte pbData,
            int cbData,
            ref byte pbCipherOut,
            ref int cbCipherLen,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyDecrypt(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ref byte pbData,
            int cbData,
            ref byte pbPlainOut,
            ref int cbPlainLen,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeySign(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ref byte pbData,
            int cbData,
            ref byte pbSignatureOut,
            ref int cbSignatureLen,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyVerify(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ref byte pbData,
            int cbData,
            ref byte pbSignature,
            ref int cbSignatureLen,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

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

        private delegate int SecKeyMobileTransform(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ref byte pbData,
            int cbData,
            ref byte pbPlainOut,
            ref int cbPlainLen,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        private static bool TryExecuteTransform(
            SafeSecKeyRefHandle key,
            PAL_PaddingMode padding,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten,
            SecKeyMobileTransform transform)
        {
            Console.Error.WriteLine ($"TRY EXECUTE TRANSFORM: {padding}");
            int osStatus;
            bytesWritten = destination.Length;
            SafeCFErrorHandle error;
            int ret = transform (
                    key,
                    padding,
                    ref MemoryMarshal.GetReference(source),
                    source.Length,
                    ref MemoryMarshal.GetReference(destination),
                    ref bytesWritten,
                    out osStatus,
                    out error);

            const int True = 1;
            const int False = 0;
            const int kErrorSeeError = -2;
            const int kErrorMaybeTooSmall = -5;

            if (ret == kErrorMaybeTooSmall)
            {
                int rsaSize = GetSimpleKeySizeInBits(key);
                byte[] rented = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> tmp = new Span<byte>(rented, 0, rsaSize);

                try
                {
                    bytesWritten = rsaSize;
                    ret = transform (
                            key,
                            padding,
                            ref MemoryMarshal.GetReference(source),
                            source.Length,
                            ref MemoryMarshal.GetReference(tmp),
                            ref bytesWritten,
                            out osStatus,
                            out error);
                    if (ret == True)
                    {
                        bytesWritten = 0;
                        return false;
                    }
                }
                finally
                {
                    tmp.Clear();
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            switch (ret)
            {
                case True:
                    return true;
                case kErrorSeeError:
                    throw CreateExceptionForOSStatus(osStatus);
                default:
                        Debug.Fail($"Native RSA transform returned {ret}");
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
            Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || padding.Mode == RSAEncryptionPaddingMode.Oaep);
            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                return TryExecuteTransform(
                        publicKey, PAL_PaddingMode.Pkcs1, source, destination, out bytesWritten, AppleCryptoNative_SecKeyEncrypt);
            }
            else if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                return TryExecuteTransform(
                        publicKey, PAL_PaddingMode.Oaep, source, destination, out bytesWritten, AppleCryptoNative_SecKeyEncrypt);
            }
            else
            {
                throw new CryptographicException();
            }
        }

        internal static bool TryRsaDecrypt(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            Debug.Assert(padding.Mode == RSAEncryptionPaddingMode.Pkcs1 || padding.Mode == RSAEncryptionPaddingMode.Oaep);
            if (padding.Mode == RSAEncryptionPaddingMode.Pkcs1)
            {
                return TryExecuteTransform(
                        privateKey, PAL_PaddingMode.Pkcs1, source, destination, out bytesWritten, AppleCryptoNative_SecKeyDecrypt);
            }
            else if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                return TryExecuteTransform(
                        privateKey, PAL_PaddingMode.Oaep, source, destination, out bytesWritten, AppleCryptoNative_SecKeyDecrypt);
            }
            else
            {
                throw new CryptographicException();
            }
        }

        internal static byte[] RsaDecrypt(
            SafeSecKeyRefHandle privateKey,
            byte[] data,
            RSAEncryptionPadding padding)
        {
            var output = new byte[data.Length];
            int bytesWritten;
            if (!TryRsaDecrypt(privateKey, data, output, padding, out bytesWritten))
            {
                throw new CryptographicException();
            }
            if (bytesWritten == output.Length)
            {
                return output;
            }
            var array = new byte[bytesWritten];
            Buffer.BlockCopy(output, 0, array, 0, bytesWritten);
            return array;
        }
        
        internal static bool TryRsaDecryptionPrimitive(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            return TryExecuteTransform(privateKey, PAL_PaddingMode.None, source, destination, out bytesWritten, AppleCryptoNative_SecKeyDecrypt);
        }

        internal static bool TryRsaEncryptionPrimitive(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            return TryExecuteTransform(publicKey, PAL_PaddingMode.None, source, destination, out bytesWritten, AppleCryptoNative_SecKeyEncrypt);
        }

        internal static bool TryRsaSignaturePrimitive(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            return TryExecuteTransform(privateKey, PAL_PaddingMode.None, source, destination, out bytesWritten, AppleCryptoNative_SecKeySign);
        }

        internal static bool TryRsaVerificationPrimitive(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            return TryExecuteTransform(publicKey, PAL_PaddingMode.None, source, destination, out bytesWritten, AppleCryptoNative_SecKeyVerify);
        }
    }
}
