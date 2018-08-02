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
        private static int AppleCryptoNative_GenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> pbDataHash,
            int cbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_GenerateSignature(
                privateKey, ref MemoryMarshal.GetReference(pbDataHash), cbDataHash, out pSignatureOut, out pOSStatus, out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_GenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ref byte pbDataHash,
            int cbDataHash,
            out SafeCFDataHandle pSignatureOut,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        private static int AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> pbDataHash,
            int cbDataHash,
            PAL_HashAlgorithm hashAlgorithm,
            out SafeCFDataHandle pSignatureOut,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
                privateKey, ref MemoryMarshal.GetReference(pbDataHash), cbDataHash, hashAlgorithm, out pSignatureOut, out pOSStatus, out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
            SafeSecKeyRefHandle privateKey,
            ref byte pbDataHash,
            int cbDataHash,
            PAL_HashAlgorithm hashAlgorithm,
            out SafeCFDataHandle pSignatureOut,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        private static int AppleCryptoNative_VerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> pbDataHash,
            int cbDataHash,
            ReadOnlySpan<byte> pbSignature,
            int cbSignature,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_VerifySignature(
                publicKey,
                ref MemoryMarshal.GetReference(pbDataHash),
                cbDataHash,
                ref MemoryMarshal.GetReference(pbSignature),
                cbSignature,
                out pOSStatus,
                out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_VerifySignature(
            SafeSecKeyRefHandle publicKey,
            ref byte pbDataHash,
            int cbDataHash,
            ref byte pbSignature,
            int cbSignature,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        private static int AppleCryptoNative_VerifySignatureWithHashAlgorithm(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> pbDataHash,
            int cbDataHash,
            ReadOnlySpan<byte> pbSignature,
            int cbSignature,
            PAL_HashAlgorithm hashAlgorithm,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut) =>
            AppleCryptoNative_VerifySignatureWithHashAlgorithm(
                publicKey,
                ref MemoryMarshal.GetReference(pbDataHash),
                cbDataHash,
                ref MemoryMarshal.GetReference(pbSignature),
                cbSignature,
                hashAlgorithm,
                out pOSStatus,
                out pErrorOut);

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_VerifySignatureWithHashAlgorithm(
            SafeSecKeyRefHandle publicKey,
            ref byte pbDataHash,
            int cbDataHash,
            ref byte pbSignature,
            int cbSignature,
            PAL_HashAlgorithm hashAlgorithm,
            out int pOSStatus,
            out SafeCFErrorHandle pErrorOut);

        private delegate int SecKeyTransform(ReadOnlySpan<byte> source, out SafeCFDataHandle outputHandle, out int pOSStatus, out SafeCFErrorHandle errorHandle);

        private static byte[] ExecuteTransform(ReadOnlySpan<byte> source, SecKeyTransform transform)
        {
            const int Success = 1;
            const int kErrorSeeError = -2;
            const int kErrorSeeStatus = -6;

            SafeCFDataHandle data;
            SafeCFErrorHandle error;
            int status;

            int ret = transform(source, out data, out status, out error);

            using (error)
            using (data)
            {
                switch (ret)
                {
                    case Success:
                        return CoreFoundation.CFGetData(data);
                    case kErrorSeeError:
                        throw CreateExceptionForCFError(error);
                    case kErrorSeeStatus:
                        throw CreateExceptionForOSStatus(status);
                    default:
                        Debug.Fail($"transform returned {ret}");
                        throw new CryptographicException();
                }
            }
        }

        private static bool TryExecuteTransform(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten,
            SecKeyTransform transform)
        {
            SafeCFDataHandle outputHandle;
            SafeCFErrorHandle errorHandle;
            int status;

            int ret = transform(source, out outputHandle, out status, out errorHandle);

            using (errorHandle)
            using (outputHandle)
            {
                const int Success = 1;
                const int kErrorSeeError = -2;
                const int kErrorSeeStatus = -6;
                switch (ret)
                {
                    case Success:
                        return CoreFoundation.TryCFWriteData(outputHandle, destination, out bytesWritten);
                    case kErrorSeeError:
                        throw CreateExceptionForCFError(errorHandle);
                    case kErrorSeeStatus:
                        throw CreateExceptionForOSStatus(status);
                    default:
                        Debug.Fail($"transform returned {ret}");
                        throw new CryptographicException();
                }
            }
        }
        
        internal static byte[] GenerateSignature(SafeSecKeyRefHandle privateKey, ReadOnlySpan<byte> dataHash)
        {
            Debug.Assert(privateKey != null, "privateKey != null");

            return ExecuteTransform(
                dataHash,
                (ReadOnlySpan<byte> source, out SafeCFDataHandle signature, out int status, out SafeCFErrorHandle error) =>
                    AppleCryptoNative_GenerateSignature(
                        privateKey,
                        source,
                        source.Length,
                        out signature,
                        out status,
                        out error));
        }

        internal static byte[] GenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> dataHash,
            PAL_HashAlgorithm hashAlgorithm)
        {
            Debug.Assert(privateKey != null, "privateKey != null");
            Debug.Assert(hashAlgorithm != PAL_HashAlgorithm.Unknown, "hashAlgorithm != PAL_HashAlgorithm.Unknown");

            return ExecuteTransform(
                dataHash,
                (ReadOnlySpan<byte> source, out SafeCFDataHandle signature, out int status, out SafeCFErrorHandle error) =>
                    AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
                        privateKey,
                        source,
                        source.Length,
                        hashAlgorithm,
                        out signature,
                        out status,
                        out error));
        }

        internal static bool TryGenerateSignature(
            SafeSecKeyRefHandle privateKey,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            PAL_HashAlgorithm hashAlgorithm,
            out int bytesWritten)
        {
            Debug.Assert(privateKey != null, "privateKey != null");
            Debug.Assert(hashAlgorithm != PAL_HashAlgorithm.Unknown, "hashAlgorithm != PAL_HashAlgorithm.Unknown");

            return TryExecuteTransform(
                source,
                destination,
                out bytesWritten,
                delegate (ReadOnlySpan<byte> innerSource, out SafeCFDataHandle outputHandle, out int status, out SafeCFErrorHandle errorHandle)
                {
                    return AppleCryptoNative_GenerateSignatureWithHashAlgorithm(
                        privateKey, innerSource, innerSource.Length, hashAlgorithm, out outputHandle, out status, out errorHandle);
                });
        }

        internal static bool VerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> dataHash,
            ReadOnlySpan<byte> signature)
        {
            Debug.Assert(publicKey != null, "publicKey != null");

            SafeCFErrorHandle error;
            int status;

            int ret = AppleCryptoNative_VerifySignature(
                publicKey,
                dataHash,
                dataHash.Length,
                signature,
                signature.Length,
                out status,
                out error);

            const int True = 1;
            const int False = 0;
            const int kErrorSeeError = -2;
            const int kErrorSeeStatus = 6;

            using (error)
            {
                switch (ret)
                {
                    case True:
                        return true;
                    case False:
                        return false;
                    case kErrorSeeError:
                        throw CreateExceptionForCFError(error);
                    case kErrorSeeStatus:
                        throw CreateExceptionForOSStatus(status);
                    default:
                        Debug.Fail($"VerifySignature returned {ret}");
                        throw new CryptographicException();
                }
            }
        }

        internal static bool VerifySignature(
            SafeSecKeyRefHandle publicKey,
            ReadOnlySpan<byte> dataHash,
            ReadOnlySpan<byte> signature,
            PAL_HashAlgorithm hashAlgorithm)
        {
            Debug.Assert(publicKey != null, "publicKey != null");
            Debug.Assert(hashAlgorithm != PAL_HashAlgorithm.Unknown);

            SafeCFErrorHandle error;
            int status;

            int ret = AppleCryptoNative_VerifySignatureWithHashAlgorithm(
                publicKey,
                dataHash,
                dataHash.Length,
                signature,
                signature.Length,
                hashAlgorithm,
                out status,
                out error);

            const int True = 1;
            const int False = 0;
            const int kErrorSeeError = -2;
            const int kErrorSeeStatus = 6;

            using (error)
            {
                switch (ret)
                {
                    case True:
                        return true;
                    case False:
                        return false;
                    case kErrorSeeError:
                        throw CreateExceptionForCFError(error);
                    case kErrorSeeStatus:
                        throw CreateExceptionForOSStatus(status);
                    default:
                        Debug.Fail($"VerifySignature returned {ret}");
                        throw new CryptographicException();
                }
            }
        }
    }
}
