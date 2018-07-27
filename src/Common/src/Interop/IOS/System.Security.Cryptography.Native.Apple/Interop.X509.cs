// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_X509ImportCertificate(
            byte[] pbKeyBlob,
            int cbKeyBlob,
            X509ContentType contentType,
            SafeCreateHandle cfPfxPassphrase,
            out SafeSecCertificateHandle pCertOut,
            out SafeSecIdentityHandle pPrivateKeyOut,
            out int pOSStatus);

        [DllImport (Libraries.AppleCryptoNative, EntryPoint = "AppleCryptoNative_X509GetContentType")]
        internal static extern X509ContentType X509GetContentType (byte[] pbData, int cbData);

        internal static SafeSecCertificateHandle X509ImportCertificate (
            byte[] bytes,
            X509ContentType contentType,
            SafePasswordHandle importPassword,
            out SafeSecIdentityHandle identityHandle)
        {
            SafeSecCertificateHandle certHandle;
            int osStatus;
            int ret;

            SafeCreateHandle cfPassphrase = s_nullExportString;
            bool releasePassword = false;

            try {
                if (!importPassword.IsInvalid) {
                    importPassword.DangerousAddRef (ref releasePassword);
                    IntPtr passwordHandle = importPassword.DangerousGetHandle ();

                    if (passwordHandle != IntPtr.Zero) {
                        cfPassphrase = CoreFoundation.CFStringCreateWithCString (passwordHandle);
                    }
                }

                ret = AppleCryptoNative_X509ImportCertificate (
                    bytes,
                    bytes.Length,
                    contentType,
                    cfPassphrase,
                    out certHandle,
                    out identityHandle,
                    out osStatus);
            } finally {
                if (releasePassword) {
                    importPassword.DangerousRelease ();
                }

                if (cfPassphrase != s_nullExportString) {
                    cfPassphrase.Dispose ();
                }
            }

            if (ret == 1) {
                return certHandle;
            }

            certHandle.Dispose ();
            identityHandle.Dispose ();

            const int SeeOSStatus = 0;
            const int ImportReturnedEmpty = -2;
            const int ImportReturnedNull = -3;

            switch (ret) {
            case SeeOSStatus:
                throw CreateExceptionForOSStatus (osStatus);
            case ImportReturnedNull:
            case ImportReturnedEmpty:
                throw new CryptographicException ();
            default:
                Debug.Fail ($"Unexpected return value {ret}");
                throw new CryptographicException ();
            }
        }
    }
}

namespace System.Security.Cryptography.X509Certificates
{
    internal sealed partial class SafeSecIdentityHandle : SafeHandle
    {
        internal SafeSecIdentityHandle ()
            : base (IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle ()
        {
            Interop.CoreFoundation.CFRelease (handle);
            SetHandle (IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }

    internal sealed partial class SafeSecCertificateHandle : SafeHandle
    {
        internal SafeSecCertificateHandle ()
            : base (IntPtr.Zero, ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle ()
        {
            Interop.CoreFoundation.CFRelease (handle);
            SetHandle (IntPtr.Zero);
            return true;
        }

        public override bool IsInvalid => handle == IntPtr.Zero;
    }
}
