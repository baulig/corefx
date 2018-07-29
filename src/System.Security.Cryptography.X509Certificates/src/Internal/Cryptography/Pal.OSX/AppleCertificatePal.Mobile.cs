// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class AppleCertificatePal
    {
        public RSA GetRSAPrivateKey()
        {
            throw new PlatformNotSupportedException();
        }

        public DSA GetDSAPrivateKey()
        {
            throw new PlatformNotSupportedException();
        }

        public ECDsa GetECDsaPrivateKey()
        {
            throw new PlatformNotSupportedException();
        }

        public ICertificatePal CopyWithPrivateKey(DSA privateKey)
        {
            throw new PlatformNotSupportedException();
        }

        public ICertificatePal CopyWithPrivateKey(ECDsa privateKey)
        {
            throw new PlatformNotSupportedException();
        }

        public ICertificatePal CopyWithPrivateKey(RSA privateKey)
        {
            throw new PlatformNotSupportedException();
        }

        private ICertificatePal CopyWithPrivateKey(SecKeyPair keyPair)
        {
            if (keyPair.PrivateKey == null)
            {
                // Both Windows and Linux/OpenSSL are unaware if they bound a public or private key.
                // Here, we do know.  So throw if we can't do what they asked.
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            // Because SecIdentityRef only has private constructors we need to have the cert and the key
            // in the same keychain.  That almost certainly means we're going to need to add this cert to a
            // keychain, and when a cert that isn't part of a keychain gets added to a keychain then the
            // interior pointer of "what keychain did I come from?" used by SecKeychainItemCopyKeychain gets
            // set. That makes this function have side effects, which is not desired.
            //
            // It also makes reference tracking on temporary keychains broken, since the cert can
            // DangerousRelease a handle it didn't DangerousAddRef on.  And so CopyWithPrivateKey makes
            // a temporary keychain, then deletes it before anyone has a chance to (e.g.) export the
            // new identity as a PKCS#12 blob.
            //
            // Solution: Clone the cert, like we do in Windows.
            SafeSecCertificateHandle tempHandle;

            {
                byte[] export = RawData;
                SafeSecIdentityHandle identityHandle;
                tempHandle = Interop.AppleCrypto.X509ImportCertificate(
                    export,
                    X509ContentType.Cert,
                    SafePasswordHandle.InvalidHandle,
                    out identityHandle);

                Debug.Assert(identityHandle.IsInvalid, "identityHandle should be IsInvalid");
                identityHandle.Dispose();

                Debug.Assert(!tempHandle.IsInvalid, "tempHandle should not be IsInvalid");
            }

            using (tempHandle)
            {
                SafeSecIdentityHandle identityHandle = Interop.AppleCrypto.X509CopyWithPrivateKey(
                    tempHandle,
                    keyPair.PrivateKey);

                AppleCertificatePal newPal = new AppleCertificatePal(identityHandle);
                return newPal;
            }
        }
    }
}
