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
        public static ICertificatePal FromBlob(
            byte[] rawData,
            SafePasswordHandle password,
            X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            X509ContentType contentType = X509Certificate2.GetCertContentType(rawData);

            if (contentType == X509ContentType.Pkcs7)
            {
                // In single mode for a PKCS#7 signed or signed-and-enveloped file we're supposed to return
                // the certificate which signed the PKCS#7 file.
                // 
                // X509Certificate2Collection::Export(X509ContentType.Pkcs7) claims to be a signed PKCS#7,
                // but doesn't emit a signature block. So this is hard to test.
                //
                // TODO(2910): Figure out how to extract the signing certificate, when it's present.
                throw new CryptographicException(SR.Cryptography_X509_PKCS7_NoSigner);
            }


            if (contentType == X509ContentType.Pkcs12)
            {
                if ((keyStorageFlags & X509KeyStorageFlags.EphemeralKeySet) == X509KeyStorageFlags.EphemeralKeySet)
                {
                    throw new PlatformNotSupportedException(SR.Cryptography_X509_NoEphemeralPfx);
                }
                if ((keyStorageFlags & X509KeyStorageFlags.PersistKeySet) == X509KeyStorageFlags.PersistKeySet)
                {
                    throw new PlatformNotSupportedException(SR.Cryptography_NotAvailableOnMobile);
                }
            }
            else
            {
                password = SafePasswordHandle.InvalidHandle;
            }

            SafeSecIdentityHandle identityHandle;
            SafeSecCertificateHandle certHandle = Interop.AppleCrypto.X509ImportCertificate(
                rawData,
                contentType,
                password,
                out identityHandle);

            if (identityHandle.IsInvalid)
            {
                identityHandle.Dispose();
                return new AppleCertificatePal(certHandle);
            }

            if (contentType != X509ContentType.Pkcs12)
            {
                Debug.Fail("Non-PKCS12 import produced an identity handle");

                identityHandle.Dispose();
                certHandle.Dispose();
                throw new CryptographicException();
            }

            Debug.Assert(certHandle.IsInvalid);
            certHandle.Dispose();
            return new AppleCertificatePal(identityHandle);
        }

        public RSA GetRSAPrivateKey()
        {
            throw new NotImplementedException();
        }

        public DSA GetDSAPrivateKey()
        {
            throw new NotImplementedException();
        }

        public ECDsa GetECDsaPrivateKey()
        {
            throw new NotImplementedException();
        }

        public ICertificatePal CopyWithPrivateKey(DSA privateKey)
        {
            throw new NotImplementedException();
        }

        public ICertificatePal CopyWithPrivateKey(ECDsa privateKey)
        {
            throw new NotImplementedException();
        }

        public ICertificatePal CopyWithPrivateKey(RSA privateKey)
        {
            throw new NotImplementedException();
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

        public byte[] Export(X509ContentType contentType, SafePasswordHandle password)
        {
            throw new NotImplementedException();
        }
    }
}
