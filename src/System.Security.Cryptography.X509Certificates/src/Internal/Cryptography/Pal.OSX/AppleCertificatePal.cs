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
    internal sealed partial class AppleCertificatePal : ICertificatePal
    {
        private SafeSecIdentityHandle _identityHandle;
        private SafeSecCertificateHandle _certHandle;
        private CertificateData _certData;
        private bool _readCertData;

        public static ICertificatePal FromHandle(IntPtr handle)
        {
            return FromHandle(handle, true);
        }

        internal static ICertificatePal FromHandle(IntPtr handle, bool throwOnFail)
        {
            if (handle == IntPtr.Zero)
                throw new ArgumentException(SR.Arg_InvalidHandle, nameof(handle));

            SafeSecCertificateHandle certHandle;
            SafeSecIdentityHandle identityHandle;

            if (Interop.AppleCrypto.X509DemuxAndRetainHandle(handle, out certHandle, out identityHandle))
            {
                Debug.Assert(
                    certHandle.IsInvalid != identityHandle.IsInvalid,
                    $"certHandle.IsInvalid ({certHandle.IsInvalid}) should differ from identityHandle.IsInvalid ({identityHandle.IsInvalid})");

                if (certHandle.IsInvalid)
                {
                    certHandle.Dispose();
                    return new AppleCertificatePal(identityHandle);
                }

                identityHandle.Dispose();
                return new AppleCertificatePal(certHandle);
            }

            certHandle.Dispose();
            identityHandle.Dispose();

            if (throwOnFail)
            {
                throw new ArgumentException(SR.Arg_InvalidHandle, nameof(handle));
            }

            return null;
        }

        public static ICertificatePal FromOtherCert(X509Certificate cert)
        {
            Debug.Assert(cert.Pal != null);

            ICertificatePal pal = FromHandle(cert.Handle);
            GC.KeepAlive(cert); // ensure cert's safe handle isn't finalized while raw handle is in use
            return pal;
        }

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

            bool exportable = true;

            SafeKeychainHandle keychain;

            if (contentType == X509ContentType.Pkcs12)
            {
                if ((keyStorageFlags & X509KeyStorageFlags.EphemeralKeySet) == X509KeyStorageFlags.EphemeralKeySet)
                {
                    throw new PlatformNotSupportedException(SR.Cryptography_X509_NoEphemeralPfx);
                }

                exportable = (keyStorageFlags & X509KeyStorageFlags.Exportable) == X509KeyStorageFlags.Exportable;

                bool persist =
                    (keyStorageFlags & X509KeyStorageFlags.PersistKeySet) == X509KeyStorageFlags.PersistKeySet;

                keychain = persist
                    ? Interop.AppleCrypto.SecKeychainCopyDefault()
                    : Interop.AppleCrypto.CreateTemporaryKeychain();
            }
            else
            {
                keychain = SafeTemporaryKeychainHandle.InvalidHandle;
                password = SafePasswordHandle.InvalidHandle;
            }

            using (keychain)
            {
                SafeSecIdentityHandle identityHandle;
                SafeSecCertificateHandle certHandle = Interop.AppleCrypto.X509ImportCertificate(
                    rawData,
                    contentType,
                    password,
                    keychain,
                    exportable,
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
        }

        public static ICertificatePal FromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
        {
            Debug.Assert(password != null);

            byte[] fileBytes = System.IO.File.ReadAllBytes(fileName);
            return FromBlob(fileBytes, password, keyStorageFlags);
        }

        internal AppleCertificatePal(SafeSecCertificateHandle certHandle)
        {
            Debug.Assert(!certHandle.IsInvalid);

            _certHandle = certHandle;
        }

        internal AppleCertificatePal(SafeSecIdentityHandle identityHandle)
        {
            Debug.Assert(!identityHandle.IsInvalid);

            _identityHandle = identityHandle;
            _certHandle = Interop.AppleCrypto.X509GetCertFromIdentity(identityHandle);
        }

        public void Dispose()
        {
            _certHandle?.Dispose();
            _identityHandle?.Dispose();

            _certHandle = null;
            _identityHandle = null;
        }

        internal SafeSecCertificateHandle CertificateHandle => _certHandle;
        internal SafeSecIdentityHandle IdentityHandle => _identityHandle;

        public bool HasPrivateKey => !(_identityHandle?.IsInvalid ?? true);

        public IntPtr Handle
        {
            get
            {
                if (HasPrivateKey)
                {
                    return _identityHandle.DangerousGetHandle();
                }

                return _certHandle?.DangerousGetHandle() ?? IntPtr.Zero;
            }
        }


        public string Issuer => IssuerName.Name;

        public string Subject => SubjectName.Name;

        public string LegacyIssuer => IssuerName.Decode(X500DistinguishedNameFlags.None);

        public string LegacySubject => SubjectName.Decode(X500DistinguishedNameFlags.None);

        public string KeyAlgorithm
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKeyAlgorithm.AlgorithmId;
            }
        }

        public byte[] KeyAlgorithmParameters
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKeyAlgorithm.Parameters;
            }
        }

        public byte[] PublicKeyValue
        {
            get
            {
                EnsureCertData();
                return _certData.PublicKey;
            }
        }

        public byte[] SerialNumber
        {
            get
            {
                EnsureCertData();
                return _certData.SerialNumber;
            }
        }

        public string SignatureAlgorithm
        {
            get
            {
                EnsureCertData();
                return _certData.SignatureAlgorithm.AlgorithmId;
            }
        }

        public string FriendlyName
        {
            get { return ""; }
            set
            {
                throw new PlatformNotSupportedException(
                    SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, nameof(FriendlyName)));
            }
        }

        public int Version
        {
            get
            {
                EnsureCertData();
                return _certData.Version + 1;
            }
        }

        public X500DistinguishedName SubjectName
        {
            get
            {
                EnsureCertData();
                return _certData.Subject;
            }
        }

        public X500DistinguishedName IssuerName
        {
            get
            {
                EnsureCertData();
                return _certData.Issuer;
            }
        }

        public IEnumerable<X509Extension> Extensions {
            get
            {
                EnsureCertData();
                return _certData.Extensions;
            }
        }

        public byte[] RawData
        {
            get
            {
                EnsureCertData();
                return _certData.RawData;
            }
        }

        public DateTime NotAfter
        {
            get
            {
                EnsureCertData();
                return _certData.NotAfter.ToLocalTime();
            }
        }

        public DateTime NotBefore
        {
            get
            {
                EnsureCertData();
                return _certData.NotBefore.ToLocalTime();
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Security", "CA5350",
            Justification = "SHA1 is required for Compat")]
        public byte[] Thumbprint
        {
            get
            {
                EnsureCertData();

                using (SHA1 hash = SHA1.Create())
                {
                    return hash.ComputeHash(_certData.RawData);
                }
            }
        }

        public bool Archived
        {
            get { return false; }
            set
            {
                throw new PlatformNotSupportedException(
                    SR.Format(SR.Cryptography_Unix_X509_PropertyNotSettable, nameof(Archived)));
            }
        }

        public byte[] SubjectPublicKeyInfo
        {
            get
            {
                EnsureCertData();

                return _certData.SubjectPublicKeyInfo;
            }
        }

        public string GetNameInfo(X509NameType nameType, bool forIssuer)
        {
            EnsureCertData();
            return _certData.GetNameInfo(nameType, forIssuer);
        }

        public void AppendPrivateKeyInfo(StringBuilder sb)
        {
            if (!HasPrivateKey)
            {
                return;
            }

            // There's nothing really to say about the key, just acknowledge there is one.
            sb.AppendLine();
            sb.AppendLine();
            sb.AppendLine("[Private Key]");
        }

        public byte[] Export(X509ContentType contentType, SafePasswordHandle password)
        {
            using (IExportPal storePal = StorePal.FromCertificate(this))
            {
                return storePal.Export(contentType, password);
            }
        }

        private void EnsureCertData()
        {
            if (_readCertData)
                return;

            Debug.Assert(!_certHandle.IsInvalid);
            _certData = new CertificateData(Interop.AppleCrypto.X509GetRawData(_certHandle));
            _readCertData = true;
        }

    }
}
