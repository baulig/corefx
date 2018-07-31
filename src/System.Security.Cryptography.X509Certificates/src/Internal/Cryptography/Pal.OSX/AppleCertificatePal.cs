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
