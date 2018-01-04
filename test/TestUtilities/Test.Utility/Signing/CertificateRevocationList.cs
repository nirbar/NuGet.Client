// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using NuGet.Test.Utility;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace Test.Utility.Signing
{
    public class CertificateRevocationList : IDisposable
    {
        private IntPtr _nativeCrlHandle;

        public StoreName StoreName { get; set; }

        public StoreLocation StoreLocation { get; set; }

        public X509Crl Crl { get; set; }

        public static CertificateRevocationList CreateCrl(TrustedTestCert<TestCertificate> certCA)
        {
            var bcCertCA = DotNetUtilities.FromX509Certificate(certCA.Source.Cert);

            var crlGen = new X509V2CrlGenerator();
            crlGen.SetIssuerDN(bcCertCA.IssuerDN);
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddYears(1));

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                               false,
                               new AuthorityKeyIdentifierStructure(bcCertCA));

            crlGen.AddExtension(X509Extensions.CrlNumber,
                               false,
                               new CrlNumber(BigInteger.One));

            var random = new SecureRandom();
            var issuerPrivateKey = DotNetUtilities.GetKeyPair(certCA.Source.Cert.PrivateKey).Private;
            var signatureFactory = new Asn1SignatureFactory(bcCertCA.SigAlgOid, issuerPrivateKey, random);
            var crl = crlGen.Generate(signatureFactory);

            return new CertificateRevocationList()
            {
                Crl = crl,
                StoreLocation = certCA.StoreLocation,
                StoreName = certCA.StoreName
            };
        }

        public void InstallCrl()
        {
            InstallCrl(Crl.GetEncoded(), StoreLocation, StoreName);
        }

        // Native
        [DllImport("CRYPT32.DLL", SetLastError = true)]
        public static extern IntPtr CertOpenStore(
            int storeProvider,
            int encodingType,
            IntPtr hcryptProv,
            int flags,
            string pvPara);

        [DllImport("CRYPT32", EntryPoint = "CertCloseStore", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CertCloseStore(
            IntPtr storeProvider,
            int flags);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        public static extern IntPtr CertCreateCRLContext(
            uint dwCertEncodingType,
            [In] byte[] pbCrlEncoded,
            [In, Out] uint cbCrlEncoded);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        public static extern bool CertAddCRLContextToStore(
          IntPtr hCertStore,
          IntPtr pCrlContext,
          Disposition dwAddDisposition,
          IntPtr ppStoreContext);

        [DllImport("CRYPT32.DLL", SetLastError = true)]
        public static extern bool CertDeleteCRLFromStore(
          IntPtr pCrlContext);

        public const int X509_ASN_ENCODING = 0x00000001;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;
        public const int ENCODING_TYPE = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

        private static int CERT_STORE_PROV_SYSTEM = 9;
        private static int CERT_SYSTEM_STORE_CURRENT_USER = (1 << 16);
        private static int CERT_SYSTEM_STORE_LOCAL_MACHINE = (2 << 16);

        public enum Disposition : uint
        {
            CERT_STORE_ADD_NEW = 1,
            CERT_STORE_ADD_USE_EXISTING = 2,
            CERT_STORE_ADD_REPLACE_EXISTING = 3,
            CERT_STORE_ADD_ALWAYS = 4,
            CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
            CERT_STORE_ADD_NEWER = 6,
            CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7,
        }

        // Reference - http://apprize.info/c/cookbook_2/10.html
        private void InstallCrl(byte[] crl, StoreLocation storeLocation, StoreName storeName)
        {
            var storeHandle = CertOpenStore(
              CERT_STORE_PROV_SYSTEM,
              ENCODING_TYPE,
              IntPtr.Zero,
              ConvertStoreLocationToNative(storeLocation),
              storeName.ToString()
            );

            var nativeCrlHandle = CertCreateCRLContext(
                X509_ASN_ENCODING,
                crl,
                (uint)crl.Length);

            if (nativeCrlHandle == IntPtr.Zero)
            {
                throw new InvalidDataException("CryptUIWizImport error while installing a CRL - " + Marshal.GetLastWin32Error());
            }

            if (!CertAddCRLContextToStore(
                storeHandle,
                nativeCrlHandle,
                Disposition.CERT_STORE_ADD_ALWAYS,
                IntPtr.Zero))
            {
                throw new InvalidOperationException("CryptUIWizImport error while installing a CRL - " + Marshal.GetLastWin32Error());
            }

            _nativeCrlHandle = nativeCrlHandle;

            if (storeHandle != IntPtr.Zero)
            {
                CertCloseStore(storeHandle, 0);
            }
        }

        private static int ConvertStoreLocationToNative(StoreLocation location)
        {
            if (location == StoreLocation.CurrentUser)
            {
                return CERT_SYSTEM_STORE_CURRENT_USER;
            }
            else
            {
                return CERT_SYSTEM_STORE_LOCAL_MACHINE;
            }
        }

        public void Dispose()
        {
            if (_nativeCrlHandle != IntPtr.Zero)
            {
                CertDeleteCRLFromStore(_nativeCrlHandle)
            }
        }
    }
}
