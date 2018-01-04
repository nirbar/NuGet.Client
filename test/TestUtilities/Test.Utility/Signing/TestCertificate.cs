// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.X509;

namespace Test.Utility.Signing
{
    /// <summary>
    /// Test certificate pair.
    /// </summary>
    public class TestCertificate
    {
        /// <summary>
        /// Cert
        /// </summary>
        public X509Certificate2 Cert { get; set; }

        /// <summary>
        /// Public cert.
        /// </summary>
        public X509Certificate2 PublicCert => SigningTestUtility.GetPublicCert(Cert);

        /// <summary>
        /// Public cert.
        /// </summary>
        public X509Certificate2 PublicCertWithPrivateKey => SigningTestUtility.GetPublicCertWithPrivateKey(Cert);

        /// <summary>
        /// Certificate Revocation List associated with a certificate.
        /// This will be null if the certificate was not created as a CA certificate.
        /// </summary>
        public CertificateRevocationList Crl { get; set; }

        /// <summary>
        /// Trust the PublicCert cert for the life of the object.
        /// </summary>
        /// <remarks>Dispose of the object returned!</remarks>
        public TrustedTestCert<TestCertificate> WithTrust(StoreName storeName = StoreName.TrustedPeople, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            return new TrustedTestCert<TestCertificate>(this, e => PublicCert, storeName, storeLocation);
        }

        /// <summary>
        /// Trust the PublicCert cert for the life of the object.
        /// </summary>
        /// <remarks>Dispose of the object returned!</remarks>
        public TrustedTestCert<TestCertificate> WithPrivateKeyAndTrust(StoreName storeName = StoreName.TrustedPeople, StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            return new TrustedTestCert<TestCertificate>(this, e => PublicCertWithPrivateKey, storeName, storeLocation);
        }

        public static TestCertificate Generate(Action<X509V3CertificateGenerator> modifyGenerator = null, X509Certificate2 issuer = null, bool isCA = false)
        {
            var certName = "NuGetTest " + Guid.NewGuid().ToString();
            var cert = SigningTestUtility.GenerateCertificate(certName, modifyGenerator, issuer: issuer, isCA: isCA);
            CertificateRevocationList crl = null;

            if (isCA)
            {
                crl = CertificateRevocationList.CreateCrl(cert);
            }

            var testCertificate = new TestCertificate
            {
                Cert = cert,
                Crl = crl
            };

            return testCertificate;
        }
    }
}
