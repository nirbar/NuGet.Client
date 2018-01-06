// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
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
        public X509Crl Crl { get; set; }

        public X509Certificate2 IssuerCert { get; private set; }

        public string CrlLocalPath { get; private set; }

#if IS_DESKTOP
        public static CertificateRevocationList CreateCrl(X509Certificate2 issuerCert, string crlLocalUri)
        {
            var bcIssuerCert = DotNetUtilities.FromX509Certificate(issuerCert);
            var crlGen = new X509V2CrlGenerator();
            var version = BigInteger.One;
            crlGen.SetIssuerDN(bcIssuerCert.SubjectDN);
            crlGen.SetThisUpdate(DateTime.Now);
            crlGen.SetNextUpdate(DateTime.Now.AddYears(1));

            crlGen.AddExtension(X509Extensions.AuthorityKeyIdentifier,
                               false,
                               new AuthorityKeyIdentifierStructure(bcIssuerCert));

            crlGen.AddExtension(X509Extensions.CrlNumber,
                               false,
                               new CrlNumber(version));

            var random = new SecureRandom();
            var issuerPrivateKey = DotNetUtilities.GetKeyPair(issuerCert.PrivateKey).Private;
            var signatureFactory = new Asn1SignatureFactory(bcIssuerCert.SigAlgOid, issuerPrivateKey, random);
            var crl = crlGen.Generate(signatureFactory);

            return new CertificateRevocationList()
            {
                Crl = crl,
                IssuerCert = issuerCert,
                CrlLocalPath = Path.Combine(crlLocalUri, $"{issuerCert.Subject}.crl")
            };
        }

        private void ExportCrl(string filePath)
        {
            var pemWriter = new PemWriter(new StreamWriter(File.Open(filePath, FileMode.Create)));
            pemWriter.WriteObject(Crl);
            pemWriter.Writer.Flush();
            pemWriter.Writer.Close();

            CrlLocalPath = filePath;
        }

        public void ExportCrl()
        {
            ExportCrl(CrlLocalPath);
        }
#else
        public static CertificateRevocationList CreateCrl(X509Certificate2 certCA, string crlLocalUri)
        {
            throw new NotImplementedException();
        }

        public void ExportCrl(string filePath)
        { 
            throw new NotImplementedException();
        }

         public void ExportCrl()
        { 
            throw new NotImplementedException();
        }
#endif

        public void Dispose()
        {
            if (!string.IsNullOrEmpty(CrlLocalPath) && File.Exists(CrlLocalPath))
            {
                File.Delete(CrlLocalPath);
            }
        }
    }
}
