// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using NuGet.Packaging.Signing;
using Test.Utility.Signing;

namespace NuGet.Packaging.FuncTest
{
    /// <summary>
    /// Used to bootstrap functional tests for signing.
    /// </summary>
    public class SigningTestFixture : IDisposable
    {
        private const string _timestamper = "http://rfc3161.gtm.corp.microsoft.com/TSS/HttpTspServer";
        private const int _trustedCertChainLength = 3;

        private TrustedTestCert<TestCertificate> _trustedTestCert;
        private IList<TrustedTestCert<TestCertificate>> _trustedTestCertChain;
        private IList<ISignatureVerificationProvider> _trustProviders;
        private SigningSpecifications _signingSpecifications;

        public TrustedTestCert<TestCertificate> TrustedTestCertificate
        {
            get
            {
                if (_trustedTestCert == null)
                {
                    var actionGenerator = SigningTestUtility.CertificateModificationGeneratorForCodeSigningEkuCert;

                    // Code Sign EKU needs trust to a root authority
                    // Add the cert to Root CA list in LocalMachine as it does not prompt a dialog
                    // This makes all the associated tests to require admin privilege
                    _trustedTestCert = TestCertificate.Generate(actionGenerator).WithTrust(StoreName.Root, StoreLocation.LocalMachine);
                }

                return _trustedTestCert;
            }
        }

        public TrustedTestCert<TestCertificate> TrustedTestCertificateWithChain
        {
            get
            {
                if (_trustedTestCertChain == null)
                {
                    _trustedTestCertChain = SigningTestUtility.GenerateCertificateChain(_trustedCertChainLength);
                }

                return _trustedTestCertChain.Last();
            }
        }

        public IList<ISignatureVerificationProvider> TrustProviders
        {
            get
            {
                if (_trustProviders == null)
                {
                    _trustProviders = new List<ISignatureVerificationProvider>()
                    {
                        new SignatureTrustAndValidityVerificationProvider(),
                        new IntegrityVerificationProvider()
                    };
                }

                return _trustProviders;
            }
        }

        public SigningSpecifications SigningSpecifications
        {
            get
            {
                if (_signingSpecifications == null)
                {
                    _signingSpecifications = SigningSpecifications.V1;
                }

                return _signingSpecifications;
            }
        }

        public string Timestamper => _timestamper;

        public void Dispose()
        {
            _trustedTestCert?.Dispose();
            (_trustedTestCertChain as List<TrustedTestCert<TestCertificate>>)?.ForEach(c => c.Dispose());
        }
    }
}
