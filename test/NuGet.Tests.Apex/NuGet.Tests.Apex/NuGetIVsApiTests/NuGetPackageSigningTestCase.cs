// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Test.Apex.VisualStudio.Solution;
using NuGet.StaFact;
using NuGet.Test.Utility;
using Test.Utility.Signing;
using Xunit;

namespace NuGet.Tests.Apex
{
    // TODO: Fix all tests to do what they are supposed to
    public class NuGetPackageSigningTestCase : SharedVisualStudioHostTestClass, IClassFixture<VisualStudioHostFixtureFactory>
    {
        private TrustedTestCert<TestCertificate> _trustedTestCert;

        public NuGetPackageSigningTestCase(VisualStudioHostFixtureFactory visualStudioHostFixtureFactory)
            : base(visualStudioHostFixtureFactory)
        {
            var actionGenerator = SigningTestUtility.CertificateModificationGeneratorForCodeSigningEkuCert;

            // Code Sign EKU needs trust to a root authority
            // Add the cert to Root CA list in LocalMachine as it does not prompt a dialog
            // This makes all the associated tests to require admin privilege
            _trustedTestCert = TestCertificate.Generate(actionGenerator).WithTrust(StoreName.Root, StoreLocation.LocalMachine);
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void InstallSignedPackageFromPMCAsync(ProjectTemplate projectTemplate)
        {
            var packageName = "TestPackage";
            var packageVersion = "1.0.0";

            var package = Utils.CreatePackage(packageName, packageVersion);

            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.Name);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName, packageVersion));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion));
                project.Build();
                Assert.True(VisualStudio.HasNoErrorsInErrorList());
                Assert.True(VisualStudio.HasNoErrorsInOutputWindows());

                nugetConsole.Clear();
                solutionService.Save();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void UninstallSignedPackageFromPMCAsync(ProjectTemplate projectTemplate)
        {
            var packageName = "TestPackage";
            var packageVersion = "1.0.0";

            var package = Utils.CreatePackage(packageName, packageVersion);

            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.Name);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName, packageVersion));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion));
                project.Build();

                Assert.True(nugetConsole.UninstallPackageFromPMC(packageName));
                Assert.False(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion));

                solutionService.Save();
                project.Build();
                Assert.True(VisualStudio.HasNoErrorsInErrorList());
                Assert.True(VisualStudio.HasNoErrorsInOutputWindows());

                nugetConsole.Clear();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void UpdateUnsignedPackageToSignedVersionFromPMCAsync(ProjectTemplate projectTemplate)
        {
            var packageName = "TestPackage";
            var packageVersion1 = "1.0.0";
            var packageVersion2 = "2.0.0";

            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                Utils.CreatePackageInSource(pathContext.PackageSource, packageName, packageVersion1);

                var package = Utils.CreatePackage(packageName, packageVersion2);
                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.UniqueName);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName, packageVersion1));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion1));
                project.Build();

                Assert.True(nugetConsole.UpdatePackageFromPMC(packageName, packageVersion2));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion2));
                Assert.False(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion1));
                project.Build();

                Assert.True(VisualStudio.HasNoErrorsInErrorList());
                Assert.True(VisualStudio.HasNoErrorsInOutputWindows());

                nugetConsole.Clear();
                solutionService.Save();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void InstallSignedAndUnsignedPackagesFromPMCAsync(ProjectTemplate projectTemplate)
        {
            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                var packageName1 = "TestPackage1";
                var packageVersion1 = "1.0.0";
                Utils.CreatePackageInSource(pathContext.PackageSource, packageName1, packageVersion1);

                var packageName2 = "TestPackage2";
                var packageVersion2 = "1.2.3";
                var package = Utils.CreatePackage(packageName2, packageVersion2);
                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.Name);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName1, packageVersion1));
                Assert.True(nugetConsole.InstallPackageFromPMC(packageName2, packageVersion2));
                project.Build();
                Assert.True(VisualStudio.HasNoErrorsInErrorList());
                Assert.True(VisualStudio.HasNoErrorsInOutputWindows());
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName1, packageVersion1));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName2, packageVersion2));

                nugetConsole.Clear();
                solutionService.Save();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void UninstallSignedAndUnsignedPackagesFromPMCAsync(ProjectTemplate projectTemplate)
        {
            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                var packageName1 = "TestPackage1";
                var packageVersion1 = "1.0.0";
                Utils.CreatePackageInSource(pathContext.PackageSource, packageName1, packageVersion1);

                var packageName2 = "TestPackage2";
                var packageVersion2 = "1.2.3";
                var package = Utils.CreatePackage(packageName2, packageVersion2);
                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.Name);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName1, packageVersion1));
                Assert.True(nugetConsole.InstallPackageFromPMC(packageName2, packageVersion2));
                project.Build();
                Assert.True(VisualStudio.HasNoErrorsInErrorList());
                Assert.True(VisualStudio.HasNoErrorsInOutputWindows());
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName1, packageVersion1));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName2, packageVersion2));

                Assert.True(nugetConsole.UninstallPackageFromPMC(packageName1));
                Assert.True(nugetConsole.UninstallPackageFromPMC(packageName2));
                project.Build();
                solutionService.SaveAll();

                Assert.False(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName1, packageVersion1));
                Assert.False(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName2, packageVersion2));

                nugetConsole.Clear();
                solutionService.Save();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public async void DowngradeSignedPackageToUnsignedVersionFromPMCAsync(ProjectTemplate projectTemplate)
        {
            using (var pathContext = new SimpleTestPathContext())
            using (var testCertificate = new X509Certificate2(_trustedTestCert.Source.Cert))
            {
                // Arrange
                EnsureVisualStudioHost();
                var solutionService = VisualStudio.Get<SolutionService>();

                solutionService.CreateEmptySolution("TestSolution", pathContext.SolutionRoot);
                var project = solutionService.AddProject(ProjectLanguage.CSharp, projectTemplate, ProjectTargetFramework.V46, "TestProject");
                project.Build();

                var packageName = "TestPackage";
                var packageVersion1 = "1.0.0";
                var packageVersion2 = "2.0.0";
                var package = Utils.CreatePackage(packageName, packageVersion1);
                await SignedArchiveTestUtility.CreateSignedPackageAsync(testCertificate, package, pathContext.PackageSource);

                Utils.CreatePackageInSource(pathContext.PackageSource, packageName, packageVersion2);

                var nugetTestService = GetNuGetTestService();
                Assert.True(nugetTestService.EnsurePackageManagerConsoleIsOpen());

                var nugetConsole = nugetTestService.GetPackageManagerConsole(project.UniqueName);

                Assert.True(nugetConsole.InstallPackageFromPMC(packageName, packageVersion2));
                project.Build();
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion2));

                Assert.True(nugetConsole.UpdatePackageFromPMC(packageName, packageVersion1));
                project.Build();

                Assert.False(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion2));
                Assert.True(Utils.IsPackageInstalled(nugetConsole, project.FullPath, packageName, packageVersion1));

                nugetConsole.Clear();
                solutionService.Save();
            }
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public void InstallSignedUntrustedPackageFromPMC(ProjectTemplate projectTemplate)
        {
            //TODO
        }

        [NuGetWpfTheory]
        [InlineData(ProjectTemplate.ClassLibrary)]
        [InlineData(ProjectTemplate.NetCoreConsoleApp)]
        [InlineData(ProjectTemplate.NetStandardClassLib)]
        public void InstallSignedTamperedPackageFromPMCAndFail(ProjectTemplate projectTemplate)
        {
            //TODO
        }
    }
}