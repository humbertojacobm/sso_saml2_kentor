using System;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using FluentAssertions;
using Kentor.AuthServices.Tests.Helpers;
using Kentor.AuthServices.Tests.WebSSO;
using Kentor.AuthServices.WebSso;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kentor.AuthServices.Tests.WebSso
{
	[TestClass]
    public class Saml2RedirectBindingSha1Tests
    {
        [TestMethod]
        public void Saml2RedirectBinding_Bind_InformativeMessageOnSigAlgNotFound()
        {
            var actual = CreateAndBindMessageWithSignature();

            var queryParams = HttpUtility.ParseQueryString(actual.Location.Query);
            var query = actual.Location.Query.TrimStart('?');

            var signedData = query.Split(new[] { "&Signature=" }, StringSplitOptions.None)[0];

            var sigalg = queryParams["SigAlg"];
            var signatureDescription = (SignatureDescription)CryptoConfig.CreateFromName(sigalg);

            var hashAlg = signatureDescription.CreateDigest();
            hashAlg.ComputeHash(Encoding.UTF8.GetBytes(signedData));
            var asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(
                SignedXmlHelper.TestCert.PublicKey.Key);

            asymmetricSignatureDeformatter.VerifySignature(
                hashAlg, Convert.FromBase64String(queryParams["Signature"]))
                .Should().BeTrue("signature should be valid");
        }

        private static CommandResult CreateAndBindMessageWithSignature(
            string issuer = "https://idp.example.com",
            string messageName = "SAMLRequest",
            bool includeRelayState = true
            )
        {
            var message = new Saml2MessageImplementation
            {
                XmlData = "<Data/>",
                RelayState = includeRelayState ? "SomeState that needs escaping #%=3" : null,
                DestinationUrl = new Uri("http://host"),
                MessageName = messageName,
                SigningCertificate = SignedXmlHelper.TestCert,
                SigningAlgorithm = AlgorithmConstants.XmlDsigRSASHA256Url
            };

            if(!string.IsNullOrEmpty(issuer))
            {
                message.XmlData = $"<Data><Issuer xmlns=\"{Saml2Namespaces.Saml2Name}\">{issuer}</Issuer></Data>";
            }

            var result = Saml2Binding.Get(Saml2BindingType.HttpRedirect).Bind(message);
            return result;
        }
    }
}
