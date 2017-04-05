using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using Kentor.AuthServices.Exceptions;
using Kentor.AuthServices.Tests.Helpers;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Kentor.AuthServices.Tests
{
	[TestClass]
    public class XmlHelpersSha1Tests
    {
        public static readonly X509Certificate2 TestCert = new X509Certificate2("Kentor.AuthServices.Tests.pfx");

        [TestMethod]
        public void XmlHelpers_IsSignedBy_ThrowsInformativeMessageOnSha256Signature()
        {
            // With .Net 4.6.2 and above this test will not throw any error because the SHA256 is now built-in
            if ( CryptoConfig.CreateFromName( "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" ) != null ) return;

            var xmlSignedWithSha256 = @"<Assertion ID=""Saml2Response_GetClaims_ThrowsInformativeExceptionForSha256"" IssueInstant=""2015-03-13T20:43:07.330Z"" Version=""2.0"" xmlns=""urn:oasis:names:tc:SAML:2.0:assertion""><Issuer>https://idp.example.com</Issuer><Signature xmlns=""http://www.w3.org/2000/09/xmldsig#""><SignedInfo><CanonicalizationMethod Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /><SignatureMethod Algorithm=""http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"" /><Reference URI=""#Saml2Response_GetClaims_ThrowsInformativeExceptionForSha256""><Transforms><Transform Algorithm=""http://www.w3.org/2000/09/xmldsig#enveloped-signature"" /><Transform Algorithm=""http://www.w3.org/2001/10/xml-exc-c14n#"" /></Transforms><DigestMethod Algorithm=""http://www.w3.org/2001/04/xmlenc#sha256"" /><DigestValue>F+E7u3vqMC07ipvP9AowsMqP7y6CsAC0GeEIxNSwDEI=</DigestValue></Reference></SignedInfo><SignatureValue>GmiXn24Ccnr64TbmDd1/nLM+891z0FtRHSpU8+75uOqbpNK/ZZGrltFf2YZ5u9b9O0HfbFFsZ0i28ocwAZOv2UfxQrCtOGf3ss7Q+t2Zmc6Q/3ES7HIa15I5BbaSdNfpOMlX6N1XXhMprRGy2YWMr5IAIhysFG1A2oHaC3yFiesfUrawN/lXUYuI22Kf4A5bmnIkKijnwX9ewnhRj6569bw+c6q+tVZSHQzI+KMU9KbKN4NsXxAmv6dM1w2qOiX9/CO9LzwEtlhA9yo3sl0uWP8z5GwK9qgOlsF2NdImAQ5f0U4Uv26doFn09W+VExFwNhcXhewQUuPBYBr+XXzdww==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIDIzCCAg+gAwIBAgIQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAMCQxIjAgBgNVBAMTGUtlbnRvci5BdXRoU2VydmljZXMuVGVzdHMwHhcNMTMwOTI1MTMzNTQ0WhcNMzkxMjMxMjM1OTU5WjAkMSIwIAYDVQQDExlLZW50b3IuQXV0aFNlcnZpY2VzLlRlc3RzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVGpfvK9N//MnA5Jo1q2liyPR24406Dp25gv7LB3HK4DWgqsb7xXM6KIV/WVOyCV2g/O1ErBlB+HLhVZ4XUJvbqBbgAJqFO+TZwcCIe8u4nTEXeU660FdtkKClA17sbtMrAGdDfOPwVBHSuavdHeD7jHNI4RUDGKnEW13/0EvnHDilIetwODRxrX/+41R24sJThFbMczByS3OAL2dcIxoAynaGeM90gXsVYow1QhJUy21+cictikb7jW4mW6dvFCBrWIceom9J295DcQIHoxJy5NoZwMir/JV00qs1wDVoN20Ve1DC5ImwcG46XPF7efQ44yLh2j5Yexw+xloA81dwIDAQABo1kwVzBVBgNVHQEETjBMgBAWIahoZhXVUogbAqkS7zwfoSYwJDEiMCAGA1UEAxMZS2VudG9yLkF1dGhTZXJ2aWNlcy5UZXN0c4IQg7mOjTf994NAVxZu4jqXpzAJBgUrDgMCHQUAA4IBAQA2aGzmuKw4AYXWMhrGj5+i8vyAoifUn1QVOFsUukEA77CrqhqqaWFoeagfJp/45vlvrfrEwtF0QcWfmO9w1VvHwm7sk1G/cdYyJ71sU+llDsdPZm7LxQvWZYkK+xELcinQpSwt4ExavS+jLcHoOYHYwIZMBn3U8wZw7Kq29oGnoFQz7HLCEl/G9i3QRyvFITNlWTjoScaqMjHTzq6HCMaRsL09DLcY3KB+cedfpC0/MBlzaxZv0DctTulyaDfM9DCYOyokGN/rQ6qkAR0DDm8fVwknbJY7kURXNGoUetulTb5ow8BvD1gncOaYHSD0kbHZG+bLsUZDFatEr2KW8jbG</X509Certificate></X509Data></KeyInfo></Signature><Subject><NameID>SomeUser</NameID><SubjectConfirmation Method=""urn:oasis:names:tc:SAML:2.0:cm:bearer"" /></Subject><Conditions NotOnOrAfter=""2100-01-01T05:00:00.000Z"" /></Assertion>";

            var xmlDoc = XmlHelpers.FromString(xmlSignedWithSha256);

            xmlDoc.DocumentElement.Invoking(
                x => x.IsSignedBy(SignedXmlHelper.TestCertSignOnly))
                .ShouldThrow<InvalidSignatureException>()
                .And.Message.Should().Be("SHA256 signatures require the algorithm to be registered at the process level. Upgrade to .Net 4.6.2 or call Kentor.AuthServices.Configuration.Options.GlobalEnableSha256XmlSignatures() on startup to register.");
        }
    }
}