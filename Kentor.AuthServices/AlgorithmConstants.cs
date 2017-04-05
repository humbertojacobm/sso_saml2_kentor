using System.Diagnostics.CodeAnalysis;

namespace Kentor.AuthServices
{
    /// <summary>
    /// Mirrors values from SignedXml, some of which only added in .Net 4.6.2 
    /// and thus not available when targetting .Net 4.5
    /// </summary>
    public static class AlgorithmConstants
    {
#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSASHA" )]
        public const string XmlDsigRSASHA1Url = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA" )]
        public const string XmlDsigSHA1Url = "http://www.w3.org/2000/09/xmldsig#sha1";

        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSASHA" )]
        public const string XmlDsigRSASHA256Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "SHA" )]
        public const string XmlDsigSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";

        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSASHA" )]
        public const string XmlDsigRSASHA384Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

        [SuppressMessage( "Microsoft.Naming", "CA1709:IdentifiersShouldBeCasedCorrectly", MessageId = "RSASHA" )]
        public const string XmlDsigRSASHA512Url = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
    }
}
