using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        //Maybe make more effective when DataEncoding.XML is available?

        public static string ToXML_NET(RSA rsa, bool includePrivateParameters)
        {
            return rsa.ToXmlString(includePrivateParameters);
        }

        public static string ToXML_NET(RSAParameters rsa, bool includePrivateParameters)
        {
            RSA x = RSA.Create();
            x.ImportParameters(rsa);

            return x.ToXmlString(includePrivateParameters);
        }

        public static RSA FromXML_NET(string xml)
        {
            RSA rsa = RSA.Create();

            rsa.FromXmlString(xml);

            return rsa;
        }
    }
}
