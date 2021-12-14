using DataEncoding.XML;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        /// <summary>
        /// Encodes the key of the given <see cref="RSA"/> instance into XML format element, using .NET standard tags.
        /// </summary>
        /// <inheritdoc cref="ToXML_W3C(RSA, bool)"/>
        public static string ToXML_NET(RSA rsa, bool includePrivateParameters)
        {
            return ToXML_NET(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        /// <summary>
        /// Encodes the parameters in the given <see cref="RSAParameters"/> instance as an RSA key into XML format element, using .NET standard tags.
        /// </summary>
        /// <inheritdoc cref="ToXML_W3C(RSAParameters, bool)"/>
        public static string ToXML_NET(RSAParameters rsa, bool includePrivateParameters)
        {
            XMLElement keyElem = MakeKeyElement(rsa, includePrivateParameters);
            keyElem.Name = "RSAKeyValue";

            return XMLBase.Beautify(keyElem.Encode());
        }
    }
}
