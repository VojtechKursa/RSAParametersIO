using System;
using System.Security.Cryptography;
using DataEncoding.XML;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        /// <summary>
        /// Encodes the key of the given <see cref="RSA"/> instance into XML format element, using W3C standard tags.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance whose key is to be encoded.</param>
        /// <param name="includePrivateParameters">True if private key is to be created, false for a public key.</param>
        /// <returns>The resulting RSA key encoded as XML element.</returns>
        public static string ToXML_W3C(RSA rsa, bool includePrivateParameters)
        {
            return ToXML_W3C(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        /// <summary>
        /// Encodes the parameters in the given <see cref="RSAParameters"/> instance as an RSA key into XML format element, using W3C standard tags.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> instance containing parameters of the key to be encoded.</param>
        /// <inheritdoc cref="ToXML_W3C(RSA, bool)"/>
        /// <exception cref="ArgumentException"/>
        public static string ToXML_W3C(RSAParameters rsa, bool includePrivateParameters)
        {
            return XMLBase.Beautify(MakeKeyElement(rsa, includePrivateParameters).Encode());
        }
    }
}
