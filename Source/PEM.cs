using DataEncoding.PEM;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        /// <summary>
        /// Encodes the key of the given <see cref="RSA"/> instance into a PEM format.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance whose key is to be encoded.</param>
        /// <param name="includePrivateParameters">True if private key is to be created, false for a public key.</param>
        /// <returns>The resulting RSA key encoded in PEM block.</returns>
        public static string ToPEM(RSA rsa, bool includePrivateParameters)
        {
            return ToPEM(rsa.ExportParameters(includePrivateParameters), includePrivateParameters, includePrivateParameters ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY");
        }

        /// <summary>
        /// Encodes the parameters in the given <see cref="RSAParameters"/> instance as an RSA key into a PEM format.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> instance containing parameters of the key to be encoded.</param>
        /// <inheritdoc cref="ToPEM(RSA, bool)"/>
        /// <exception cref="System.ArgumentException"/>
        public static string ToPEM(RSAParameters rsa, bool includePrivateParameters)
        {
            return ToPEM(rsa, includePrivateParameters, includePrivateParameters ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY");
        }

        /// <param name="customLabel">A custom label to use for the resulting PEM block.</param>
        /// <inheritdoc cref="ToPEM(RSA, bool)"/>
        public static string ToPEM(RSA rsa, bool includePrivateParameters, string customLabel)
        {
            return ToPEM(rsa.ExportParameters(includePrivateParameters), includePrivateParameters, customLabel);
        }

        /// <param name="customLabel">A custom label to use for the resulting PEM block.</param>
        /// <inheritdoc cref="ToPEM(RSAParameters, bool)"/>
        public static string ToPEM(RSAParameters rsa, bool includePrivateParameters, string customLabel)
        {
            return new PEMBlock(customLabel, ToDER(rsa, includePrivateParameters)).Encode();
        }

        /// <summary>
        /// Decodes a key present in the given PEM block or all keys present in a series of PEM blocks.
        /// </summary>
        /// <param name="text">A <see cref="string"/> containing the PEM structure to decode.</param>
        /// <returns>
        /// An array of all decoded <see cref="RSAParameters"/>.<br />
        /// The array can be null if the text didn't contain any PEM block.<br />
        /// The array can also have 0 items in case PEM blocks were found in the text, but no label matched the standard RSA key labels.<br />
        /// <see cref="System.ArgumentException"/> can be thrown if there is an error during decode of the PEM blocks or during decode of a DER block inside a valid and correctly labeled PEM block.
        /// </returns>
        /// <exception cref="System.ArgumentException"/>
        public static RSAParameters[] FromPEM(string text)
        {
            return FromPEM(text, 0, new string[] { "RSA PRIVATE KEY", "RSA PUBLIC KEY" });
        }

        /// <param name="start">The index in text at which to start decoding.</param>
        /// <inheritdoc cref="FromPEM(string)"/>
        public static RSAParameters[] FromPEM(string text, int start)
        {
            return FromPEM(text, start, new string[] { "RSA PRIVATE KEY", "RSA PUBLIC KEY" });
        }

        /// <param name="acceptedLabels">An array of custom labels to accept.</param>
        /// <inheritdoc cref="FromPEM(string, int)"/>
        public static RSAParameters[] FromPEM(string text, int start, string[] acceptedLabels)
        {
            PEMSuperBlock superBlock = new PEMSuperBlock();

            superBlock.Decode(text, start);

            if (superBlock.Blocks.Count > 0)
            {
                List<RSAParameters> parameters = new List<RSAParameters>();

                foreach (PEMBlock block in superBlock.Blocks)
                {
                    if (Contains(acceptedLabels, block.BlockLabel))
                        parameters.Add(FromDER(block.Content, 0));
                }

                return parameters.ToArray();
            }
            else
                return null;
        }

        private static bool Contains(string[] array, string value)
        {
            for (int i = 0; i < array.Length; i++)
            {
                if (value == array[i])
                    return true;
            }

            return false;
        }
    }
}
