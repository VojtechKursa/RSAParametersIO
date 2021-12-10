using DataEncoding.PEM;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        public static string ToPEM(RSA rsa, bool includePrivateParameters)
        {
            return ToPEM(rsa.ExportParameters(includePrivateParameters), includePrivateParameters, includePrivateParameters ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY");
        }

        public static string ToPEM(RSAParameters rsa, bool includePrivateParameters)
        {
            return ToPEM(rsa, includePrivateParameters, includePrivateParameters ? "RSA PRIVATE KEY" : "RSA PUBLIC KEY");
        }

        public static string ToPEM(RSA rsa, bool includePrivateParameters, string customLabel)
        {
            return ToPEM(rsa.ExportParameters(includePrivateParameters), includePrivateParameters, customLabel);
        }

        public static string ToPEM(RSAParameters rsa, bool includePrivateParameters, string customLabel)
        {
            return new PEMBlock(customLabel, ToDER(rsa, includePrivateParameters)).Encode();
        }

        public static RSAParameters[] FromPEM(string text)
        {
            return FromPEM(text, 0, new string[] { "RSA PRIVATE KEY", "RSA PUBLIC KEY" });
        }

        public static RSAParameters[] FromPEM(string text, int start)
        {
            return FromPEM(text, start, new string[] { "RSA PRIVATE KEY", "RSA PUBLIC KEY" });
        }

        public static RSAParameters[] FromPEM(string text, int start, string[] acceptedLabels)
        {
            PEMSuperBlock superBlock = new PEMSuperBlock();

            superBlock.Decode(text, start);

            if (superBlock.Blocks.Count > 0)
            {
                List<RSAParameters> parameters = new List<RSAParameters>();

                foreach (PEMBlock block in superBlock.Blocks)
                {
                    if (Contains(block.BlockLabel, acceptedLabels))
                        parameters.Add(FromDER(block.Content, 0));
                }

                return parameters.ToArray();
            }
            else
                return null;
        }

        private static bool Contains(string value, string[] array)
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
