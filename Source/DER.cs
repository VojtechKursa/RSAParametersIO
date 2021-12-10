using DataEncoding.DER;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        public static byte[] ToDER(RSA rsa, bool includePrivateParameters)
        {
            return ToDER(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        public static byte[] ToDER(RSAParameters rsa, bool includePrivateParameters)
        {
            return includePrivateParameters ? BuildPrivateDER(rsa) : BuildPublicDER(rsa);
        }

        private static byte[] BuildPublicDER(RSAParameters rsa)
        {
            List<DERBase> content = new List<DERBase>
            {
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.Modulus)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.Exponent))
            };

            DERSequence sequence = new DERSequence(content);

            return sequence.Encode();
        }

        private static byte[] BuildPrivateDER(RSAParameters rsa)
        {
            List<DERBase> content = new List<DERBase>
            {
                new DERGeneric(0, true, DataType.Integer, new byte[] {0}),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.Modulus)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.Exponent)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.D)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.P)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.Q)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.DP)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.DQ)),
                new DERGeneric(0, true, DataType.Integer, SolveSetHighBit(rsa.InverseQ))
            };

            DERSequence sequence = new DERSequence(content);

            return sequence.Encode();
        }

        public static RSAParameters FromDER(byte[] data, int start)
        {
            DERSequence sequence = new DERSequence();

            try
            {
                sequence.Decode(data, start);
            }
            catch (Exception)
            {
                throw new ArgumentException(nameof(data) + " couldn't be decoded, is input a DER Sequence?");
            }

            if (sequence.Content.Count > 0)
            {
                if (sequence.Content.Count == 2)
                {
                    RSAParameters parameters = new RSAParameters()
                    {
                        Modulus = RemoveNullHighBit(((DERGeneric)sequence.Content[0]).Content),
                        Exponent = RemoveNullHighBit(((DERGeneric)sequence.Content[0]).Content)
                    };

                    return parameters;
                }
                else if (sequence.Content.Count >= 9)
                {
                    RSAParameters parameters = new RSAParameters()
                    {
                        Modulus = RemoveNullHighBit(((DERGeneric)sequence.Content[1]).Content),
                        Exponent = RemoveNullHighBit(((DERGeneric)sequence.Content[2]).Content),
                        D = RemoveNullHighBit(((DERGeneric)sequence.Content[3]).Content),
                        P = RemoveNullHighBit(((DERGeneric)sequence.Content[4]).Content),
                        Q = RemoveNullHighBit(((DERGeneric)sequence.Content[5]).Content),
                        DP = RemoveNullHighBit(((DERGeneric)sequence.Content[6]).Content),
                        DQ = RemoveNullHighBit(((DERGeneric)sequence.Content[7]).Content),
                        InverseQ = RemoveNullHighBit(((DERGeneric)sequence.Content[8]).Content),
                    };

                    return parameters;
                }
                else
                    throw new ArgumentException("Invalid data. Amount of parameters in DER data is different from what was expected.");
            }
            else
                throw new ArgumentException(nameof(data) + " doesn't contain expected data, is input a DER Sequence?");
        }

        private static byte[] SolveSetHighBit(byte[] originalData)
        {
            if ((originalData[0] & 0x80) == 0)
                return originalData;
            else
            {
                byte[] result = new byte[originalData.Length + 1];
                result[0] = 0;

                Array.Copy(originalData, 0, result, 1, originalData.Length);

                return result;
            }
        }

        private static byte[] RemoveNullHighBit(byte[] originalData)
        {
            if (originalData[0] != 0)
                return originalData;
            else
            {
                byte[] result = new byte[originalData.Length - 1];

                Array.Copy(originalData, 1, result, 0, result.Length);

                return result;
            }
        }
    }
}
