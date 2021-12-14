using DataEncoding.DER;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        #region Public methods

        /// <summary>
        /// Encodes the key of the given <see cref="RSA"/> instance into a DER format.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance whose key is to be encoded.</param>
        /// <param name="includePrivateParameters">True if private key is to be created, false for a public key.</param>
        /// <returns>The resulting RSA key encoded in DER structure.</returns>
        public static byte[] ToDER(RSA rsa, bool includePrivateParameters)
        {
            return ToDER(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        /// <summary>
        /// Encodes the parameters in the given <see cref="RSAParameters"/> instance as an RSA key into a DER format.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> instance containing parameters of the key to be encoded.</param>
        /// <exception cref="ArgumentException"/>
        /// <inheritdoc cref="ToDER(RSA, bool)"/>
        public static byte[] ToDER(RSAParameters rsa, bool includePrivateParameters)
        {
            return includePrivateParameters ? BuildPrivateDER(rsa) : BuildPublicDER(rsa);
        }

        /// <summary>
        /// Decodes a key present in the given DER structure.
        /// </summary>
        /// <param name="data">A <see cref="byte"/> array containing the DER structure to decode</param>
        /// <param name="start">The index in the data array at which to start decoding.</param>
        /// <returns>The decoded RSA parameters.</returns>
        /// <exception cref="ArgumentException"/>
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
                        Modulus = RemoveNullHighByte(((DERGeneric)sequence.Content[0]).Content),
                        Exponent = RemoveNullHighByte(((DERGeneric)sequence.Content[1]).Content)
                    };

                    return parameters;
                }
                else if (sequence.Content.Count >= 9)
                {
                    RSAParameters parameters = new RSAParameters()
                    {
                        Modulus = RemoveNullHighByte(((DERGeneric)sequence.Content[1]).Content),
                        Exponent = RemoveNullHighByte(((DERGeneric)sequence.Content[2]).Content),
                        D = RemoveNullHighByte(((DERGeneric)sequence.Content[3]).Content),
                        P = RemoveNullHighByte(((DERGeneric)sequence.Content[4]).Content),
                        Q = RemoveNullHighByte(((DERGeneric)sequence.Content[5]).Content),
                        DP = RemoveNullHighByte(((DERGeneric)sequence.Content[6]).Content),
                        DQ = RemoveNullHighByte(((DERGeneric)sequence.Content[7]).Content),
                        InverseQ = RemoveNullHighByte(((DERGeneric)sequence.Content[8]).Content),
                    };

                    return parameters;
                }
                else
                    throw new ArgumentException("Invalid data. Amount of parameters in DER data is different from what was expected.");
            }
            else
                throw new ArgumentException(nameof(data) + " doesn't contain expected data, is input a DER Sequence?");
        }

        #endregion

        #region Support methods

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
            if (rsa.D != null)
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
            else
                throw new ArgumentException("Private key couldn't be built as the given data don't contain private parameters.");
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

        private static byte[] RemoveNullHighByte(byte[] originalData)
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

        #endregion
    }
}
