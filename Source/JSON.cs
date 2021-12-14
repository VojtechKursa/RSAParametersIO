using DataEncoding.JSON;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    /// <summary>
    /// A static class containing all methods in the RSAParametersIO Library.
    /// </summary>
    public static partial class RSAParamsIO
    {
        #region Public methods

        /// <summary>
        /// Encodes the key of the given <see cref="RSA"/> instance into a JSON format object.
        /// </summary>
        /// <param name="rsa">The <see cref="RSA"/> instance whose key is to be encoded.</param>
        /// <param name="includePrivateParameters">True if private key is to be created, false for a public key.</param>
        /// <returns>The resulting RSA key encoded as a JSON object.</returns>
        public static string ToJSON(RSA rsa, bool includePrivateParameters)
        {
            return ToJSON(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        /// <summary>
        /// Encodes the parameters in the given <see cref="RSAParameters"/> instance as an RSA key into a JSON format object.
        /// </summary>
        /// <param name="rsa">The <see cref="RSAParameters"/> instance containing parameters of the key to be encoded.</param>
        /// <inheritdoc cref="ToJSON(RSA, bool)"/>
        /// <exception cref="System.ArgumentException"/>
        public static string ToJSON(RSAParameters rsa, bool includePrivateParameters)
        {
            JSONNameValuePairCollection coll = new JSONNameValuePairCollection
            {
                { "n", new JSONString(Convert.ToBase64String(rsa.Modulus)) },
                { "e", new JSONString(Convert.ToBase64String(rsa.Exponent)) }
            };

            if (includePrivateParameters)
            {
                if (rsa.D != null)
                {
                    coll.Add("d", new JSONString(Convert.ToBase64String(rsa.D)));
                    coll.Add("p", new JSONString(Convert.ToBase64String(rsa.P)));
                    coll.Add("q", new JSONString(Convert.ToBase64String(rsa.Q)));
                    coll.Add("dp", new JSONString(Convert.ToBase64String(rsa.DP)));
                    coll.Add("dq", new JSONString(Convert.ToBase64String(rsa.DQ)));
                    coll.Add("qi", new JSONString(Convert.ToBase64String(rsa.InverseQ)));
                }
                else
                    throw new ArgumentException("RSA private key requested, but the RSAParameters instance doesn't contain private parameters.");
            }

            return JSONFunctions.Beautify(new JSONObject(coll).Encode());
        }

        /// <summary>
        /// Decodes all keys present in any JSON encoded object in the given JSON encoded string.<br />
        /// (Decodes also keys that are inside an array or another object as long as the key parameters are inside an object and are named correctly)
        /// </summary>
        /// <param name="json">A <see cref="string"/> containing the JSON objects to decode.</param>
        /// <returns>
        /// An array of all decoded <see cref="RSAParameters"/>.<br />
        /// The array can be null if no JSON values were found in the input.<br />
        /// The array can also have 0 items in case JSON values were found in the input, but no JSON object containing any key parameters was found.<br />
        /// </returns>
        public static RSAParameters[] FromJSON(string json)
        {
            return FromJSON(json, 0);
        }

        /// <param name="start">An index in the input JSON text from which to start decoding.</param>
        /// <inheritdoc cref="FromJSON(string)"/>
        public static RSAParameters[] FromJSON(string json, int start)
        {
            List<JSONBase> decoded = JSONFunctions.DecodeString(json, start);

            if (decoded.Count > 0)
            {
                List<RSAParameters> result = new List<RSAParameters>();
                RSAParameters[] temp;

                foreach (JSONBase jsonBase in decoded)
                {
                    temp = CheckValue(jsonBase);

                    if (temp != null)
                    {
                        foreach (RSAParameters tempParameters in temp)
                        {
                            result.Add(tempParameters);
                        }
                    }
                }

                return result.ToArray();
            }
            else
                return null;
        }

        #endregion

        #region Support methods

        private static RSAParameters[] CheckValue(JSONBase value)
        {
            RSAParameters[] result = null;

            if (value is JSONObject obj)
            {
                result = CheckObject(obj);
            }
            else if (value is JSONArray arr)
            {
                result = CheckArray(arr);
            }

            return result;
        }

        private static RSAParameters[] CheckArray(JSONArray array)
        {
            List<RSAParameters> result = new List<RSAParameters>();
            RSAParameters[] tempResult;

            foreach (JSONBase value in array.Content)
            {
                tempResult = CheckValue(value);

                if (tempResult != null)
                {
                    foreach (RSAParameters parameters in tempResult)
                    {
                        result.Add(parameters);
                    }
                }
            }

            return result.Count > 0 ? result.ToArray() : null;
        }

        private static RSAParameters[] CheckObject(JSONObject jsonObject)
        {
            List<RSAParameters> result = new List<RSAParameters>();
            RSAParameters[] tempResult;

            RSAParameters? objectParameters = ExtractRSA(jsonObject);
            if (objectParameters != null)
                result.Add((RSAParameters)objectParameters);

            foreach (JSONNameValuePair nameValuePair in jsonObject.Content)
            {
                tempResult = CheckValue(nameValuePair.Value);

                if (tempResult != null)
                {
                    foreach (RSAParameters parameters in tempResult)
                    {
                        result.Add(parameters);
                    }
                }
            }

            return result.Count > 0 ? result.ToArray() : null;
        }

        private static RSAParameters? ExtractRSA(JSONObject jsonObject)
        {
            if (jsonObject.Content.Contains("e") && jsonObject.Content.Contains("n"))
            {
                RSAParameters parameters = new RSAParameters
                {
                    Exponent = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("e")).Content),
                    Modulus = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("n")).Content)
                };

                if (jsonObject.Content.Contains("d") &&
                    jsonObject.Content.Contains("p") &&
                    jsonObject.Content.Contains("q") &&
                    jsonObject.Content.Contains("dp") &&
                    jsonObject.Content.Contains("dq") &&
                    jsonObject.Content.Contains("qi"))
                {
                    parameters.D = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("d")).Content);
                    parameters.P = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("p")).Content);
                    parameters.Q = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("q")).Content);
                    parameters.DP = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("dp")).Content);
                    parameters.DQ = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("dq")).Content);
                    parameters.InverseQ = Convert.FromBase64String(((JSONString)jsonObject.Content.FindValue("qi")).Content);
                }

                return parameters;
            }

            return null;
        }

        #endregion
    }
}
