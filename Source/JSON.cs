using DataEncoding.JSON;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        public static string ToJSON(RSA rsa, bool includePrivateParameters)
        {
            return ToJSON(rsa.ExportParameters(includePrivateParameters), includePrivateParameters);
        }

        public static string ToJSON(RSAParameters rsa, bool includePrivateParameters)
        {
            JSONNameValuePairCollection coll = new JSONNameValuePairCollection
            {
                { "n", new JSONString(Convert.ToBase64String(rsa.Modulus)) },
                { "e", new JSONString(Convert.ToBase64String(rsa.Exponent)) }
            };

            if (includePrivateParameters)
            {
                coll.Add("d", new JSONString(Convert.ToBase64String(rsa.D)));
                coll.Add("p", new JSONString(Convert.ToBase64String(rsa.P)));
                coll.Add("q", new JSONString(Convert.ToBase64String(rsa.Q)));
                coll.Add("dp", new JSONString(Convert.ToBase64String(rsa.DP)));
                coll.Add("dq", new JSONString(Convert.ToBase64String(rsa.DQ)));
                coll.Add("qi", new JSONString(Convert.ToBase64String(rsa.InverseQ)));
            }

            return new JSONObject(coll).Encode();
        }

        public static RSAParameters[] FromJSON(string json, int start)
        {
            List<JSONBase> decoded = JSONDecoder.DecodeString(json, start);

            if (decoded.Count > 0)
            {
                List<RSAParameters> result = new List<RSAParameters>();
                RSAParameters[] temp = new RSAParameters[0];

                foreach (JSONBase jsonBase in decoded)
                {
                    if (jsonBase is JSONObject obj)
                    {
                        temp = CheckObject(obj);
                    }

                    //TO DO: Add scanning for JSONArray later

                    if (temp.Length > 0)
                    {
                        foreach (RSAParameters tempParameters in temp)
                        {
                            result.Add(tempParameters);
                        }

                        temp = new RSAParameters[0];
                    }
                }

                return result.ToArray();
            }
            else
                return null;
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
                if (nameValuePair.Value is JSONObject obj)
                {
                    tempResult = CheckObject(obj);
                    if (tempResult.Length > 0)
                    {
                        foreach (RSAParameters parameters in tempResult)
                        {
                            result.Add(parameters);
                        }
                    }
                }
            }

            return result.ToArray();
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
    }
}
