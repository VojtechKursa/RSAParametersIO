using DataEncoding.XML;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace RSAParametersIO
{
    public static partial class RSAParamsIO
    {
        /// <summary>
        /// Decodes all keys present in any XML element in the given XML encoded string.<br />
        /// (Decodes also keys from elements that are nested in other elements)
        /// </summary>
        /// <param name="xml">A <see cref="string"/> containing the XML elements to decode.</param>
        /// <returns>
        /// An array of all decoded <see cref="RSAParameters"/>.<br />
        /// The array can be null if no XML values were found in the input.<br />
        /// The array can also have 0 items in case XML values were found in the input, but no XML element containing any key parameters was found.<br />
        /// </returns>
        public static RSAParameters[] FromXML(string xml)
        {
            return FromXML(xml, 0);
        }

        /// <param name="start">An index in the input XML text from which to start decoding.</param>
        /// <inheritdoc cref="FromXML(string)"/>
        public static RSAParameters[] FromXML(string xml, int start)
        {
            List<XMLElement> elements = new List<XMLElement>();
            int end = start;
            XMLElement tempElement;

            while (true)
            {
                try
                {
                    tempElement = XMLElement.FromEncoded(xml, end, out end);

                    if (tempElement != null)
                        elements.Add(tempElement);
                }
                catch
                { break; }
            }

            if (elements.Count > 0)
            {
                List<RSAParameters> result = new List<RSAParameters>();
                RSAParameters[] tempResult;

                foreach (XMLElement element in elements)
                {
                    tempResult = CheckElement(element);

                    if (tempResult.Length > 0)
                    {
                        foreach (RSAParameters parameters in tempResult)
                        {
                            result.Add(parameters);
                        }
                    }
                }

                return result.ToArray();
            }
            else
                return null;
        }

        private static XMLElement MakeKeyElement(RSAParameters rsa, bool includePrivateParameters)
        {
            XMLElement mainElement = new XMLElement(includePrivateParameters ? "RSAKeyPair" : "RSAKeyValue");

            mainElement.Content.Add(new XMLElement("Modulus", new XMLString(Convert.ToBase64String(rsa.Modulus))));
            mainElement.Content.Add(new XMLElement("Exponent", new XMLString(Convert.ToBase64String(rsa.Exponent))));

            if (includePrivateParameters)
            {
                if (rsa.P != null)
                {
                    mainElement.Content.Add(new XMLElement("P", new XMLString(Convert.ToBase64String(rsa.P))));
                    mainElement.Content.Add(new XMLElement("Q", new XMLString(Convert.ToBase64String(rsa.Q))));
                    mainElement.Content.Add(new XMLElement("DP", new XMLString(Convert.ToBase64String(rsa.DP))));
                    mainElement.Content.Add(new XMLElement("DQ", new XMLString(Convert.ToBase64String(rsa.DQ))));
                    mainElement.Content.Add(new XMLElement("InverseQ", new XMLString(Convert.ToBase64String(rsa.InverseQ))));
                    mainElement.Content.Add(new XMLElement("D", new XMLString(Convert.ToBase64String(rsa.D))));
                }
                else
                    throw new ArgumentException("Private key encode was requested, but only public parameters were given.");
            }

            return mainElement;
        }

        private static RSAParameters[] CheckElement(XMLElement element)
        {
            List<RSAParameters> result = new List<RSAParameters>();
            RSAParameters[] tempResult;

            RSAParameters? elementParams = ExtractRSA(element);
            if (elementParams != null)
            {
                result.Add((RSAParameters)elementParams);
            }

            foreach (XMLBase x in element.Content)
            {
                if (x is XMLElement el)
                {
                    tempResult = CheckElement(el);

                    if (tempResult.Length > 0)
                    {
                        foreach (RSAParameters res in tempResult)
                        {
                            result.Add(res);
                        }
                    }
                }
            }

            return result.ToArray();
        }

        private static RSAParameters? ExtractRSA(XMLElement element)
        {
            XMLElement e = element.Content.Find("Exponent");
            XMLElement n = element.Content.Find("Modulus");

            if (e != null & n != null)
            {
                if (e.Content.Count == 1 && n.Content.Count == 1)
                {
                    if (e.Content.Items[0] is XMLString eStr && n.Content.Items[0] is XMLString nStr)
                    {
                        RSAParameters parameters = new RSAParameters
                        {
                            Exponent = Convert.FromBase64String(eStr.Content),
                            Modulus = Convert.FromBase64String(nStr.Content)
                        };

                        XMLElement d = element.Content.Find("D");

                        if (d != null)
                        {
                            if (d.Content.Count == 1)
                            {
                                if (d.Content.Items[0] is XMLString dStr)
                                {
                                    XMLElement p = element.Content.Find("P");
                                    XMLElement q = element.Content.Find("Q");
                                    XMLElement dp = element.Content.Find("DP");
                                    XMLElement dq = element.Content.Find("DQ");
                                    XMLElement invQ = element.Content.Find("InverseQ");

                                    if (p != null && q != null && dp != null && dq != null && invQ != null)
                                    {
                                        if (p.Content.Count == 1 && q.Content.Count == 1 && dp.Content.Count == 1 && dq.Content.Count == 1 && invQ.Content.Count == 1)
                                        {
                                            if (p.Content.Items[0] is XMLString pStr &&
                                                q.Content.Items[0] is XMLString qStr &&
                                                dp.Content.Items[0] is XMLString dpStr &&
                                                dq.Content.Items[0] is XMLString dqStr &&
                                                invQ.Content.Items[0] is XMLString invQStr)
                                            {

                                                parameters.D = Convert.FromBase64String(dStr.Content);
                                                parameters.P = Convert.FromBase64String(pStr.Content);
                                                parameters.Q = Convert.FromBase64String(qStr.Content);
                                                parameters.InverseQ = Convert.FromBase64String(invQStr.Content);
                                                parameters.DP = Convert.FromBase64String(dpStr.Content);
                                                parameters.DQ = Convert.FromBase64String(dqStr.Content);
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        return parameters;
                    }
                }
            }

            return null;
        }
    }
}
