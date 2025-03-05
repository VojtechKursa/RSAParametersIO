using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Xml.Serialization;

namespace Tests.Types;

public class RsaPublicParameters
{
    [XmlElement(Order = 0)]
    [JsonPropertyOrder(0)]
    public byte[]? n;

    [XmlElement(Order = 1)]
    [JsonPropertyOrder(1)]
    public byte[]? e;

    public virtual RsaPublicParameters TakeParameters(RSAParameters parameters)
    {
        n = parameters.Modulus;
        e = parameters.Exponent;

        return this;
    }
}
