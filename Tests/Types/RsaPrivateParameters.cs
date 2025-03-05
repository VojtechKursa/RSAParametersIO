using System.Security.Cryptography;
using System.Text.Json.Serialization;
using System.Xml.Serialization;

namespace Tests.Types;

public class RsaPrivateParameters : RsaPublicParameters
{
    [XmlElement(Order = 2)]
    [JsonPropertyOrder(2)]
    public byte[]? d;

    [XmlElement(Order = 3)]
    [JsonPropertyOrder(3)]
    public byte[]? p;

    [XmlElement(Order = 4)]
    [JsonPropertyOrder(4)]
    public byte[]? q;

    [XmlElement(Order = 5)]
    [JsonPropertyOrder(5)]
    public byte[]? dp;

    [XmlElement(Order = 6)]
    [JsonPropertyOrder(6)]
    public byte[]? dq;

    [XmlElement(Order = 7)]
    [JsonPropertyOrder(7)]
    public byte[]? qi;

    public override RsaPrivateParameters TakeParameters(RSAParameters parameters)
    {
        base.TakeParameters(parameters);

        d = parameters.D;
        p = parameters.P;
        q = parameters.Q;
        dp = parameters.DP;
        dq = parameters.DQ;
        qi = parameters.InverseQ;

        return this;
    }
}