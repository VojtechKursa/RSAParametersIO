using System.Security.Cryptography;
using Tests.Types;

namespace Tests;

public static class Utils
{
    private static readonly Lazy<RSA> instance = new(RSA.Create);
    private static readonly Lazy<RSAParameters> paramsPublic = new(Rsa.ExportParameters(false));
    private static readonly Lazy<RSAParameters> paramsPrivate = new(Rsa.ExportParameters(true));

    public static RSA Rsa => instance.Value;
    public static RSAParameters ParametersPublic => paramsPublic.Value;
    public static RSAParameters ParametersPrivate => paramsPrivate.Value;

    public static readonly RsaPublicParameters SerializablePublic = new RsaPublicParameters().TakeParameters(ParametersPublic);
    public static readonly RsaPrivateParameters SerializablePrivate = new RsaPrivateParameters().TakeParameters(ParametersPrivate);

    public static void RsaParametersEqual(RSAParameters expected, RSAParameters actual, bool compareOnlyPublic = false)
    {
        Assert.Equal(expected.Modulus, actual.Modulus);
        Assert.Equal(expected.Exponent, actual.Exponent);

        if (!compareOnlyPublic)
        {
            Assert.Equal(expected.D, actual.D);
            Assert.Equal(expected.P, actual.P);
            Assert.Equal(expected.Q, actual.Q);
            Assert.Equal(expected.DP, actual.DP);
            Assert.Equal(expected.DQ, actual.DQ);
            Assert.Equal(expected.InverseQ, actual.InverseQ);
        }
    }
}
