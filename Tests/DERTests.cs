using System.Security.Cryptography;
using RSAParametersIO;

namespace Tests;

public class DERTests
{
    [Fact]
    public void DER_Serialize_Public()
    {
        byte[] reference = Utils.Rsa.ExportRSAPublicKey();
        byte[] library = RSAParamsIO.ToDER(Utils.ParametersPrivate, false);

        Assert.Equal(reference, library);
    }

    [Fact]
    public void DER_Serialize_Private()
    {
        byte[] reference = Utils.Rsa.ExportRSAPrivateKey();
        byte[] library = RSAParamsIO.ToDER(Utils.ParametersPrivate, true);

        Assert.Equal(reference, library);
    }

    [Fact]
    public void DER_Deserialize()
    {
        RSAParameters reference = Utils.Rsa.ExportParameters(true);
        byte[] input = Utils.Rsa.ExportRSAPrivateKey();

        RSAParameters library = RSAParamsIO.FromDER(input, 0);

        Utils.RsaParametersEqual(reference, library);
    }

    [Fact]
    public void DER_EndToEnd()
    {
        RSAParameters reference = Utils.Rsa.ExportParameters(true);

        byte[] serialized = RSAParamsIO.ToDER(reference, true);
        RSAParameters library = RSAParamsIO.FromDER(serialized, 0);

        Utils.RsaParametersEqual(reference, library);
    }
}
