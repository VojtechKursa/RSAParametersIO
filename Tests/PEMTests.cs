using System.Security.Cryptography;
using RSAParametersIO;

namespace Tests;

public class PEMTests
{
    [Fact]
    public void PEM_Serialize_Public()
    {
        // Strings are trimmed because whether there is an endline at the end of the PEM encoded string doesn't matter,
        //  in regards to the standards conformity

        string reference = Utils.Rsa.ExportRSAPublicKeyPem().TrimEnd();
        string library = RSAParamsIO.ToPEM(Utils.ParametersPrivate, false).TrimEnd();

        // Standard defines EOL as CR / LF / CRLF, so line ending differences can be ignored
        Assert.Equal(reference, library, ignoreLineEndingDifferences: true);
    }

    [Fact]
    public void PEM_Serialize_Private()
    {
        // Strings are trimmed because whether there is an endline at the end of the PEM encoded string doesn't matter,
        //  in regards to the standards conformity

        string reference = Utils.Rsa.ExportRSAPrivateKeyPem().ReplaceLineEndings().TrimEnd();
        string library = RSAParamsIO.ToPEM(Utils.ParametersPrivate, true).ReplaceLineEndings().TrimEnd();

        // Standard defines EOL as CR / LF / CRLF, so line ending differences can be ignored
        Assert.Equal(reference, library, ignoreLineEndingDifferences: true);
    }

    [Fact]
    public void PEM_Deserialize()
    {
        RSAParameters reference = Utils.Rsa.ExportParameters(true);
        string input = Utils.Rsa.ExportRSAPrivateKeyPem();

        RSAParameters[] libraryOutput = RSAParamsIO.FromPEM(input);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }

    [Fact]
    public void PEM_EndToEnd()
    {
        RSAParameters reference = Utils.Rsa.ExportParameters(true);

        string serialized = RSAParamsIO.ToPEM(reference, true);
        RSAParameters[] libraryOutput = RSAParamsIO.FromPEM(serialized);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }
}
