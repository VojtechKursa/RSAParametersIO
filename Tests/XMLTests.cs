using System.Security.Cryptography;
using DataEncoding.XML;
using RSAParametersIO;

namespace Tests;

public class XMLTests
{
    [Fact]
    public void XML_Serialize_Public()
    {
        string reference = Utils.Rsa.ToXmlString(false);
        string library = XMLBase.Minify(RSAParamsIO.ToXML_NET(Utils.ParametersPrivate, false));

        Assert.Equal(reference, library);
    }

    [Fact]
    public void XML_Serialize_Private()
    {
        string reference = Utils.Rsa.ToXmlString(true);
        string library = XMLBase.Minify(RSAParamsIO.ToXML_NET(Utils.ParametersPrivate, true));

        Assert.Equal(reference, library);
    }

    [Fact]
    public void XML_Deserialize()
    {
        var reference = Utils.ParametersPrivate;
        string input = Utils.Rsa.ToXmlString(true);

        RSAParameters[] libraryOutput = RSAParamsIO.FromXML(input);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }

    [Fact]
    public void XML_NET_EndToEnd()
    {
        var reference = Utils.ParametersPrivate;

        string serialized = RSAParamsIO.ToXML_NET(reference, true);
        RSAParameters[] libraryOutput = RSAParamsIO.FromXML(serialized);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }

    [Fact]
    public void XML_W3C_EndToEnd()
    {
        var reference = Utils.ParametersPrivate;

        string serialized = RSAParamsIO.ToXML_W3C(reference, true);
        RSAParameters[] libraryOutput = RSAParamsIO.FromXML(serialized);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }
}
