using System.Security.Cryptography;
using System.Text.Json;
using DataEncoding.JSON;
using RSAParametersIO;

namespace Tests;

public class JSONTests
{
    private static readonly JsonSerializerOptions options = new()
    {
        IncludeFields = true
    };

    [Fact]
    public void JSON_Serialize_Public()
    {
        var referenceInput = Utils.SerializablePublic;

        string reference = JsonSerializer.Serialize(referenceInput, options);
        string library = JSONFunctions.Minify(RSAParamsIO.ToJSON(Utils.ParametersPrivate, false));

        Assert.Equal(reference, library);
    }

    [Fact]
    public void JSON_Serialize_Private()
    {
        var referenceInput = Utils.SerializablePrivate;

        string reference = JsonSerializer.Serialize(referenceInput, options);
        string library = JSONFunctions.Minify(RSAParamsIO.ToJSON(Utils.ParametersPrivate, true));

        Assert.Equal(reference, library);
    }

    [Fact]
    public void JSON_Deserialize()
    {
        var reference = Utils.ParametersPrivate;
        string input = JsonSerializer.Serialize(Utils.SerializablePrivate, options);

        RSAParameters[] libraryOutput = RSAParamsIO.FromJSON(input);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }

    [Fact]
    public void JSON_EndToEnd()
    {
        var reference = Utils.ParametersPrivate;

        string serialized = RSAParamsIO.ToJSON(reference, true);
        RSAParameters[] libraryOutput = RSAParamsIO.FromJSON(serialized);

        RSAParameters library = Assert.Single(libraryOutput);

        Utils.RsaParametersEqual(reference, library);
    }
}
