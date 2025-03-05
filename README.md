# RSAParametersIO Library

A .NET Standard 2.0 library for exporting RSA keys to and importing RSA keys from DER, PEM, JSON and XML formats.

## Usage

The library consists of a single static class `RSAParamsIO` in the `RSAParametersIO` namespace.
The class contans all methods for serializing and deserializing of RSA keys.
For example:

```cs
// Create the RSA class with it's parameters
RSA rsa = RSA.Create();

// Serialize only the entirety of the RSA key (including private parts) into the PEM format
string priv = RSAParamsIO.ToPEM(rsa, true);

// Serialize only the public part of the RSA key into the PEM format
string pub = RSAParamsIO.ToPEM(rsa, false);

// Deserialize the RSA key from the PEM format
var parameters = RSAParamsIO.FromPEM(priv);

// Import the deserialized RSA key into an RSA object
RSA rsa2 = RSA.Create();
rsa2.ImportParameters(parameters);
```

## License

This library is licensed under the **GNU Lesser General Public License v3**.

## Used libraries

### DataEncoding library

This library uses DataEncoding library for encoding and decoding of the RSA keys into/from the respective formats.
- License: LGPLv3
- Source code: GitHub repository at [https://www.github.com/VojtechKursa/DataEncoding](https://www.github.com/VojtechKursa/DataEncoding)

## Building the library

Clone the Github repository.

```sh
git clone https://github.com/VojtechKursa/RSAParametersIO
```

In the root directory of the repository, run the following commands to initialize the submodules.

```sh
git submodule init
git submodule update
```

### Visual Studio

Open either the *.csproj* or *.sln* file in the root of this repository in Visual Studio and build the project.
Alternatively you can download a build from the [releases section of the GitHub repository](https://github.com/VojtechKursa/RSAParametersIO/releases).

### .NET CLI

Run the following command in the root of the repository:

```sh
dotnet build
```

## Contributing

This library is licensed under the **GNU Lesser General Public License v3** so anyone can use it for free and modify it as long as that person follows the conditions stated by the license.
If you have suggestions that would optimize or otherwise improve this library feel free to share them by creating an issue or submitting a pull request with your implemented ideas in the GitHub repository (see section *Source code & Repository*).

## Source code & Repository
The source code for this library and it's public repository can be found on [GitHub](https://github.com/VojtechKursa/RSAParametersIO).
