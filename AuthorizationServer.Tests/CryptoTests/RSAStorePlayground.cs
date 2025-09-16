using Shouldly;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Tests.CryptoTests;

public sealed class RSAStorePlayground
{
    [Theory, AutoData]
    public void SameContainerNameReturnsSameKey(string containerName)
    {
        var key1 = GetRsaKey(containerName);
        var key2 = GetRsaKey(containerName);

        key2.ShouldBe(key1);
    }

    [Theory, AutoData]
    public void DeleteAndRestoreKeysGetsNewKey(string containerName)
    {
        var key1 = GetRsaKey(containerName);
        DeleteKey(containerName);
        var key2 = GetRsaKey(containerName);

        key2.ShouldNotBe(key1);
    }

    [Theory, AutoData]
    public void DifferentContainerNamesReturnsDifferentKey(
        string containerName1,
        string containerName2)
    {
        var key1 = GetRsaKey(containerName1);
        var key2 = GetRsaKey(containerName2);

        key2.ShouldNotBe(key1);
    }

    private static string GetRsaKey(string containerName)
    {
        using var container = new RSACryptoServiceProvider(new CspParameters()
        {
            KeyContainerName = containerName,
        });

        return container.ToXmlString(true);
    }

    private static void DeleteKey(string containerName)
    {
        var parameters = new CspParameters
        {
            KeyContainerName = containerName
        };

        using var rsa = new RSACryptoServiceProvider(parameters)
        {
            // Delete the key entry in the container.
            PersistKeyInCsp = false
        };

        rsa.Clear();
    }
}

public sealed class CryptographicSignaturePlayground
{
    private const string MESSAGE = """
        When I had journeyed half of our life's way,
        I found myself within a shadowed forest,
        for I had lost the path that does not stray.
        """;

    [Fact]
    public void CheckSignatureWithRightPublicKeyPasses()
    {
        using var encryptionRsa = RSA.Create();

        var data = Encoding.ASCII.GetBytes(MESSAGE);

        var signature = CreateDataSignature(
            encryptionRsa.ExportParameters(true),
            data);

        var result = VerifyHash(
            encryptionRsa.ExportParameters(false),
            data,
            signature);

        result.ShouldBeTrue();
    }

    [Fact]
    public void CheckSignatureWithWrongKeyFails()
    {
        using var encryptionRsa = RSA.Create();
        using var decryptionRsa = RSA.Create();

        var data = Encoding.ASCII.GetBytes(MESSAGE);

        var signature = CreateDataSignature(
            encryptionRsa.ExportParameters(true),
            data);

        var result = VerifyHash(
            decryptionRsa.ExportParameters(false),
            data,
            signature);

        result.ShouldBeFalse();
    }

    private static byte[] CreateDataSignature(
        RSAParameters rsaParameters,
        byte[] data)
    {
        using var rsa = RSA.Create(rsaParameters);
        var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
        var hash = SHA256.HashData(data);
        rsaFormatter.SetHashAlgorithm(nameof(SHA256));

        return rsaFormatter.CreateSignature(hash);
    }

    private static bool VerifyHash(
        RSAParameters rsaParameters,
        byte[] data,
        byte[] signature)
    {
        using var rsa = RSA.Create(rsaParameters);
        var rsaFormatter = new RSAPKCS1SignatureDeformatter(rsa);
        var hash = SHA256.HashData(data);
        rsaFormatter.SetHashAlgorithm(nameof(SHA256));
        return rsaFormatter.VerifySignature(hash, signature);
    }
}
