using Shouldly;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Tests.CryptoTests;

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
