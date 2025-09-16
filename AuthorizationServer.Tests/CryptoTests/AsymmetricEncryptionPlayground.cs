using Shouldly;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Tests.CryptoTests;

public sealed class AsymmetricEncryptionPlayground
{
    private const string SECRET = "My love's eternal, my heart's aflame";

    [Fact]
    public void CompareArrays()
    {
        var bytes1 = Encoding.ASCII.GetBytes(SECRET);
        var bytes2 = Encoding.ASCII.GetBytes(SECRET);
        
        bytes1.ShouldBe(bytes2);
    }

    [Fact]
    public void EncryptTest()
    {
        using var rsa = RSA.Create();
        var bytes = Encoding.ASCII.GetBytes(SECRET);
        var encryptedBytes = rsa.Encrypt(bytes, RSAEncryptionPadding.Pkcs1);

        encryptedBytes.ShouldNotBe(bytes);
    }

    [Fact]
    public void DecryptTest()
    {
        using var rsa = RSA.Create();
        var bytes = Encoding.ASCII.GetBytes(SECRET);
        var encryptedBytes = rsa.Encrypt(bytes, RSAEncryptionPadding.Pkcs1);
        var decryptedBytes = rsa.Decrypt(encryptedBytes, RSAEncryptionPadding.Pkcs1);

        decryptedBytes.ShouldBe(bytes);
    }
}
