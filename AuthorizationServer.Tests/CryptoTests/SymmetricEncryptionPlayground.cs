using Shouldly;
using System.Security.Cryptography;

namespace AuthorizationServer.Tests.CryptoTests;

public sealed class SymmetricEncryptionPlayground
{
    private const string SECRET_MESSAGE = """
        When I had journeyed half of our life’s way,
        I found myself within a shadowed forest,
        for I had lost the path that does not stray.
        """;
    private const string PATH = "file.txt";

    [Fact]
    public async Task EncryptTestAsync()
    {
        using var aes = Aes.Create();
        using (var stream = File.OpenWrite(PATH))
        {
            await EncryptAsync(SECRET_MESSAGE, aes, stream);
        }

        var text = await File.ReadAllTextAsync(
            PATH,
            TestContext.Current.CancellationToken);
        text.ShouldNotBe(SECRET_MESSAGE);
    }

    [Fact]
    public async Task DecryptTestAsync()
    {
        using var aes = Aes.Create();
        using (var writeStream = File.OpenWrite(PATH))
        {
            await EncryptAsync(SECRET_MESSAGE, aes, writeStream);
        }
        using var readStream = File.OpenRead(PATH);

        var text = await DecryptAsync(
            aes,
            readStream,
            TestContext.Current.CancellationToken);

        text.ShouldBe(SECRET_MESSAGE);
    }

    private static async Task EncryptAsync(
        string message, 
        Aes aes, 
        Stream stream)
    {
        using var cryptoStream = new CryptoStream(
            stream,
            aes.CreateEncryptor(),
            CryptoStreamMode.Write);
        using var writer = new StreamWriter(cryptoStream);

        await writer.WriteAsync(message);
    }

    private static async Task<string> DecryptAsync(
        Aes aes,
        Stream stream,
        CancellationToken cancellationToken = default)
    {
        using var cryptoStream = new CryptoStream(
            stream,
            aes.CreateDecryptor(),
            CryptoStreamMode.Read);
        using var writer = new StreamReader(cryptoStream);

        return await writer.ReadToEndAsync(cancellationToken: cancellationToken);
    }
}
