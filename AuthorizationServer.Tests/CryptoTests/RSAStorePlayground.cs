using Shouldly;
using System.Security.Cryptography;

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
