using Shouldly;
using System.Security.Cryptography;
using System.Text;

namespace AuthorizationServer.Tests.CryptoTests;

public sealed class DataProtectionPlayground
{
    private const string MESSAGE = """
        When I had journeyed half of our life's way,
        I found myself within a shadowed forest,
        for I had lost the path that does not stray.
        """;

    [Fact]
    public void ProtectDataTest()
    {
        var data = Encoding.ASCII.GetBytes(MESSAGE);

        var protectedData = ProtectedData.Protect(data, [], DataProtectionScope.CurrentUser);

        protectedData.ShouldNotBe(data);
    }

    [Fact]
    public void UnprotectDataTest()
    {
        var data = Encoding.ASCII.GetBytes(MESSAGE);

        var protectedData = ProtectedData.Protect(data, [], DataProtectionScope.CurrentUser);
        var unprotectedData = ProtectedData.Unprotect(protectedData, [], DataProtectionScope.CurrentUser);

        unprotectedData.ShouldBe(data);
    }
}
