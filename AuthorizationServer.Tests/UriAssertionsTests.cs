using System.Drawing;
using AutoFixture.Xunit2;
using FluentAssertions;

namespace AuthorizationServer.Tests;

public class UriAssertionsTests
{
    [Theory, AutoData]
    public void NotBeNull(Uri uri)
    {
        uri.Should().NotBeNull();
    }

    [Fact]
    public void BeNull()
    {
        default(Uri)
            .Should()
            .BeNull();
    }

    [Theory, AutoData]
    public void ShouldHaveHost_Right(
        UriBuilder uriBuilder)
    {
        var uri = uriBuilder.Uri;
        uri.Should().HaveHost(uriBuilder.Host);
    }

    [Theory, AutoData]
    public void ShouldHaveHost_Wrong(
        UriBuilder uriBuilder,
        string host)
    {
        var uri = uriBuilder.Uri;
        uri.Invoking(x => x.Should().HaveHost(host))
            .Should()
            .Throw<Exception>();
    }

    [Theory, AutoData]
    public void ShouldHaveHost_Null_ShouldntThrownNullRefereneceException(
        string host)
    {
        var action = () => default(Uri).Should().HaveHost(host);
        action.Should().NotThrow<NullReferenceException>();
    }
}