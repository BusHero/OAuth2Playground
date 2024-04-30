using AutoFixture.Xunit2;
using FluentAssertions;

namespace AuthorizationServer.Tests;

public sealed class UriAssertionsTests
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
    public void ShouldHaveHost_WrongHost_ThrowsException(
        UriBuilder uriBuilder,
        string host)
    {
        var uri = uriBuilder.Uri;

        var exception = uri.Invoking(x => x.Should().HaveHost(host))
            .Should()
            .Throw<Exception>()
            .And;
        exception
            .Message
            .Should()
            .Contain($"Expected host to contain \"{host}\", but found \"{uri.Host}\"");
    }

    [Theory, AutoData]
    public void ShouldHaveHost_Wrong_ContainsBecauseMessage(
        UriBuilder uriBuilder,
        string host,
        string because)
    {
        var uri = uriBuilder.Uri;

        uri.Invoking(x => x.Should().HaveHost(host, because))
            .Should()
            .Throw<Exception>()
            .And
            .Message
            .Should()
            .Contain(because);
    }

    [Theory, AutoData]
    public void ShouldHaveHost_SubjectIsNull_ShouldNotThrowNullReferenceException(
        string host)
    {
        var action = () => default(Uri).Should().HaveHost(host);

        action.Should().NotThrow<NullReferenceException>();
    }

    [Theory, AutoData]
    public void ShouldHaveHost_SubjectIsNull_ContainsTheRightMessage(
        string host)
    {
        var action = () => default(Uri).Should().HaveHost(host);

        action
            .Should()
            .Throw<Exception>()
            .And
            .Message
            .Should()
            .Contain("You can't assert a uri if it is null");
    }
}