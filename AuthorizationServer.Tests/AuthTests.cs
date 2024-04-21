using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using FluentAssertions;
using Flurl.Http;
using Flurl.Http.Testing;

namespace AuthorizationServer.Tests;

public sealed class AuthTests(
    WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly FlurlClient _client =
        new(factory.CreateDefaultClient());

    [Fact]
    public async Task ClientId_Ok()
    {
        var result = await _client
            .GetRightRequest()
            .SendAsync(HttpMethod.Get);

        result.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task NoClientId_BadRequest()
    {
        var result = await _client
            .GetRightRequest()
            .RemoveQueryParam("client_id")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task WrongClientId_BadRequest()
    {
        var result = await _client
            .GetRightRequest()
            .SetQueryParam("client_id", "another_client")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }
}

public static class Foo
{
    public static IFlurlRequest GetRightRequest(this IFlurlClient client) =>
        client.Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("authorize")
            .AppendQueryParam("client_id", "oauth-client-1");
}