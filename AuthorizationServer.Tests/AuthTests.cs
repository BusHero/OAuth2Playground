using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using FluentAssertions;

namespace AuthorizationServer.Tests;

public sealed class AuthTests(
    WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client
        = factory.CreateDefaultClient();
    
    [Fact]
    public async Task ClientId_Ok()
    {
        var result = await _client
            .GetAsync("/authorize?client_id=oauth-client-1");

        result.StatusCode
            .Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NoClientId_BadRequest()
    {
        var result = await _client.GetAsync("/authorize");

        result.StatusCode
            .Should()
            .Be(HttpStatusCode.BadRequest);
    }
    
    [Fact]
    public async Task WrongClientId_BadRequest()
    {
        var result = await _client
            .GetAsync("/authorize?client_id=some_client_id");

        result.StatusCode
            .Should()
            .Be(HttpStatusCode.BadRequest);
    }
}