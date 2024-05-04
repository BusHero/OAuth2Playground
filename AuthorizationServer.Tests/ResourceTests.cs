using Flurl.Http;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthorizationServer.Tests;

public sealed class ResourceTests(
    CustomAuthorizationServiceFactory authFactory,
    WebApplicationFactory<WebApplication2.Program> resourceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>,
        IClassFixture<WebApplicationFactory<WebApplication2.Program>>
{
    private readonly IFlurlClient _authClient
        = new FlurlClient(authFactory.CreateDefaultClient());

    private readonly IFlurlClient _resourceClient
        = new FlurlClient(resourceFactory.CreateDefaultClient());

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
        string token)
    {
        var result = await _resourceClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("resource2")
            .WithOAuthBearerToken(token)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task WeiredValueForAuth_Returns401(
        string authValue)
    {
        var result = await _resourceClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("resource2")
            .WithHeader("Authorization", authValue)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Fact]
    public async Task NoAuthorizationHeader_Returns401()
    {
        var result = await _resourceClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("resource2")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(401);
    }
}