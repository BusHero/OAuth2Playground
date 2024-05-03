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

    [Fact]
    public async Task GetResource2FromResourceClient()
    {
        var result = await _resourceClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("resource2")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }
}