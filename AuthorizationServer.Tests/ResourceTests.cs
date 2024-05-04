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

    private readonly InMemoryClientRepository _clientRepository 
        = authFactory.ClientRepository;

    private readonly IFlurlClient _resourceClient
        = new FlurlClient(resourceFactory.CreateDefaultClient());

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
        Client client)
    {
        var token = await PerformAuthentication(client);
        
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

    [Theory, AutoData]
    public async Task InvalidToken_Returns401(
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
            .Be(401);
    }

    private async Task<string> PerformAuthentication(
        Client client)
    {
        _clientRepository.AddClient(client);

        var requestId = await GetRequestId(
            client.ClientId,
            client.RedirectUris[0]);

        var authorizationCode = await GetAuthorizationCode(
            requestId);

        var token = await GetToken(
            client.ClientId,
            client.ClientSecret,
            authorizationCode);

        return token;
    }

    private async Task<string> GetRequestId(
        string clientId,
        Uri redirectUri)
    {
        var response = await _authClient
            .Request()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", redirectUri.ToString())
            .AppendQueryParam("state", Guid.NewGuid().ToString())
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        var responseObject = await response
            .GetJsonAsync<Response>();

        return responseObject.Code;
    }

    private async Task<string> GetAuthorizationCode(
        string requestId)
    {
        var result = await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["reqId"] = requestId,
                ["approve"] = "approve",
            });

        var query = result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters();

        return query["code"];
    }

    private async Task<string> GetToken(
        string clientId,
        string clientSecret,
        string authorizationCode)
    {
        var response = await _authClient
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(clientId, clientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = authorizationCode,
            });

        var json = await response.GetJsonAsync<Dictionary<string, string>>();

        return json["access_token"];
    }
}