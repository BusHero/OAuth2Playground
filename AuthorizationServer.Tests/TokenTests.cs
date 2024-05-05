using System.Diagnostics.CodeAnalysis;
using FluentAssertions.Execution;
using Flurl.Http;

namespace AuthorizationServer.Tests;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Local")]
public sealed class TokenTests(CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly FlurlClient _client
        = new(authorizationServiceFactory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = authorizationServiceFactory.ClientRepository;

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsToken(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        var json = await result.GetJsonAsync<Dictionary<string, string>>();

        using (new AssertionScope())
        {
            json.Should()
                .ContainKey("token_type")
                .WhoseValue
                .Should()
                .Be("Bearer");

            json.Should()
                .ContainKey("access_token")
                .WhoseValue
                .Should()
                .NotBeNullOrEmpty();
        }
    }

    [Theory, AutoData]
    public async Task CodeForWrongClient_Returns400(
        Client rightClient,
        Client wrongClient)
    {
        _clientRepository.AddClient(wrongClient);
        _clientRepository.AddClient(rightClient);

        var code = await GetAuthorizationCode(rightClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(wrongClient.ClientId, wrongClient.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task InvalidCode_Returns400(
        Client client,
        string invalidCode)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = invalidCode,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task MissingCode_Returns400(
        Client client)
    {
        _clientRepository.AddClient(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task MissingGrantType_Returns400(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type1"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task GrantTypeIsNotAuthorizationCode_Returns400(
        Client client,
        string authorizationCode)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = authorizationCode,
                ["code"] = code,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task NonRegistered_Returns401(
        Client unregisteredClient,
        Client registeredClient)
    {
        _clientRepository.AddClient(registeredClient);
        var code = await GetAuthorizationCode(registeredClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(unregisteredClient.ClientId, unregisteredClient.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task WrongSecret_Returns401(
        Client client,
        string wrongSecret)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, wrongSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task NoCredentials_Return401(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task CredentialsInBody_Returns200(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task SameCredentialsInHeaderAndBody_Returns401(
        Client client)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task WrongAuthenticationScheme_Returns400(
        Client client,
        string token)
    {
        _clientRepository.AddClient(client);

        var code = await GetAuthorizationCode(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithOAuthBearerToken(token)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task DifferentCredentialsInHeaderAndBody_Returns401(
        Client client1,
        Client client2)
    {
        _clientRepository.AddClient(client1);
        _clientRepository.AddClient(client2);

        var code = await GetAuthorizationCode(client1);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client1.ClientId, client1.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client2.ClientId,
                ["secret"] = client2.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result.StatusCode.Should().Be(401);
    }

    private async Task<string> GetAuthorizationCode(
        Client oauthClient)
    {
        var response = await _client
            .Request()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", Guid.NewGuid().ToString())
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        var responseObject = await response.GetJsonAsync<Response>();

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["reqId"] = responseObject.Code,
                ["approve"] = "approve",
            });

        var query = result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters();

        return query["code"];
    }
}