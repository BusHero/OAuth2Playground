using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory) : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly FlurlClient _client
        = new(authorizationServiceFactory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = authorizationServiceFactory.ClientRepository;

    [Theory, AutoData]
    public async Task HappyPath_ReturnsOk(
        Client oauthClient,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsRequestId(
        Client oauthClient,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        var code = await result.GetStringAsync();

        code
            .Should()
            .NotBeNullOrEmpty();
    }

    [Theory, AutoData]
    public async Task ClientId_Missing_ReturnsBadRequest(
        Client oauthClient,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ClientId_Invalid_ReturnsBadRequest(
        Client oauthClient,
        string invalidClientId,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", invalidClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RedirectUri_Missing_ReturnsBadRequest(
        Client oauthClient,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RedirectUri_InvalidRedirectUri_ReturnsBadRequest(
        Client oauthClient,
        string state,
        Uri invalidRedirectUri)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", invalidRedirectUri.ToString())
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ResponseType_Missing_ReturnsBadRequest(
        Client oauthClient,
        string state)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task State_Missing_ReturnsOk(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("client_id", oauthClient.ClientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }
}