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
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string responseType,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", redirectUri)
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsRequestId(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string responseType,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", redirectUri)
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        var code = await result.GetStringAsync();

        code
            .Should()
            .NotBeNullOrEmpty();
    }

    [Theory, AutoData]
    public async Task ClientId_Missing_ReturnsBadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string responseType,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", redirectUri)
            .AppendQueryParam("state", state)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ClientId_Invalid_ReturnsBadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string responseType,
        string invalidClientId,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", redirectUri)
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
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string responseType,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RedirectUri_InvalidRedirectUri_ReturnsBadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state,
        string responseType,
        Uri invalidRedirectUri)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", invalidRedirectUri.ToString())
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ResponseType_Missing_ReturnsBadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("redirect_uri", redirectUri)
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task State_Missing_ReturnsOk(
        string responseType,
        string clientId,
        string clientSecret,
        Uri redirectUri)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", responseType)
            .AppendQueryParam("redirect_uri", redirectUri)
            .AppendQueryParam("client_id", clientId)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }
}