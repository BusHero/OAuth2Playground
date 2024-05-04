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
    public async Task ValidClientId_ReturnsOk(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task ValidClientId_ReturnsCode(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .GetAsync();

        var code = await result.GetStringAsync();

        code
            .Should()
            .NotBeNullOrEmpty();
    }

    [Theory, AutoData]
    public async Task NoClientId_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("client_id")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task WrongClientId_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("client_id", "another_client")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NoRedirectUri_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("redirect_uri")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task WrongRedirectUri_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("redirect_uri", "http://example.com")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NoResponseType_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("response_type")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NoState_ReturnsOk(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("state")
            .GetAsync();

        result
            .StatusCode
            .Should()
            .Be(200);
    }
}