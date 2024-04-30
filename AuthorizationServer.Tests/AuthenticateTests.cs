using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomFactory factory) : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    [Theory, AutoData]
    public async Task Authenticate_ValidClientId_ReturnsOk(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .GetAsync();

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task Authenticate_ValidClientId_ReturnsCode(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .GetAsync();

        var code = await result.GetStringAsync();
        code.Should().NotBeNullOrEmpty();
    }

    [Theory, AutoData]
    public async Task Authenticate_NoClientId_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("client_id")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_WrongClientId_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("client_id", "another_client")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_NoRedirectUri_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("redirect_uri")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_WrongRedirectUri_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("redirect_uri", "http://example.com")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_NoResponseType_ReturnsBadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("response_type")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_NoState_Ok(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("state")
            .GetAsync();

        result.StatusCode
            .Should()
            .Be(200);
    }
}