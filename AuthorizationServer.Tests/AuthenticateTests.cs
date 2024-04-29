using AutoFixture.Xunit2;
using FluentAssertions;
using FluentAssertions.Execution;
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
            .SendAsync(HttpMethod.Get);

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task Authenticate_ValidClientId_ReturnsCode(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SendAsync(HttpMethod.Get);

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
            .SendAsync(HttpMethod.Get);

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
            .SendAsync(HttpMethod.Get);

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
            .SendAsync(HttpMethod.Get);

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
            .SendAsync(HttpMethod.Get);

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
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }
}