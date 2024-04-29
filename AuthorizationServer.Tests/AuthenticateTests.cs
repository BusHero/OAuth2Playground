using AutoFixture.Xunit2;
using FluentAssertions;
using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomFactory factory) : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    private readonly InMemoryRequestsRepository _requestsRepository
        = factory.RequestsRepository;

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
    public async Task Authenticate_ValidClient_AddsQueryToRequestsRepository(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);
        _requestsRepository.Clear();
        
        var uri = _client
            .CreateAuthorizationEndpoint(oauthClient);
        var query = uri.Url.Query;
        
        await uri
            .SendAsync(HttpMethod.Get);

        _requestsRepository
            .Requests
            .Values
            .Should()
            .ContainEquivalentOf(new
            {
                RedirectUri = oauthClient.RedirectUris.First(),
                ClientId = oauthClient.ClientId,
            });
    }

    [Theory, AutoData]
    public async Task Authenticate_NoClientId_DoesntAddRequestToRequestsRepository(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);
        _requestsRepository.Clear();

        await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("client_id")
            .SendAsync(HttpMethod.Get);

        _requestsRepository.Requests.Should().BeEmpty();
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
    public async Task Authenticate_WrongClientId_DoesntAddQueryToRequestsRepository(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);
        _requestsRepository.Clear();

        await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("client_id", "another_client")
            .SendAsync(HttpMethod.Get);

        _requestsRepository
            .Requests
            .Should()
            .BeEmpty();
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
}