using System.Diagnostics.CodeAnalysis;
using Flurl.Http;

namespace AuthorizationServer.Tests;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Local")]
public sealed class TokenTests(CustomFactory factory)
    : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
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

        result.StatusCode.Should().Be(200);
    }
    
    [Theory, AutoData]
    public async Task MissingGrantType_Returns400(
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
                ["grant_type1"] = "authorization_code",
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task GrantTypeIsNotAuthorizationCode_Returns400(
        Client client,
        string authorizationCode)
    {
        _clientRepository.AddClient(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, client.ClientSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = authorizationCode,
            });

        result.StatusCode.Should().Be(400);
    }

    [Theory, AutoData]
    public async Task WrongClient_Returns401(
        string client,
        string secret)
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client, secret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task WrongSecret_Returns401(
        Client client,
        string wrongSecret)
    {
        _clientRepository.AddClient(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client.ClientId, wrongSecret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(401);
    }

    [Fact]
    public async Task NoCredentials_Return401()
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task CredentialsInBody_Returns200(
        Client client)
    {
        _clientRepository.AddClient(client);

        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task SameCredentialsInHeaderAndBody_Returns401(
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
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
                ["grant_type"] = "authorization_code",
            });

        result.StatusCode.Should().Be(401);
    }

    [Theory, AutoData]
    public async Task DifferentCredentialsInHeaderAndBody_Returns401(
        Client client1,
        Client client2)
    {
        _clientRepository.AddClient(client1);
        _clientRepository.AddClient(client2);

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
            });

        result.StatusCode.Should().Be(401);
    }
}