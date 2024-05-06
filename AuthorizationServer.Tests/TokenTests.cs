using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using FluentAssertions.Execution;

namespace AuthorizationServer.Tests;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Local")]
public sealed class TokenTests(CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient(),
        authorizationServiceFactory.ClientRepository);

    private readonly InMemoryClientRepository _clientRepository
        = authorizationServiceFactory.ClientRepository;

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
        string clientId,
        string clientSecret,
        string state,
        Uri redirectUri)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsToken(
        string clientId,
        string clientSecret,
        string state,
        Uri redirectUri)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            code);

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
        string rightClientId,
        string rightClientSecret,
        Uri rightRedirectUri,
        string wrongClientId,
        string wrongClientSecret,
        Uri wrongRedirectUri,
        string state)
    {
        _clientRepository.AddClient(rightClientId, rightClientSecret, rightRedirectUri);
        _clientRepository.AddClient(wrongClientId, wrongClientSecret, wrongRedirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            rightClientId,
            rightRedirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            wrongClientId,
            wrongClientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task InvalidCode_Returns400(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state,
        string invalidCode)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            invalidCode);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task MissingCode_Returns400(
        string clientId,
        string clientSecret,
        Uri redirectUri)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task MissingGrantType_Returns400(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            new Dictionary<string, string>
            {
                ["code"] = code,
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task GrantTypeIsNotAuthorizationCode_Returns400(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string grantType,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            grantType,
            code);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task WrongClientId_Returns401(
        string clientId,
        string clientSecret,
        string wrongClientId,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            wrongClientId,
            clientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task WrongSecret_Returns401(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state,
        string wrongSecret)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            wrongSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task NoCredentials_Return401(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            code);

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task CredentialsInBody_Returns200(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            new Dictionary<string, string>
            {
                ["client"] = clientId,
                ["secret"] = clientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task SameCredentialsInHeaderAndBody_Returns401(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId,
            clientSecret,
            new Dictionary<string, string>
            {
                ["client"] = clientId,
                ["secret"] = clientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task WrongAuthenticationScheme_Returns400(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string scheme,
        string parameter,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var code = await _authenticator.GetAuthorizationCode(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            new AuthenticationHeaderValue(scheme, parameter),
            code);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task DifferentCredentialsInHeaderAndBody_Returns401(
        string clientId1,
        string clientSecret1,
        Uri redirectUri1,
        string clientId2,
        string clientSecret2,
        Uri redirectUri2,
        string state)
    {
        _clientRepository.AddClient(
            clientId1,
            clientSecret1,
            redirectUri1);

        _clientRepository.AddClient(
            clientId2,
            clientSecret2,
            redirectUri2);

        var code = await _authenticator.GetAuthorizationCode(
            clientId1,
            redirectUri1,
            state);

        var result = await _authenticator.PerformTokenRequest(
            clientId1,
            clientSecret1,
            new Dictionary<string, string>()
            {
                ["client"] = clientId2,
                ["secret"] = clientSecret2,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result
            .StatusCode
            .Should()
            .Be(401);
    }
}