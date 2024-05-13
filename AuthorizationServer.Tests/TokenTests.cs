using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using FluentAssertions.Execution;

namespace AuthorizationServer.Tests;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Local")]
public sealed class TokenTests(CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient());

    [Theory, AutoData]
    public async Task HappyPath_Returns200(
        string state,
        Uri redirectUri)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsToken(
        string state,
        Uri redirectUri)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
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
        Uri rightRedirectUri,
        Uri wrongRedirectUri,
        string state)
    {
        var rightClient = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [rightRedirectUri],
            });
        var wrongClient = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [wrongRedirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            rightClient.ClientId,
            rightRedirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            wrongClient.ClientId,
            wrongClient.ClientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task InvalidCode_Returns400(
        Uri redirectUri,
        string state,
        string invalidCode)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
            invalidCode);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task MissingCode_Returns400(
        Uri redirectUri)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
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
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
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
        Uri redirectUri,
        string grantType,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
            grantType,
            code);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task WrongClientId_Returns401(
        string wrongClientId,
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            wrongClientId,
            client.ClientSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task WrongSecret_Returns401(
        Uri redirectUri,
        string state,
        string wrongSecret)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            wrongSecret,
            code);

        result
            .StatusCode
            .Should()
            .Be(401);
    }

    [Theory, AutoData]
    public async Task NoCredentials_Return401(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
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
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            new Dictionary<string, string>
            {
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
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
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client.ClientId,
            client.ClientSecret,
            new Dictionary<string, string>
            {
                ["client"] = client.ClientId,
                ["secret"] = client.ClientSecret,
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
        Uri redirectUri,
        string scheme,
        string parameter,
        string state)
    {
        var client = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client.ClientId,
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
        Uri redirectUri1,
        Uri redirectUri2,
        string state)
    {
        var client1 = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri1],
            });
        var client2 = await _authenticator
            .RegisterClient(RegisterRequest.Valid with
            {
                RedirectUris = [redirectUri2],
            });

        var code = await _authenticator.GetAuthorizationCode(
            client1.ClientId,
            redirectUri1,
            state);

        var result = await _authenticator.PerformTokenRequest(
            client1.ClientId,
            client1.ClientSecret,
            new Dictionary<string, string>()
            {
                ["client"] = client2.ClientId,
                ["secret"] = client2.ClientSecret,
                ["grant_type"] = "authorization_code",
                ["code"] = code,
            });

        result
            .StatusCode
            .Should()
            .Be(401);
    }
}