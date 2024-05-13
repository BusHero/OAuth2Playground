namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient());

    [Theory, AutoData]
    public async Task HappyPath_ReturnsOk(
        Uri redirectUri,
        string responseType,
        string state,
        string scope)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = scope,
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: scope,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsRequestId(
        Uri redirectUri,
        string responseType,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            responseType: responseType);

        var code = await result.GetStringAsync();

        code
            .Should()
            .NotBeNullOrEmpty();
    }

    [Theory, AutoData]
    public async Task ClientId_Missing_ReturnsBadRequest(
        Uri redirectUri,
        string responseType,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: null,
            redirectUri: redirectUri,
            state: state,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ClientId_Invalid_ReturnsBadRequest(
        Uri redirectUri,
        string responseType,
        string invalidClientId,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: invalidClientId,
            redirectUri: redirectUri,
            state: state,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RedirectUri_Missing_ReturnsBadRequest(
        Uri redirectUri,
        string responseType,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            state: state,
            redirectUri: null,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RedirectUri_InvalidRedirectUri_ReturnsBadRequest(
        Uri redirectUri,
        string state,
        string responseType,
        Uri invalidRedirectUri)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: invalidRedirectUri,
            state: state,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task ResponseType_Missing_ReturnsBadRequest(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            responseType: null);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task WrongScope_Returns400(
        Uri redirectUri,
        string responseType,
        string state,
        string scope,
        string wrongScope)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = scope,
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            responseType: responseType,
            scope: wrongScope);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task TwoScopes_RequestFirstScope_Returns200(
        Uri redirectUri,
        string responseType,
        string state,
        string scope1,
        string scope2)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = $"{scope1} {scope2}",
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: scope1,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task TwoScopes_RequestSecondScope_Returns200(
        Uri redirectUri,
        string responseType,
        string state,
        string scope1,
        string scope2)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = $"{scope1} {scope2}",
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: scope2,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task TwoScopes_RequestBothScopes_Returns200(
        Uri redirectUri,
        string responseType,
        string state,
        string scope1,
        string scope2)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = $"{scope1} {scope2}",
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: [scope2, scope1],
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task TwoScopes_ValidAndInvalid_Returns400(
        Uri redirectUri,
        string responseType,
        string state,
        string scope1,
        string scope2,
        string invalidScope)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
            Scope = $"{scope1} {scope2}",
        });

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: [scope2, invalidScope],
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(400);
    }
}