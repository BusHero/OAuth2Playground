namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory) : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient(),
        authorizationServiceFactory.ClientRepository);

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

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
            redirectUri: redirectUri,
            state: state,
            responseType: responseType);

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

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
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

        var result = await _authenticator.PerformAuthorizationRequest(
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

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
            state: state,
            responseType: responseType);

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

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
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
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
            redirectUri: redirectUri,
            state: state,
            responseType: null);

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

        var result = await _authenticator.PerformAuthorizationRequest(
            clientId: clientId,
            redirectUri: redirectUri,
            responseType: responseType);

        result
            .StatusCode
            .Should()
            .Be(200);
    }
}