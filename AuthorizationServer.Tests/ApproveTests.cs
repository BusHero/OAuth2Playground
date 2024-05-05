using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class ApproveTests
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    public ApproveTests(
        CustomAuthorizationServiceFactory authorizationServiceFactory)
    {
        var httpClient = authorizationServiceFactory.CreateDefaultClient();

        _client = new FlurlClient(httpClient);
        _clientRepository = authorizationServiceFactory.ClientRepository;
        _authenticator = new Authenticator(httpClient, _clientRepository);
    }

    private readonly FlurlClient _client;

    private readonly InMemoryClientRepository _clientRepository;

    private readonly Authenticator _authenticator;

    [Theory, AutoData]
    public async Task HappyPath_Redirect(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            requestId);

        result
            .StatusCode
            .Should()
            .Be(302);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsCode(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId,
            clientSecret,
            redirectUri);

        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            requestId);

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters()
            .Should()
            .ContainKey("code");
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsExpectedState(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);

        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator
            .PerformAuthorizationCodeRequest(requestId);

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters()
            .Should()
            .ContainKey("state")
            .WhoseValue
            .Should()
            .Be(state);
    }

    [Theory, AutoData]
    public async Task NonExistingReqId_BadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string requestId,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);

        await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator
            .PerformAuthorizationCodeRequest(requestId);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NonExistingReqId_ExpectedMessage(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string requestId,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);

        await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator
            .PerformAuthorizationCodeRequest(requestId);

        var result2 = await result.GetJsonAsync<Error>();

        result2
            .Errors
            .Should()
            .ContainKey("reqId");
    }

    [Theory, AutoData]
    public async Task NoRequiredId_BadRequest(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);

        await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            new Dictionary<string, string>
            {
                ["approve"] = "approve",
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Approve_Missing_RedirectToSetupUri(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);
        
        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            new Dictionary<string, string>
            {
                ["reqId"] = requestId,
            });

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetComponents(
                UriComponents.Host | UriComponents.Scheme | UriComponents.Path | UriComponents.Port,
                UriFormat.Unescaped)
            .Should()
            .BeEquivalentTo(redirectUri.ToString());
    }

    [Theory, AutoData]
    public async Task ResponseTypeIsNotCode_ReturnsError(
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

        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state,
            responseType: responseType);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            requestId);

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters()
            .Should()
            .ContainKey("error")
            .WhoseValue
            .Should()
            .Be("unsupported_response_type");
    }

    [Theory, AutoData]
    public async Task SendsBackStateDuringRegistration(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);

        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            requestId);

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters()
            .Should()
            .ContainKey("state")
            .WhoseValue
            .Should()
            .Be(state);
    }

    [Theory, AutoData]
    public async Task NoRedirects(
        string clientId,
        string clientSecret,
        Uri redirectUri,
        string state)
    {
        _clientRepository.AddClient(
            clientId, 
            clientSecret, 
            redirectUri);
        
        var requestId = await _authenticator.GetRequestId(
            clientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformAuthorizationCodeRequest(
            new Dictionary<string, string>
            {
                ["reqId"] = requestId,
            });

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetQueryParameters()
            .Should()
            .ContainKey("error")
            .WhoseValue
            .Should()
            .Be("access_denied");
    }

    [Fact]
    public async Task NoBody_InternalServerError()
    {
        var result = await _client
            .Request()
            .AppendPathSegment("approve")
            .WithAutoRedirect(false)
            .AllowAnyHttpStatus()
            .PostAsync();

        result
            .StatusCode
            .Should()
            .Be(500);
    }
}