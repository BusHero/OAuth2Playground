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
        _authenticator = new Authenticator(
            httpClient);
    }

    private readonly FlurlClient _client;

    private readonly Authenticator _authenticator;

    [Theory, AutoData]
    public async Task HappyPath_Returns302(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var requestId = await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformApproveRequest(
            requestId);

        result
            .StatusCode
            .Should()
            .Be(302);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsCode(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var requestId = await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformApproveRequest(
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
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });
        
        var response = await _authenticator.PerformAuthorizationRequest(
            clientId: client.ClientId,
            redirectUri: redirectUri,
            state: state,
            scope: default(string),
            responseType: "code");

        var token = await AntiForgeryTokenExtractor
            .ExtractAntiForgeryValues(response.ResponseMessage);

        var result = await _authenticator
            .PerformApproveRequest(token, "approve");

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
    public async Task RequestId_Invalid_Returns400(
        Uri redirectUri,
        string requestId,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator
            .PerformApproveRequest(requestId);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task RequestId_Invalid_ReturnsExpectedMessage(
        Uri redirectUri,
        string requestId,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator
            .PerformApproveRequest(requestId);

        var result2 = await result.GetJsonAsync<Error>();

        result2
            .Errors
            .Should()
            .ContainKey("reqId");
    }

    [Theory, AutoData]
    public async Task RequestId_Missing_Returns400(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformApproveRequest(
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
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var requestId = await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformApproveRequest(
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
    public async Task ResponseType_Invalid_ReturnsExpectedErrorMessage(
        Uri redirectUri,
        string responseType,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var requestId = await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state,
            responseType: responseType);

        var result = await _authenticator.PerformApproveRequest(
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
    public async Task Approve_Missing_ReturnsExpectedErrorMessage(
        Uri redirectUri,
        string state)
    {
        var client = await _authenticator.RegisterClient(RegisterRequest.Valid with
        {
            RedirectUris = [redirectUri],
        });

        var requestId = await _authenticator.GetRequestId(
            client.ClientId,
            redirectUri,
            state);

        var result = await _authenticator.PerformApproveRequest(
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
    public async Task NoBody_Returns500()
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