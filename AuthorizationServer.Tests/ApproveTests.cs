using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class ApproveTests(CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly FlurlClient _client
        = new(authorizationServiceFactory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = authorizationServiceFactory.ClientRepository;

    [Theory, AutoData]
    public async Task HappyPath_Redirect(
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(GetApproveContent(response.Code));

        result
            .StatusCode
            .Should()
            .Be(302);
    }

    [Theory, AutoData]
    public async Task HappyPath_ReturnsCode(
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(GetApproveContent(response.Code));

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
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(GetApproveContent(response.Code));

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
        Client client,
        string requestId,
        string state)
    {
        _clientRepository.AddClient(client);

        await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", client.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", client.ClientId)
            .GetAsync();

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(GetApproveContent(requestId));

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NonExistingReqId_ExpectedMessage(
        Client client,
        string requestId)
    {
        _clientRepository.AddClient(client);

        await _client
            .Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", client.RedirectUris[0])
            .AppendQueryParam("state", "")
            .AppendQueryParam("client_id", client.ClientId)
            .GetAsync();

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(GetApproveContent(requestId));

        var result2 = await result.GetJsonAsync<Error>();

        result2
            .Errors
            .Should()
            .ContainKey("reqId");
    }

    [Theory, AutoData]
    public async Task NoRequiredId_BadRequest(
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", "")
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var data = GetApproveContent(response.Code);
        data.Remove("reqId");

        var result = await _client
            .CreateApproveEndpoint()
            .PostUrlEncodedAsync(data);

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task NoRedirectsToSetupUri(
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var data = GetApproveContent(response.Code);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .PostUrlEncodedAsync(data);

        result
            .ResponseMessage
            .Headers
            .Location!
            .GetComponents(
                UriComponents.Host | UriComponents.Scheme | UriComponents.Path | UriComponents.Port,
                UriFormat.Unescaped)
            .Should()
            .BeEquivalentTo(client.RedirectUris[0].ToString());
    }

    [Theory, AutoData]
    public async Task ResponseTypeIsNotCode_ReturnsError(
        Client client,
        string responseType,
        string state)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .AppendQueryParam("response_type", responseType)
                .GetAsync())
            .GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .PostUrlEncodedAsync(GetApproveContent(response.Code));

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
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", state)
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .PostUrlEncodedAsync(GetApproveContent(response.Code));

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
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .Request()
                .AllowAnyHttpStatus()
                .WithAutoRedirect(false)
                .AppendPathSegment("authorize")
                .AppendQueryParam("response_type", "code")
                .AppendQueryParam("redirect_uri", client.RedirectUris[0])
                .AppendQueryParam("state", "")
                .AppendQueryParam("client_id", client.ClientId)
                .GetAsync())
            .GetJsonAsync<Response>();

        var data = GetApproveContent(response.Code);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .PostUrlEncodedAsync(data);

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

    private static Dictionary<string, string> GetApproveContent(
        string requestId)
    {
        return new Dictionary<string, string>
        {
            ["reqId"] = requestId,
            ["approve"] = "approve",
        };
    }
}