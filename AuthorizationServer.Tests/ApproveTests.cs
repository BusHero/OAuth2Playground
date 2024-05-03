using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class ApproveTests(CustomFactory factory)
    : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    [Theory, AutoData]
    public async Task Approve_RequiredId_Redirect(
        Client client)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_RequiredId_ContainsCodeAndState(
        Client client)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
            .ContainKeys("code", "state");
    }

    [Theory, AutoData]
    public async Task Approve_NonExistingReqId_BadRequest(
        Client client,
        string requestId)
    {
        _clientRepository.AddClient(client);

        await _client
            .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_NonExistingReqId_ExpectedMessage(
        Client client,
        string requestId)
    {
        _clientRepository.AddClient(client);

        await _client
            .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_NoRequiredId_BadRequest(
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_NoApprove_RedirectsToSetupUri(
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_ResponseTypeIsNotCode_ReturnsError(
        Client client,
        string responseType)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_SendsBackStateDuringRegistration(
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .CreateAuthorizationEndpoint(client, state)
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
    public async Task Approve_NoApprove_Redirects(
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
                .CreateAuthorizationEndpoint(client)
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
    public async Task Approve_NoBody_InternalServerError()
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