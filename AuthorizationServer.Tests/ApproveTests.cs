using System.Text.Json.Serialization;
using AutoFixture.Xunit2;
using FluentAssertions;
using FluentAssertions.Execution;
using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class ApproveTests(CustomFactory factory)
    : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    private readonly InMemoryRequestsRepository _requestsRepository
        = factory.RequestsRepository;

    [Theory, AutoData]
    public async Task Approve_RequiredId_Redirect(
        Client client)
    {
        _clientRepository.AddClient(client);

        var response = await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(response.Code).CreateFormUrlEncodedContent());

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

        var response = await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(response.Code).CreateFormUrlEncodedContent());

        var query = result.ResponseMessage.Headers.Location!.GetComponents(UriComponents.Query, UriFormat.Unescaped);

        var parameters = query
            .Split('&')
            .Select(x => x.Split('='))
            .ToDictionary(x => x[0], x => x[1]);

        using (new AssertionScope())
        {
            parameters.Should().ContainKey("code");
            parameters.Should().ContainKey("state");
        }
    }

    [Theory, AutoData]
    public async Task Approve_NonExistingReqId_BadRequest(
        Client client,
        string requestId)
    {
        _clientRepository.AddClient(client);

        await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(requestId).CreateFormUrlEncodedContent());

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
        await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(requestId).CreateFormUrlEncodedContent());

        var result2 = await result.GetJsonAsync<Error>();

        result2.Errors.Should().ContainKey("reqId");
    }

    [Theory, AutoData]
    public async Task Approve_NoRequiredId_BadRequest(
        Client client)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();

        var data = GetApproveContent(response.Code);
        data.Remove("reqId");

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

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
        var response = await (await _client.CreateAuthorizationEndpoint(client).GetAsync()).GetJsonAsync<Response>();
        var data = GetApproveContent(response.Code);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

        var location = result.ResponseMessage.Headers.Location!;

        using (new AssertionScope())
        {
            location.Should().NotBeNull();
            location.GetComponents(
                    UriComponents.Host | UriComponents.Scheme | UriComponents.Path | UriComponents.Port,
                    UriFormat.Unescaped)
                .Should()
                .BeEquivalentTo(client.RedirectUris[0].ToString());
        }
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
            .GetAsync()).GetJsonAsync<Response>();
        var data = GetApproveContent(response.Code);

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

        var location = result.ResponseMessage.Headers.Location!;

        using (new AssertionScope())
        {
            location.Should().NotBeNull();
            var query = location.GetComponents(UriComponents.Query, UriFormat.Unescaped);
            var foo = query.Split("&");
            var arguments = foo[0].Split('=');
            arguments[0].Should().Be("error");
            arguments[1].Should().Be("unsupported_response_type");
        }
    }

    [Theory, AutoData]
    public async Task Approve_SendsBackStateDuringRegistration(
        Client client,
        string state)
    {
        _clientRepository.AddClient(client);
        var response = await (await _client
            .CreateAuthorizationEndpoint(client, state)
            .GetAsync()).GetJsonAsync<Response>();

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(response.Code).CreateFormUrlEncodedContent());

        var location = result.ResponseMessage.Headers.Location!;
        var dict = location
            .GetComponents(UriComponents.Query, UriFormat.Unescaped)
            .Split('&')
            .Select(x => x.Split('='))
            .ToDictionary(x => x[0], x => x[1]);

        dict
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
            .GetAsync()).GetJsonAsync<Response>();

        var data = GetApproveContent(response.Code);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

        var location = result.ResponseMessage.Headers.Location!;

        using (new AssertionScope())
        {
            result.StatusCode.Should().Be(302);
            location.Should().NotBeNull();
            var query = location.GetComponents(UriComponents.Query, UriFormat.Unescaped);
            var foo = query.Split("&");
            var arguments = foo[0].Split('=');
            arguments[0].Should().Be("error");
            arguments[1].Should().Be("access_denied");
        }
    }

    [Fact]
    public async Task Approve_NoBody_InternalServerError()
    {
        var result = await _client
            .Request()
            .AppendPathSegment("approve")
            .WithAutoRedirect(false)
            .AllowAnyHttpStatus()
            .SendAsync(HttpMethod.Post);

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