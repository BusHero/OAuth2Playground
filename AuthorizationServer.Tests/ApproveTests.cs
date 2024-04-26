using FluentAssertions;
using FluentAssertions.Execution;
using Flurl;
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
    
    [Fact]
    public async Task Approve_Ok()
    {
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent().CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Fact]
    public async Task Approve_NoApproveField_BadRequest()
    {
        var body = GetApproveContent();
        body.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(HttpMethod.Post, body.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Approve_NoApproval_BadRequest()
    {
        var body = GetApproveContent();
        body["approve"] = "false";

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(HttpMethod.Post, body.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Approve_NoBoolean_BadRequest()
    {
        var body = GetApproveContent();
        body["approve"] = "asdasd";

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(HttpMethod.Post, body.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Approve_WrongResponseType_RedirectsToExpectedUri()
    {
        var body = GetApproveContent();
        body["response_type"] = "something-else";

        var result = await _client
            .CreateApproveEndpoint()
            .PostAsync(body.CreateFormUrlEncodedContent());

        using (new AssertionScope())
        {
            result
                .StatusCode
                .Should()
                .Be(302);

            var redirectUri = "http://localhost:9000"
                .AppendPathSegment("callback")
                .AppendQueryParam("error", "unsupported_response_type")
                .ToUri();

            result
                .ResponseMessage
                .Headers
                .Location
                .Should()
                .Be(redirectUri);
        }
    }

    private Dictionary<string, string> GetApproveContent()
    {
        return new Dictionary<string, string>()
        {
            ["approve"] = "true",
            ["response_type"] = "code",
        };
    }
}