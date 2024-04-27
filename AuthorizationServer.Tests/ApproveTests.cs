using AutoFixture.Xunit2;
using FluentAssertions;
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
    public async Task Approve_RequiredId_Ok(string requestId, string request)
    {
        _requestsRepository.Add(requestId, request);
        
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                new Dictionary<string, string>
                {
                    ["reqId"] = requestId,
                }.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task Approve_NonExistingReqId_BadRequest(string requestId)
    {
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                new Dictionary<string, string>
                {
                    ["reqId"] = requestId,
                }.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
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

    [Fact]
    public async Task Approve_NoRequiredId_BadRequest()
    {
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                new Dictionary<string, string>().CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
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