using AutoFixture.Xunit2;
using FluentAssertions;
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

    [Theory, AutoData]
    public async Task Approve_RequiredId_Ok(
        string requestId,
        string request)
    {
        _requestsRepository.Add(requestId, request);

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(requestId).CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, AutoData]
    public async Task Approve_NonExistingReqId_BadRequest(
        string requestId)
    {
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
        string requestId)
    {
        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                GetApproveContent(requestId).CreateFormUrlEncodedContent());

        var result2 = await result.GetJsonAsync<Error>();

        result2.Errors.Should().ContainKey("reqId");
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

    [Theory, AutoData]
    public async Task Approve_NoRequiredId_BadRequest(
        string requestId)
    {
        var data = GetApproveContent(requestId);
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
    public async Task Approve_NoApprove_Ok(
        string requestId,
        string request)
    {
        _requestsRepository.Add(requestId, request);
        var data = GetApproveContent(requestId);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(302);
    }
    
    [Theory, AutoData]
    public async Task Approve_NoApprove_Redirects(
        string requestId,
        Uri request)
    {
        _requestsRepository.Add(requestId, request.ToString());
        var data = GetApproveContent(requestId);
        data.Remove("approve");

        var result = await _client
            .CreateApproveEndpoint()
            .WithAutoRedirect(false)
            .SendAsync(
                HttpMethod.Post,
                data.CreateFormUrlEncodedContent());

        result.ResponseMessage.Headers.Location
            .Should()
            .Be(request);
    }

    private static Dictionary<string, string> GetApproveContent(
        string requestId)
    {
        return new Dictionary<string, string>
        {
            ["reqId"] = requestId,
            ["approve"] = "code",
        };
    }
}

public sealed class Error
{
    public string Title { get; init; } = null!;

    public int Status { get; init; }

    public Dictionary<string, string[]> Errors { get; init; } = null!;
}