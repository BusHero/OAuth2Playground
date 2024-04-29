using AutoFixture.Xunit2;
using FluentAssertions;
using FluentAssertions.Execution;
using FluentAssertions.Primitives;
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
        string clientId,
        Uri request)
    {
        _requestsRepository.Add(requestId, clientId, request);

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
        string clientId,
        Uri redirectUri)
    {
        _requestsRepository.Add(requestId, clientId, redirectUri);
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
    public async Task Approve_NoApprove_RedirectsToSetupUri(
        string requestId,
        string clientId,
        Uri request)
    {
        _requestsRepository.Add(requestId, clientId, request);
        var data = GetApproveContent(requestId);
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
                .BeEquivalentTo(request.ToString());
        }
    }

    [Theory, AutoData]
    public async Task Approve_ResponseTypeIsNotCode_ReturnsError(
        string requestId,
        string clientId,
        Uri request)
    {
        _requestsRepository.Add(requestId, clientId, request);
        var data = GetApproveContent(requestId);
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
            var query = location.GetComponents(UriComponents.Query, UriFormat.Unescaped);
            var foo = query.Split("&");
            var arguments = foo[0].Split('=');
            arguments[0].Should().Be("error");
            arguments[1].Should().Be("unsupported_response_type");
        }
    }

    [Theory, AutoData]
    public async Task Approve_NoApprove_Redirects(
        string requestId,
        string clientId,
        Uri request)
    {
        _requestsRepository.Add(requestId, clientId, request);
        var data = GetApproveContent(requestId);
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
            var query = location.GetComponents(UriComponents.Query, UriFormat.Unescaped);
            var foo = query.Split("&");
            var arguments = foo[0].Split('=');
            arguments[0].Should().Be("error");
            arguments[1].Should().Be("access_denied");
        }
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

public sealed class Error
{
    public string Title { get; init; } = null!;

    public int Status { get; init; }

    public Dictionary<string, string[]> Errors { get; init; } = null!;
}

public static class UriExtensions
{
    public static UriAssertions Should(this Uri? uri)
    {
        return new UriAssertions(uri);
    }
}

public sealed class UriAssertions(Uri? uri)
    : ReferenceTypeAssertions<Uri?, UriAssertions>(uri)
{
    private readonly Uri? _uri = uri;

    protected override string Identifier => "uri";

    public AndConstraint<UriAssertions> HaveHost(
        string host,
        string because = "")
    {
        Execute.Assertion
            .BecauseOf(because)
            .ForCondition(_uri is not null)
            .FailWith("You can't assert a uri if it is null {reason}")
            .Then
            .ForCondition(_uri!.Host == host)
            .FailWith("Expected host to contain {0}{reason}, but found {1}",
                host,
                _uri!.Host);

        return new AndConstraint<UriAssertions>(this);
    }
}