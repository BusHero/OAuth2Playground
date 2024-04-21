using Microsoft.AspNetCore.Mvc.Testing;
using FluentAssertions;
using FluentAssertions.Execution;
using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class AuthTests(
    WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly FlurlClient _client =
        new(factory.CreateDefaultClient());

    [Fact]
    public async Task Authenticate_ClientId_Ok()
    {
        var result = await _client
            .CreateAuthorizationEndpoint()
            .SendAsync(HttpMethod.Get);

        result.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task Authenticate_NoClientId_BadRequest()
    {
        var result = await _client
            .CreateAuthorizationEndpoint()
            .RemoveQueryParam("client_id")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Authenticate_WrongClientId_BadRequest()
    {
        var result = await _client
            .CreateAuthorizationEndpoint()
            .SetQueryParam("client_id", "another_client")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Authenticate_NoRedirectUri_BadRequest()
    {
        var result = await _client
            .CreateAuthorizationEndpoint()
            .RemoveQueryParam("redirect_uri")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task Authenticate_WrongRedirectUri_BadRequest()
    {
        var result = await _client
            .CreateAuthorizationEndpoint()
            .SetQueryParam("redirect_uri", "http://example.com")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

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

            result
                .ResponseMessage
                .Headers
                .Location
                .Should()
                .Be("http://localhost:9000/callback?error=unsupported_response_type");
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

public static class Foo
{
    public static HttpContent CreateFormUrlEncodedContent(
        this IEnumerable<KeyValuePair<string, string>> body)
        => new FormUrlEncodedContent(body);

    public static IFlurlRequest CreateApproveEndpoint(this IFlurlClient client)
        => client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve");

    public static IFlurlRequest CreateAuthorizationEndpoint(this IFlurlClient client) =>
        client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("redirect_uri", "http://localhost:9000/callback")
            .AppendQueryParam("client_id", "oauth-client-1");
}

public class AnotherTestClass : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;

    public AnotherTestClass(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task Foo()
    {
        var client = _factory.CreateDefaultClient();
        var flurlClient = new FlurlClient(client);

        var body = new Dictionary<string, string>
        {
            ["approve"] = true.ToString(),
            ["response_type"] = "code",
        }.CreateFormUrlEncodedContent();

        var result = await flurlClient.Request()
            .AppendPathSegment("approve")
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .PostAsync(body);

        result.StatusCode.Should().Be(302);
        result.ResponseMessage.Headers.Location.Should().Be("http://localhost:9000/callback");
    }
}