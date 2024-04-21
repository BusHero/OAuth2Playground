using Microsoft.AspNetCore.Mvc.Testing;
using FluentAssertions;
using Flurl.Http;
using Flurl.Http.Testing;

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
    public async Task Approve_NoResponseType_BadRequest()
    {
        var body = GetApproveContent();
        body.Remove("response_type");

        var result = await _client
            .CreateApproveEndpoint()
            .SendAsync(HttpMethod.Post, body.CreateFormUrlEncodedContent());

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    // [Fact]
    // public async Task Approve_WrongResponseType_BadRequest()
    // {
    //     var body = GetApproveContent();
    //     body["response_type"] = "some-other-response-type";
    //
    //     var result = await _client
    //         .CreateApproveEndpoint()
    //         .SendAsync(HttpMethod.Post, body.CreateFormUrlEncodedContent());
    //
    //     result
    //         .StatusCode
    //         .Should()
    //         .Be(400);
    // }

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
            .AppendPathSegment("approve");

    public static IFlurlRequest CreateAuthorizationEndpoint(this IFlurlClient client) =>
        client.Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("authorize")
            .AppendQueryParam("redirect_uri", "http://localhost:9000/callback")
            .AppendQueryParam("client_id", "oauth-client-1");
}