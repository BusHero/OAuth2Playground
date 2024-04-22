using AutoFixture.Xunit2;
using Microsoft.AspNetCore.Mvc.Testing;
using FluentAssertions;
using FluentAssertions.Execution;
using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthorizationServer.Tests;

public sealed class AuthenticateTests(
    CustomFactory factory) : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    [Theory, AutoData]
    public async Task Authenticate_ClientId_Ok(
        Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SendAsync(HttpMethod.Get);

        result.StatusCode.Should().Be(200);
    }

    [Theory, AutoData]
    public async Task Authenticate_NoClientId_BadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("client_id")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_WrongClientId_BadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("client_id", "another_client")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_NoRedirectUri_BadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .RemoveQueryParam("redirect_uri")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task Authenticate_WrongRedirectUri_BadRequest(Client oauthClient)
    {
        _clientRepository.AddClient(oauthClient);

        var result = await _client
            .CreateAuthorizationEndpoint(oauthClient)
            .SetQueryParam("redirect_uri", "http://example.com")
            .SendAsync(HttpMethod.Get);

        result.StatusCode
            .Should()
            .Be(400);
    }
}

public class ApproveTests(CustomFactory factory)
    : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

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

public static class Extensions
{
    public static HttpContent CreateFormUrlEncodedContent(
        this IEnumerable<KeyValuePair<string, string>> body)
        => new FormUrlEncodedContent(body);

    public static IFlurlRequest CreateApproveEndpoint(this IFlurlClient client)
        => client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve");

    public static IFlurlRequest CreateAuthorizationEndpoint(
        this IFlurlClient client,
        Client oauthClient) =>
        client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("client_id", oauthClient.ClientId);
}

public sealed class CustomFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.RemoveAll(typeof(IClientRepository));
            services.AddSingleton<IClientRepository>(_ => ClientRepository);
        });
    }

    public InMemoryClientRepository ClientRepository { get; } = new();
}