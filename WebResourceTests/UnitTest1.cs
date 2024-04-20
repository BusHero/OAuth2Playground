using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using AutoFixture.Xunit2;
using Microsoft.AspNetCore.Mvc.Testing;

namespace WebResourceTests;

public class UnitTest1(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly HttpClient _client = factory.CreateDefaultClient();

    [Fact]
    public async Task RightAuthorizationSchemeReturnsToken()
    {
        var token = GetToken();
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .Be(token);
    }

    [Fact]
    public async Task NoAuthHeaderReturnsNull()
    {
        var result = await _client
            .PostAsync("/resource", null);

        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .BeNull();
    }

    [Theory, AutoData]
    public async Task InvalidAuthReturnsNull(string scheme)
    {
        var token = GetToken();
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue(scheme, null);

        var result = await _client
            .PostAsync("/resource", null);

        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .BeNull();
    }

    [Theory, AutoData]
    public async Task WrongAuthSchemeReturnsNull(string scheme)
    {
        var token = GetToken();
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue(scheme, token);

        var result = await _client
            .PostAsync("/resource", null);

        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .BeNull();
    }

    [Fact]
    public async Task GetTokenFromBody()
    {
        var token = GetToken();
        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>("access_token", token)
            ]));

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .Be(token);
    }

    [Theory, AutoData]
    public async Task NoTokenInBodyReturnsNull(string otherName)
    {
        var token = GetToken();
        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>(otherName, token)
            ]));

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .BeNull();
    }

    [Fact]
    public async Task GetTokenFromQueryParameters()
    {
        var token = GetToken();

        var result = await _client
            .PostAsync($"/resource?access_token={token}", null);

        var body = await result.Content.ReadAsStringAsync();
        var content = await result.Content.ReadFromJsonAsync<Content>();

        content!
            .Token
            .Should()
            .Be(token);
    }

    [Fact]
    public async Task JwtToken()
    {
        var token = GetToken(
            issuer: "http://localhost:9001");
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        var content = await result.Content.ReadFromJsonAsync<BearerToken>();

        content!
            .Content!
            .Issuer
            .Should()
            .Be("http://localhost:9001");
    }

    private static string GetToken(
        string? issuer = default)
    {
        var header =
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(new
                    {
                        typ = "JWT",
                        alg = "none",
                    })));
        var payload =
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(new
                    {
                        iss = issuer ?? "http://localhost:9001",
                        sub = "alice",
                        aud = "http://localhost:9002/",
                        iat = DateTimeOffset.Now.ToUnixTimeSeconds(),
                        exp = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
                        jti = Guid.NewGuid().ToString("N"),
                    })));

        var token = $"{header}.{payload}.";

        return token;
    }
}

internal class Content
{
    public BearerToken BearerToken { get; set; } = null!;
    
    public string? Token { get; set; }
}