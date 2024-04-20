using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
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
    public async Task AuthorizationInHeader_Ok()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task NoAuthorization_Unauthroized()
    {
        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Theory, AutoData]
    public async Task InvalidScheme_Unauthrorized(string scheme)
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");
        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue(scheme, token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TokenInBody_Ok()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>("access_token", token)
            ]));

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.OK);
    }

    [Theory, AutoData]
    public async Task NoTokenInBody_Unauthorized(string otherName)
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");
        var result = await _client
            .PostAsync("/resource", new FormUrlEncodedContent([
                new KeyValuePair<string, string>(otherName, token)
            ]));

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task TokenInQueryParameters_Ok()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        var result = await _client
            .PostAsync($"/resource?access_token={token}", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.OK);
    }


    [Fact]
    public async Task UnsignedToken_Unauthorized()
    {
        var token = GetToken();

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ExpiredToken_Unauthorized()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(-1).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task WrongAudience_Unauthorized()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://example.com",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task WrongIssuer_Unauthorized()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://example.com",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task IssuedAtInTheFuture_Unauthorized()
    {
        var token = GetHmac256SignedToken(new Dictionary<string, object>
        {
            ["iss"] = "http://localhost:9001",
            ["sub"] = "alice",
            ["aud"] = "http://localhost:9002",
            ["iat"] = DateTimeOffset.Now.AddMinutes(1).ToUnixTimeSeconds(),
            ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
            ["jti"] = Guid.NewGuid().ToString("N"),
        }, "secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    private static string GetHmac256SignedToken(
        Dictionary<string, object> payload,
        string secret)
    {
        var payloadAsJson = JsonSerializer.Serialize(payload);
        var headerAsJson = JsonSerializer.Serialize(new
        {
            typ = "JWT",
            alg = "HS256",
        });

        var headerBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(headerAsJson));
        var payloadBase64 = Convert.ToBase64String(Encoding.ASCII.GetBytes(payloadAsJson));
        var dataToSign = $"{headerBase64}.{payloadBase64}";

        var encryptedData = HMACSHA256
            .HashData(
                Encoding.ASCII.GetBytes(secret),
                Encoding.ASCII.GetBytes(dataToSign));

        var signature = Convert.ToBase64String(encryptedData).Replace("/", "_").Replace("=", "");

        return $"{headerBase64}.{payloadBase64}.{signature}";
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