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
        var token = GetValidPayload()
            .CreateHmac256SignedToken("secret");

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
    public async Task NoAuthorization_Unauthorized()
    {
        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    [Theory, AutoData]
    public async Task InvalidScheme_Unauthorized(string scheme)
    {
        var token = GetValidPayload()
            .CreateHmac256SignedToken("secret");

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
        var token = GetValidPayload()
            .CreateHmac256SignedToken("secret");

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
        var token = GetValidPayload()
            .CreateHmac256SignedToken("secret");

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
        var token = GetValidPayload()
            .CreateHmac256SignedToken("secret");

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
        var token = GetValidPayload()
            .CreateUnsignedToken();

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
        var payload = GetValidPayload();

        payload["exp"] = DateTimeOffset
            .Now
            .AddMinutes(-1)
            .ToUnixTimeSeconds();

        var token = payload
            .CreateHmac256SignedToken("secret");

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
        var payload = GetValidPayload();
        payload["aud"] = "http://example.com";

        var token = payload
            .CreateHmac256SignedToken("secret");

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
        var payload = GetValidPayload();
        payload["iss"] = "http://example.com";

        var token = payload
            .CreateHmac256SignedToken("secret");

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
        var payload = GetValidPayload();
        payload["iat"] = DateTimeOffset
            .Now
            .AddMinutes(1)
            .ToUnixTimeSeconds();

        var token = payload.CreateHmac256SignedToken("secret");

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
    public async Task NoScope_Unauthorized()
    {
        var payload = GetValidPayload();
        payload.Remove("scope");

        var token = payload.CreateHmac256SignedToken("secret");

        _client.DefaultRequestHeaders.Authorization
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await _client
            .PostAsync("/resource", null);

        result
            .StatusCode
            .Should()
            .Be(HttpStatusCode.Unauthorized);
    }

    private static Dictionary<string, object> GetValidPayload() => new()
    {
        ["iss"] = "http://localhost:9001",
        ["sub"] = "alice",
        ["aud"] = "http://localhost:9002",
        ["iat"] = DateTimeOffset.Now.AddMinutes(-1).ToUnixTimeSeconds(),
        ["exp"] = DateTimeOffset.Now.AddMinutes(5).ToUnixTimeSeconds(),
        ["jti"] = Guid.NewGuid().ToString("N"),
        ["scope"] = "api1",
    };
}

public static class StringExtensions
{
    private static string ToBase64String(this byte[] bytes) 
        => Convert.ToBase64String(bytes);

    private static string ToBase64String(this string input) =>
        Encoding
            .UTF8
            .GetBytes(input)
            .ToBase64String();

    private static byte[] GetBytes(this string input, Encoding encoding) 
        => encoding.GetBytes(input);

    private static string ToBase64String(this object @object) =>
        JsonSerializer
            .Serialize(@object)
            .ToBase64String();

    public static string CreateHmac256SignedToken(
        this Dictionary<string, object> payload,
        string secret)
    {
        var header = new Dictionary<string, object>()
        {
            ["typ"] = "JWT",
            ["alg"] = "none",
        };

        var headerBase64 = header
            .ToBase64String();

        var payloadBase64 = payload
            .ToBase64String();

        var signature = HMACSHA256
            .HashData(
                secret.GetBytes(Encoding.ASCII),
                $"{headerBase64}.{payloadBase64}".GetBytes(Encoding.ASCII))
            .ToBase64String()
            .Replace("/", "_")
            .Replace("=", "");

        return $"{headerBase64}.{payloadBase64}.{signature}";
    }

    public static string CreateUnsignedToken(
        this Dictionary<string, object> payload)
    {
        var header = new Dictionary<string, object>()
        {
            ["typ"] = "JWT",
            ["alg"] = "none",
        };

        var headerBase64 = header
            .ToBase64String();

        var payloadBase64 = payload
            .ToBase64String();

        var token = $"{headerBase64}.{payloadBase64}.";

        return token;
    }
}