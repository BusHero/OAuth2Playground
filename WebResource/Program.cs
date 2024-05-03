using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication2;

public partial class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();
        builder.Services.AddLogging();
        builder.Services.AddSingleton<TokenExtractor>();

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.MapPost("/resource", GetResource);

        app.MapGet("/resource2", () => Results.Ok());

        app.Run();
    }

    private static async Task<IResult> GetResource([FromServices] TokenExtractor extractor, HttpContext context)
    {
        var token = await extractor.GetBearerToken(context);
        var isTokenValid = IsTokenValid(token);
        return isTokenValid
            ? Results.Ok(new { Message = "Hello, World!", })
            : Results.Unauthorized();
    }

    private static bool IsTokenValid(string? token)
    {
        if (string.IsNullOrEmpty(token))
        {
            return false;
        }

        var parts = token.Split('.');

        if (parts.Length != 3)
        {
            return false;
        }

        if (string.IsNullOrEmpty(parts[2]))
        {
            return false;
        }

        var verified = HMACSHA256
            .HashData(
                Encoding.ASCII.GetBytes("secret"),
                Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}"));

        var signature = Convert
            .ToBase64String(verified)
            .Replace("/", "_")
            .Replace("=", "");

        if (signature != parts[2])
        {
            return false;
        }

        var payloadAsJson = parts[1].FromBase64();

        var payload = JsonDocument.Parse(payloadAsJson)
            .RootElement;

        if (payload.GetProperty("iss").GetString() != "http://localhost:9001")
        {
            return false;
        }

        if (!payload.GetProperty("aud").GetString()!.Contains("http://localhost:9002"))
        {
            return false;
        }

        var issuedAt = payload
            .GetProperty("iat")
            .GetInt64();

        var now = DateTimeOffset.Now.ToUnixTimeSeconds();
        if (now < issuedAt)
        {
            return false;
        }

        var expireAt = payload
            .GetProperty("exp")
            .GetInt64();

        if (expireAt < now)
        {
            return false;
        }

        if (!payload.TryGetProperty("scope", out var scopeProperty))
        {
            return false;
        }

        var scope = scopeProperty.GetString();

        if (string.IsNullOrEmpty(scope))
        {
            return false;
        }

        if (!scope.Split(' ').Contains("api1"))
        {
            return false;
        }

        return true;
    }
}

public partial class Program;

public static class Base64Extensions
{
    public static string FromBase64(this string base64)
    {
        var bytes = Convert.FromBase64String(base64);
        var @string = Encoding.UTF8.GetString(bytes);
        return @string;
    }
}

public class BearerToken
{
    public Header? Header { get; set; }

    public Payload? Payload { get; set; }
}

public class Header
{
    [JsonPropertyName("typ")] public string? Type { get; set; }

    [JsonPropertyName("alg")] public string? Algorithm { get; set; }
}

public class Payload
{
    [JsonPropertyName("iss")] public string? Issuer { get; set; }

    [JsonPropertyName("sub")] public string? Subject { get; set; }

    [JsonPropertyName("aud")] public string? Audience { get; set; }

    [JsonPropertyName("iat")] public int? IssuedAt { get; set; }

    [JsonPropertyName("exp")] public int? ExpirationTime { get; set; }

    [JsonPropertyName("jti")] public string? JwtId { get; set; }
}

internal class TokenExtractor(ILogger<TokenExtractor> logger)
{
    public async Task<string?> GetBearerToken(HttpContext context)
    {
        return context.Request switch
        {
            { Headers.Authorization: [{ } x] } => x.Split(' ') switch
            {
                ["Bearer", var token] => token,
                _ => null
            },
            { HasFormContentType: true } x => await x.ReadFormAsync() switch
            {
                var form when form.TryGetValue("access_token", out var accessToken) => accessToken.ToString(),
                _ => null,
            },
            { Query: var query } when query.TryGetValue("access_token", out var accessToken) => accessToken.ToString(),
            _ => null,
        };
    }
}

public class Content
{
    public string? Token { get; set; }

    public bool IsVerified { get; set; }
}