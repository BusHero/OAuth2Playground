using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddLogging();
builder.Services.AddSingleton<TokenExtractor>();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapPost("/resource", async (
    [FromServices] TokenExtractor extractor,
    HttpContext context) =>
{
    var token = await extractor.GetBearerToken(context);
    var bearerToken = GetParts(token);
    var isTokenValid = IsTokenValid(token);
    return new Content
    {
        Token = token,
        IsVerified = isTokenValid,
    };
});

app.Run();
return;

BearerToken GetParts(string? token)
{
    if (token is null)
    {
        return new BearerToken();
    }

    var parts = token.Split(".");

    if (parts.Length != 3)
    {
        return new BearerToken();
    }

    var header = parts[0].FromBase64();
    var content = parts[1].FromBase64();

    var bearerToken = new BearerToken
    {
        Header = JsonSerializer.Deserialize<Header>(header),
        Payload = JsonSerializer.Deserialize<Payload>(content),
    };

    return bearerToken;
}

bool IsTokenValid(string token)
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
    
    var result = signature == parts[2];

    return result;
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