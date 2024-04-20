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
    return new
    {
        BearerToken = bearerToken,
        Token = token,
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
        Content = JsonSerializer.Deserialize<Content>(content),
    };

    return bearerToken;
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

    public Content? Content { get; set; }
}

public class Header
{
    [JsonPropertyName("typ")] public string? Type { get; set; }

    [JsonPropertyName("alg")] public string? Algorithm { get; set; }
}

public class Content
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