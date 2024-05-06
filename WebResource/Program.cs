using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication2;

public sealed class Program
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

        app.MapGet("/resource2", async (HttpContext context) =>
        {
            var authorizationHeader = context
                .Request
                .Headers
                .Authorization;

            if (authorizationHeader.Count == 0)
            {
                return Results.Unauthorized();
            }

            var headerValue = AuthenticationHeaderValue.Parse(authorizationHeader!);

            if (headerValue.Scheme != "Bearer")
            {
                return Results.Unauthorized();
            }

            var lines = await File.ReadAllLinesAsync($"{Path.GetTempPath()}/tokens");

            if (!lines.Contains(headerValue.Parameter))
            {
                return Results.Unauthorized();
            }

            return Results.Ok();
        });

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