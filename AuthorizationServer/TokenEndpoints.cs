using Microsoft.AspNetCore.Mvc;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;

namespace AuthorizationServer;

internal static class TokenEndpoints
{
    internal static readonly string[] validScopes = ["scope1", "scope2"];

    public static void RegisterTokenEndpoints(this WebApplication app)
    {
        app.MapPost(
            "/connect/token",
            async (
                HttpContext context,
                [FromForm(Name = "grant_type")] string grantType,
                [FromForm(Name = "scope")] string? requestedScopesAsString,
                CancellationToken cancellationToken) =>
            {
                var authenticationParameters = await GetAuthenticationCredentials(context, cancellationToken);
                if (authenticationParameters is not { ClientId: "client.credentials.sample", ClientSecret: "secret" })
                {
                    return Results.BadRequest();
                }

                if (grantType != "client_credentials")
                {
                    return Results.BadRequest();
                }

                var requestedScopes = requestedScopesAsString?.Split(' ') ?? validScopes;
                foreach (var _scope in requestedScopes)
                {
                    if (!validScopes.Contains(_scope))
                    {
                        return Results.BadRequest();
                    }
                }

                return Results.Ok(new TokenResponse
                {
                    AccessToken = Guid.NewGuid().ToString(),
                    TokenType = "Bearer",
                    ExpiresIn = 3600,
                    Scope = string.Join(' ', requestedScopes),
                });
            })
            .DisableAntiforgery();
    }

    private static async Task<AuthParameters?> GetAuthenticationCredentials(
        HttpContext context,
        CancellationToken cancellationToken)
    {
        var clientId = default(string);
        var clientSecret = default(string);
        var auth = context.Request.Headers.Authorization;
        if (auth.Count != 0)
        {
            var authHeader = AuthenticationHeaderValue.Parse(auth!);
            if (authHeader.Scheme != "Basic")
            {
                return null;
            }

            var stuff = authHeader.Parameter!.FromBase64String();
            var parameters = stuff.Split(':');

            clientId = parameters[0];
            clientSecret = parameters[1];
        }
        else
        {
            var formData = await context
                .Request
                .ReadFormAsync(cancellationToken);
            if (formData.TryGetValue("client_id", out var clientFromBody1))
            {
                clientId = clientFromBody1.ToString();
            }

            if (formData.TryGetValue("client_secret", out var secretFromBody1))
            {
                clientSecret = secretFromBody1.ToString();
            }
        }

        return new AuthParameters
        {
            ClientId = clientId,
            ClientSecret = clientSecret,
        };
    }

    private sealed record TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = null!;

        [JsonPropertyName("token_type")]
        public string TokenType { get; set; } = null!;

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("scope")]
        public string Scope { get; set; } = null!;
    }
}

internal sealed record TokenRequest
{
    [FromForm(Name = "grant_type")]
    public string GrantType { get; set; } = null!;

    [FromForm(Name = "scope")]
    public string? Scope { get; set; }
}


internal sealed record AuthParameters
{
    public string? ClientId { get; set; }

    public string? ClientSecret { get; set; }
}
