using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;
using Microsoft.AspNetCore.Antiforgery;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IClientRepository, InMemoryClientRepository>();
builder.Services.AddTransient<IValidator<Request>, RequestValidator>();
builder.Services.AddSingleton<InMemoryRequestsRepository>();
builder.Services.AddSingleton<InMemoryCodeRepository>();
builder.Services.AddAntiforgery(x =>
{
    x.FormFieldName = "AntiForgeryTokenField";
    x.Cookie.Name = "AntiForgeryTokenCookie";
});

var app = builder.Build();

app.UseHttpsRedirection();
app.UseAntiforgery();

app.MapGet("/authorize", (
    HttpContext context,
    [FromServices] IClientRepository clientRepository,
    [FromServices] InMemoryRequestsRepository requestsRepository,
    [FromServices] IAntiforgery antiForgeryService,
    [AsParameters] AuthorizeRequest request) =>
{
    var client = clientRepository.FindClientById(request.ClientId);
    if (client == null || !client.RedirectUris.Contains(request.RedirectUri))
    {
        return Results.BadRequest();
    }

    var token = antiForgeryService.GetAndStoreTokens(context);
    var code = token.RequestToken!;

    if (!AreScopesValid(request, client))
    {
        return Results.BadRequest();
    }

    requestsRepository.Add(
        code,
        client.ClientId,
        request.RedirectUri,
        request.ResponseType,
        request.State);

    var html =
        $"""
         <html>
             <body>
                 <form action="/handle-form" method="POST">
                     <input name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}">
                     <input type="text" name="comment" value="value">
                     <input type="submit">
                 </form>
             </body
         </html>
         """;

    return Results.Content(html, "text/html");
});

app.MapPost("/approve", (
        [AsParameters] Request input,
        [FromServices] InMemoryRequestsRepository requestRepository,
        [FromServices] InMemoryCodeRepository codesRepository) =>
    {
        var request = requestRepository.GetAndRemoveRequest(input.RequestId);
        if (request is null)
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["reqId"] = ["Unknown requestId"]
            });
        }

        if (input.Approve is null)
        {
            var foo = new UriBuilder(request.RedirectUri)
            {
                Query = "error=access_denied",
            }.Uri.ToString();

            return Results.Redirect(foo);
        }

        if (request.ResponseType is not "code")
        {
            var foo = new UriBuilder(request.RedirectUri)
            {
                Query = "error=unsupported_response_type",
            }.Uri.ToString();

            return Results.Redirect(foo);
        }

        var code = Guid.NewGuid().ToString();
        codesRepository.Add(
            code: code,
            clientId: request.ClientId);

        var uri = new UriBuilder(request.RedirectUri)
        {
            Query = $"code={code}&state={request.State}"
        }.Uri.ToString();

        return Results.Redirect(uri);
    })
    .AddEndpointFilter<ValidationFilter<Request>>();

app.MapPost("/register", (
    [FromBody] RegisterData data,
    [FromServices] IClientRepository clientRepository) =>
{
    string[] acceptedTokenEndpointAuthMethods = ["secret_basic", "secret_post"];
    var tokenEndpointAuthMethod = data.TokenEndpointAuthMethod ?? "secret_basic";
    if (!acceptedTokenEndpointAuthMethods.Contains(tokenEndpointAuthMethod))
    {
        return Results.BadRequest(new Dictionary<string, string>
        {
            ["error"] = "invalid_client_metadata",
        });
    }

    string[] validGrantTypes = ["authorization_code", "refresh_token"];
    string[] validResponseTypes = ["code"];

    var grantTypes = data.GrantTypes.ToHashSet();
    var responseTypes = data.ResponseTypes.ToHashSet();

    grantTypes.Add("authorization_code");
    responseTypes.Add("code");

    if (!grantTypes.All(validGrantTypes.Contains) || !responseTypes.All(validResponseTypes.Contains))
    {
        return Results.BadRequest(new Dictionary<string, string>
        {
            ["error"] = "invalid_client_metadata",
        });
    }

    if (data.RedirectUris is { Length: 0 })
    {
        return Results.BadRequest(new Dictionary<string, string>
        {
            ["error"] = "invalid_redirect_uri",
        });
    }

    var clientId = Guid.NewGuid().ToString();
    var clientSecret = Guid.NewGuid().ToString();
    clientRepository.AddClient(
        clientId,
        clientSecret,
        scopes: data.Scope.Split(' '),
        data.RedirectUris);

    return Results.Ok(new Dictionary<string, object>
    {
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret,
        ["token_endpoint_auth_method"] = tokenEndpointAuthMethod,
        ["grant_types"] = grantTypes.ToArray(),
        ["response_types"] = responseTypes.ToArray(),
        ["redirect_uris"] = data.RedirectUris,
        ["scope"] = data.Scope,
    });
});

app.MapPost("/token", async (
        HttpContext context,
        [FromForm(Name = "grant_type")] string grantType,
        [FromForm(Name = "code")] string code,
        [FromServices] IClientRepository clientRepository,
        [FromServices] InMemoryCodeRepository codesRepository) =>
    {
        var clientId = default(string);
        var clientSecret = default(string);
        var auth = context.Request.Headers.Authorization;
        if (auth.Count != 0)
        {
            var authHeader = AuthenticationHeaderValue.Parse(auth!);
            if (authHeader.Scheme != "Basic")
            {
                return Results.BadRequest();
            }

            var stuff = authHeader.Parameter!.FromBase64String();
            var parameters = stuff.Split(':');

            clientId = parameters[0];
            clientSecret = parameters[1];
        }

        var clientFromBody = default(string);
        var secretFromBody = default(string);
        if (context.Request.HasFormContentType)
        {
            var formData = await context
                .Request
                .ReadFormAsync();
            if (formData.TryGetValue("client", out var clientFromBody1))
            {
                clientFromBody = clientFromBody1.ToString();
            }

            if (formData.TryGetValue("secret", out var secretFromBody1))
            {
                secretFromBody = secretFromBody1.ToString();
            }
        }

        if (clientId is not null && clientFromBody is not null)
        {
            return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
        }

        if (clientId is null && clientFromBody is null)
        {
            return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
        }

        var client = clientRepository.FindClientById(clientId ?? clientFromBody!);
        if (client is null)
        {
            return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
        }

        var actualSecret = clientSecret ?? secretFromBody;
        if (client.ClientSecret != actualSecret)
        {
            return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
        }

        if (grantType != "authorization_code")
        {
            return Results.BadRequest();
        }

        var clientIdAssociatedWithCode = codesRepository.GetAndRemoveClientForCode(code);

        if (clientIdAssociatedWithCode != client.ClientId)
        {
            return Results.BadRequest();
        }

        var token = Guid.NewGuid().ToString();

        await File.WriteAllLinesAsync($"{Path.GetTempPath()}/tokens", [token]);

        return Results.Ok(new
        {
            access_token = token,
            token_type = "Bearer",
        });
    })
    .DisableAntiforgery();

app.MapGet("/example", (HttpContext context, IAntiforgery antiforgery) =>
{
    var token = antiforgery.GetAndStoreTokens(context);
    var html =
        $"""
         <html>
             <body>
                 <form action="/handle-form" method="POST">
                     <input name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}">
                     <input type="text" name="comment" value="value">
                     <input type="submit">
                 </form>
             </body
         </html>
         """;

    return Results.Content(html, "text/html");
});

app.MapPost("/handle-form", ([FromForm] string comment) => Results.Ok("Ok"));

app.Run();

return;

bool AreScopesValid(AuthorizeRequest authorizeRequest, Client client1)
{
    var requestScopes = authorizeRequest
        .Scope?
        .Split(' ') ?? [];

    return requestScopes.All(x => client1.Scopes.Contains(x));
}

public sealed partial class Program;

internal sealed record RegisterData
{
    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; init; }

    [JsonPropertyName("grant_types")] public string[] GrantTypes { get; init; } = [];

    [JsonPropertyName("response_types")] public string[] ResponseTypes { get; init; } = [];

    [JsonPropertyName("redirect_uris")] public Uri[] RedirectUris { get; init; } = [];

    [JsonPropertyName("scope")] public string Scope { get; init; } = null!;
}