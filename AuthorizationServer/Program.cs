using System.Net.Http.Headers;
using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;
using Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IClientRepository, InMemoryClientRepository>();
builder.Services.AddTransient<IValidator<Request>, RequestValidator>();
builder.Services.AddSingleton<InMemoryRequestsRepository>();
builder.Services.AddSingleton<InMemoryCodeRepository>();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapGet("/authorize", (
    [FromServices] IClientRepository clientRepository,
    [FromServices] InMemoryRequestsRepository requestsRepository,
    [AsParameters] AuthorizeRequest request) =>
{
    var client = clientRepository.FindClientById(request.ClientId);
    if (client == null || !client.RedirectUris.Contains(request.RedirectUri))
    {
        return Results.BadRequest();
    }

    var code = Guid
        .NewGuid()
        .ToString();

    requestsRepository.Add(
        code,
        client.ClientId,
        request.RedirectUri,
        request.ResponseType,
        request.State);


    if (request.Scope is null)
    {
        return Results.Ok(new
        {
            Code = code
        });
    }

    if (request.Scope.Length == 0)
    {
        return Results.Ok(new
        {
            Code = code
        });
    }

    return Results.BadRequest();
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
    .DisableAntiforgery()
    .AddEndpointFilter<ValidationFilter<Request>>();

app.MapPost(
        "/token", async (
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

app.Run();

public sealed partial class Program;