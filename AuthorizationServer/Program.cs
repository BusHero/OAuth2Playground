using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.HttpResults;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<IClientRepository, InMemoryClientRepository>();
builder.Services.AddTransient<IValidator<Request>, RequestValidator>();

builder.Services
    .AddSingleton<IRequestsRepository, InMemoryRequestsRepository>();
builder.Services.AddProblemDetails();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapGet("/authorize", (
    [FromServices] IClientRepository clientRepository,
    [FromServices] IRequestsRepository requestsRepository,
    [AsParameters] AuthorizeRequest request) =>
{
    var client = clientRepository.FindClientById(request.ClientId);
    if (client == null || !client.RedirectUris.Contains(request.RedirectUri))
    {
        return Results.BadRequest();
    }

    var code = Guid.NewGuid().ToString();
    requestsRepository.Add(
        code,
        request.RedirectUri,
        request.ResponseType,
        request.State);

    return Results.Ok(new { Code = code });
});

app.MapPost("/approve", (
        [AsParameters] Request input,
        [FromServices] IRequestsRepository requestRepository) =>
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

        var uri = new UriBuilder(request.RedirectUri)
        {
            Query = $"code={Guid.NewGuid()}&state={request.State}"
        }.Uri.ToString();

        return Results.Redirect(uri);
    })
    .DisableAntiforgery()
    .AddEndpointFilter<ValidationFilter<Request>>();

app.MapPost(
    "/token", async (HttpContext context) =>
    {
        var client = default(string);
        var secret = default(string);
        var auth = context.Request.Headers.Authorization;
        if (auth.Count != 0)
        {
            var foo = AuthenticationHeaderValue.Parse(auth!);
            var stuff = foo.Parameter!.FromBase64String();
            var parameters = stuff.Split(':');

            client = parameters[0];
            secret = parameters[1];
        }

        var clientFromBody = default(string);
        var secretFromBody = default(string);
        if (context.Request.HasFormContentType)
        {
            var formData = await context.Request.ReadFormAsync();
            clientFromBody = formData["client"].ToString();
            secretFromBody = formData["secret"].ToString();
        }

        if (client is not null && clientFromBody is not null)
        {
            return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
        }

        if (client is not null)
        {
            return Results.Ok(new
            {
                Client = client,
                Secret = secret,
            });
        }

        if (clientFromBody is not null)
        {
            return Results.Ok(new
            {
                Client = clientFromBody,
                Secret = secretFromBody,
            });
        }

        return Results.Json(new { Error = "invalid_client" }, statusCode: 401);
    });

app.Run();

public abstract partial class Program;

public static class StringExtensions
{
    private static string ToBase64String(this byte[] bytes)
        => Convert.ToBase64String(bytes);

    public static Uri ToUri(this string uri) => new(uri);

    public static string ToBase64String(this string input) =>
        Encoding
            .UTF8
            .GetBytes(input)
            .ToBase64String();

    public static string FromBase64String(this string input)
    {
        var bytes = Convert.FromBase64String(input);
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] GetBytes(this string input, Encoding encoding)
        => encoding.GetBytes(input);

    private static string ToBase64String(this object @object) =>
        JsonSerializer
            .Serialize(@object)
            .ToBase64String();
}