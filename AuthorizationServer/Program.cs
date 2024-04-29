using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;
using FluentValidation;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddSingleton<IClientRepository, InMemoryClientRepository>();
builder.Services.AddTransient<IValidator<Request?>, RequestValidator>();

builder.Services
    .AddSingleton<IRequestsRepository, InMemoryRequestsRepository>();
builder.Services.AddProblemDetails();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.MapGet("/authorize", (
    HttpContext context,
    [FromServices] IClientRepository clientRepository,
    [FromServices] IRequestsRepository requestsRepository,
    [FromQuery(Name = "client_id")] string clientId,
    [FromQuery(Name = "redirect_uri")] Uri redirectUri,
    [FromQuery(Name = "response_type")] string responseType,
    [FromQuery(Name = "state")] string state) =>
{
    var client = clientRepository.FindClientById(clientId);
    if (client == null || !client.RedirectUris.Contains(redirectUri))
    {
        return Results.BadRequest();
    }

    var code = Guid.NewGuid().ToString();
    requestsRepository.Add(
        code,
        clientId,
        redirectUri,
        responseType,
        state);

    return Results.Ok(new { Code = code });
});

app.MapPost("/approve", async (
        [AsParameters] Request input,
        [FromServices] IRequestsRepository requestRepository) =>
    {
        var request = requestRepository.GetRequest(input.RequestId);
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

app.Run();

public abstract partial class Program;

internal sealed class Request
{
    [FromForm(Name = "reqId")] public required string RequestId { get; init; }

    [FromForm(Name = "approve")] public string? Approve { get; init; }
}