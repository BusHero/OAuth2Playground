using System.ComponentModel.DataAnnotations;
using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddSingleton<IClientRepository, InMemoryClientRepository>();

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
    [FromQuery(Name = "redirect_uri")] Uri redirectUri) =>
{
    var client = clientRepository.FindClientById(clientId);
    if (client == null || !client.RedirectUris.Contains(redirectUri))
    {
        return Results.BadRequest();
    }

    requestsRepository.Add(
        Guid.NewGuid().ToString(),
        context.Request.QueryString.ToString()[1..]);

    return Results.Ok();
});

app.MapPost("/approve", async (
        [FromForm(Name = "reqId")] string? requestId,
        [FromServices] IRequestsRepository requestRepository) =>
    {
        if (requestId is null)
        {
            return Results.BadRequest(new
            {
                Message = "Missing requestId",
            });
        }

        if (requestRepository.GetRequest(requestId) is null)
        {
            return Results.BadRequest(new
            {
                Message = "Unknown requestId",
            });
        }

        return Results.Ok();
    })
    .DisableAntiforgery()
    .Finally(x => { });

app.Run();

public abstract partial class Program;

public sealed class Client
{
    public required string ClientId { get; init; }

    public required string ClientSecret { get; init; }

    public required Uri[] RedirectUris { get; init; }
}

class Request
{
    [Required] public bool? Approve { get; set; }
}