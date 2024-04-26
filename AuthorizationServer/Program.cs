using System.ComponentModel.DataAnnotations;
using AuthorizationServer;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddSingleton<IClientRepository, InMemoryClientRepository>();

builder.Services
    .AddSingleton<IRequestsRepository, InMemoryRequestsRepository>();

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
    if (client != null && client.RedirectUris.Contains(redirectUri))
    {
        requestsRepository.Add(
            Guid.NewGuid().ToString(),
            context.Request.QueryString.ToString()[1..]);
        return Results.Ok();
    }

    return Results.BadRequest();
});

app.MapPost("/approve", async (
        [FromForm] bool approve,
        [FromForm(Name = "response_type")] string? responseType) =>
    {
        if (!approve)
        {
            return Results.BadRequest();
        }

        if (responseType != "code")
        {
            return Results.Redirect("http://localhost:9000/callback?error=unsupported_response_type");
        }

        return Results.Ok();
    })
    .DisableAntiforgery();

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