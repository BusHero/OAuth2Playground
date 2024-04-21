using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

Client[] clients =
[
    new Client
    {
        ClientId = "oauth-client-1",
        ClientSecret = "secret",
        RedirectUris = ["http://localhost:9000/callback"]
    },
];

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
    [FromQuery(Name = "client_id")] string clientId,
    [FromQuery(Name = "redirect_uri")] string redirectUri) =>
{
    return clients.FirstOrDefault(x => x.ClientId == clientId) switch
    {
        { RedirectUris: var redirectUris } when redirectUris.Contains(redirectUri) => Results.Ok(),
        _ => Results.BadRequest()
    };
});

app.MapPost("/approve", (
        [FromForm] bool approve) =>
    {
        if (!approve)
        {
            return Results.BadRequest();
        }
        
        return Results.Ok();
    })
    .DisableAntiforgery();

app.Run();

public abstract partial class Program;

internal sealed class Client
{
    public required string ClientId { get; init; }

    public required string ClientSecret { get; init; }

    public required string[] RedirectUris { get; init; }
}

class Request
{
    [Required]
    public bool? Approve { get; set; }
}