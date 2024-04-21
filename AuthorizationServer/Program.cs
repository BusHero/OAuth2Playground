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
    [FromQuery(Name = "client_id")]
    string clientId) =>
{
    var client = clients.FirstOrDefault(x => x.ClientId == clientId);

    if (client is null)
    {
        return Results.BadRequest();
    }
    
    return Results.Ok();
});

app.Run();

public abstract partial class Program;

internal sealed class Client
{
    public required string ClientId { get; init; }

    public required string ClientSecret { get; init; }

    public required string[] RedirectUris { get; init; }
}