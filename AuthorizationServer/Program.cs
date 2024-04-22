using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddSingleton<IClientRepository, InMemoryClientRepository>();

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
    [FromServices] IClientRepository repository,
    [FromQuery(Name = "client_id")] string clientId,
    [FromQuery(Name = "redirect_uri")] string redirectUri) =>
{
    return repository.FindClientById(clientId) switch
    {
        { RedirectUris: var redirectUris } when redirectUris.Contains(new Uri(redirectUri)) => Results.Ok(),
        _ => Results.BadRequest()
    };
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

public interface IClientRepository
{
    Client? FindClientById(string clientId);
}

public class InMemoryClientRepository : IClientRepository
{
    private readonly List<Client> _clients = [];

    public Client? FindClientById(string clientId)
    {
        return _clients.FirstOrDefault(x => x.ClientId == clientId);
    }

    public void AddClient(Client client)
    {
        _clients.Add(client);
    }
}