using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddLogging();
builder.Services.AddSingleton<TokenExtractor>();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapPost("/resource", (
    [FromServices] TokenExtractor extractor,
    HttpContext context) =>
{
    var token = extractor.GetToken(context);
    return new { Message = token };
});

app.Run();

public partial class Program;

internal class TokenExtractor(ILogger<TokenExtractor> logger)
{
    public string? GetToken(HttpContext context)
    {
        return context.Request switch
        {
            { Headers.Authorization: [{ } x] } => x.Split(' ') switch
            {
                ["Bearer", var token] => token,
                _ => null
            },
            _ => null,
        };
    }
}