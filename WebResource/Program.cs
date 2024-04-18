using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddLogging();
builder.Services.AddSingleton<TokenExtractor>();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapPost("/resource", async (
    [FromServices] TokenExtractor extractor,
    HttpContext context) =>
{
    var token = await extractor.GetToken(context);
    return new { Message = token };
});

app.Run();

public partial class Program;

internal class TokenExtractor(ILogger<TokenExtractor> logger)
{
    public async Task<string?> GetToken(HttpContext context)
    {
        return context.Request switch
        {
            { Headers.Authorization: [{ } x] } => x.Split(' ') switch
            {
                ["Bearer", var token] => token,
                _ => null
            },
            {HasFormContentType:true}x => await x.ReadFormAsync() switch
            {
                var y when y.ContainsKey("access_token") => y["access_token"].ToString(),
                _ => null,
            },
            _ => null,
        };
    }
}