using WebClient;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

app.UseHttpsRedirection();

app.MapGet("/callback", () =>
{
    app.Logger.LogInformation("Hi there");
    return "Hello";
});

app.MapStuff();

app.Run();