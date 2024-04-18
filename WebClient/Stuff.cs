using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace WebClient;

public static class Stuff
{
    public static void MapStuff(this WebApplication app)
    {
        app.MapGet("/authorize", DoStuff);
    }


    private const string ClientId = "oauth-client-1";
    private const string ClientSecret = "oauth-client-secret-1";
    private const string RedirectUri = "http://localhost:9000/callback";
    private const string AuthEndpoint = "http://localhost:9001/authorize";
    private const string TokenEndpoint = "http://localhost:9001/token";

    private static async Task<string> DoStuff()
    {
        using var httpClient = new HttpClient();

        httpClient.BaseAddress = new Uri("http://localhost:9001");

        var result = await httpClient
            .GetAsync($"/authorize?response_type=code&client_id={ClientId}&redirect_uri={RedirectUri}");

        var response = await result.Content.ReadAsStringAsync();
        Debug.WriteLine(response);
        
        return "world!";
    }
}