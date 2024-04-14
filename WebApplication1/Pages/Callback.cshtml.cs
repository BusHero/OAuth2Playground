using System.Text.Json.Serialization;
using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class Callback : PageModel
{
    public string Code { get; set; } = null!;
    
    public string State { get; set; } = null!;

    public string AccessToken { get; set; } = null!;

    public string TokenType { get; set; } = null!;

    public string RefreshToken { get; set; } = null!;
    
    public string Body { get; set; } = null!;

    public async Task OnGet(
        [FromServices] HttpClient httpClient,
        [FromServices] ILogger<Callback> logger,
        string code,
        string state)
    {
        var state2 = HttpContext.Session.GetString("state");

        if (state != state2)
        {
            throw new Exception($"state is not right gotten: {state} vs stored: {state2}");
        }

        Code = code;
        State = state;

        var result = await "http://localhost:9001"
            .AppendPathSegment("token")
            .WithBasicAuth(Client.ClientId, Client.ClientSecret)
            .PostAsync(new FormUrlEncodedContent([
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", Client.RedirectUri),
            ]));
        Body = await result.GetStringAsync();

        var response = await result.GetJsonAsync<AuthSomething>();

        AccessToken = response.AccessToken;
        TokenType = response.TokenType;
        RefreshToken = response.RefreshToken;

        HttpContext.Session.SetString("token", AccessToken);
        HttpContext.Session.SetString("refresh_token", RefreshToken);
    }


    internal class AuthSomething
    {
        [JsonPropertyName("access_token")] public string AccessToken { get; set; } = null!;

        [JsonPropertyName("token_type")] public string TokenType { get; set; } = null!;

        [JsonPropertyName("scope")] public string Scope { get; set; } = null!;
        [JsonPropertyName("refresh_token")] public string RefreshToken { get; set; } = null!;
    }
}