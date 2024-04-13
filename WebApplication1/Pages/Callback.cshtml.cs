using System.Text;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class Callback : PageModel
{
    public string Code { get; set; }
    public string State { get; set; }

    public string AccessToken { get; set; }

    public string TokenType { get; set; }

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

        var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri("http://localhost:9001/token"),
            Content = new FormUrlEncodedContent([
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", Client.RedirectUri),
            ]),
        };
        const string authString = $"{Client.ClientId}:{Client.ClientSecret}";
        var base64String = Convert.ToBase64String(Encoding.ASCII.GetBytes(authString));
        request.Headers.Add("Authorization", $"Basic {base64String}");
        var result = await httpClient.SendAsync(request);
        result.EnsureSuccessStatusCode();

        var response = await result.Content.ReadFromJsonAsync<AuthSomething>();

        AccessToken = response.AccessToken;
        TokenType = response.TokenType;

        HttpContext.Session.SetString("token", AccessToken);
    }

    internal class AuthSomething
    {
        [JsonPropertyName("access_token")] public string AccessToken { get; set; } = null!;

        [JsonPropertyName("token_type")] public string TokenType { get; set; } = null!;

        [JsonPropertyName("scope")] public string Scope { get; set; } = null!;
    }
}