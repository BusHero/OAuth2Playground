using Flurl;
using Flurl.Http;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class ExternalResource : PageModel
{
    public string Content2 { get; set; } = null!;

    public async Task OnGet()
    {
        Content2 = await GetResult2();
    }

    private async Task<string> GetResult2()
    {
        var token = HttpContext.Session.GetString("token");
        if (string.IsNullOrEmpty(token))
        {
            throw new InvalidOperationException();
        }

        try
        {
            return await GetResult(token);
        }
        catch (FlurlHttpException)
        {
            var newToken = await GetNewToken();
            HttpContext.Session.SetString("token", newToken);
            return await GetResult(newToken);
        }
    }

    private async Task<string> GetNewToken()
    {
        var refreshToken = HttpContext.Session.GetString("refresh_token");
        if (string.IsNullOrEmpty(refreshToken))
        {
            throw new InvalidOperationException();
        }
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("refresh_token", refreshToken),
            new KeyValuePair<string, string>("redirect_uri", Client.RedirectUri),
        ]);
        var result = await "http://localhost:9001"
            .AppendPathSegment("token")
            .WithBasicAuth(Client.ClientId, Client.ClientSecret)
            .PostAsync(body);

        var response = await result.GetJsonAsync<Callback.AuthSomething>();

        return response.AccessToken;
    }


    private static async Task<string> GetResult(string token)
    {
        var result = await "http://localhost:9002"
            .AppendPathSegment("resource")
            .WithOAuthBearerToken(token)
            .PostAsync();

        return await result.GetStringAsync();
    }
}