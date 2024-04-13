using System.Net.Http.Headers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class ExternalResource : PageModel
{
    public string Token { get; set; }
    
    public string Content { get; set; }
    
    public async Task OnGet([FromServices] HttpClient client)
    {
        var token = HttpContext.Session.GetString("token");
        if (string.IsNullOrEmpty(token))
        {
            throw new Exception();
        }

        client.BaseAddress = new Uri("http://localhost:9002");

        client.DefaultRequestHeaders.Authorization 
            = new AuthenticationHeaderValue("Bearer", token);

        var result = await client.PostAsync(
            "/resource", 
            null);
        
        result.EnsureSuccessStatusCode();

        Content = await result.Content.ReadAsStringAsync();
    }
}