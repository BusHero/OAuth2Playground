using Flurl;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class Login : PageModel
{
    public async Task<IActionResult> OnGet()
    {
        var state = Guid.NewGuid().ToString();
        HttpContext.Session.SetString("state", state);
        await HttpContext.Session.CommitAsync();
        var link = "http://localhost:9001"
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("client_id", Client.ClientId)
            .AppendQueryParam("redirect_uri", Client.RedirectUri)
            .AppendQueryParam("state", state);

        return Redirect(link);
    }
}