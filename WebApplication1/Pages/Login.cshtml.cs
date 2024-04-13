using Flurl;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace WebApplication1.Pages;

public class Login : PageModel
{
    public async Task<IActionResult> OnGet()
    {
        var escapeDataString = Uri.EscapeDataString(Client.RedirectUri);
        var state = Guid.NewGuid().ToString();
        HttpContext.Session.SetString("state", state);
        await HttpContext.Session.CommitAsync();
        var link =
            $"http://localhost:9001/authorize?response_type=code&client_id={Client.ClientId}&redirect_uri={escapeDataString}&state={state}";
        return Redirect(link);
    }
}