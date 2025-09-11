using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer;

internal static class AuthorizeEndpoints
{
    public static void RegisterAuthorizeEndpoints(this WebApplication app)
    {
        app.MapPost("/connect/token", (HttpContext context) =>
        {
            return Results.BadRequest();
        });

        app.MapGet("/authorize", (
            HttpContext context,
            [FromServices] IClientRepository clientRepository,
            [FromServices] InMemoryRequestsRepository requestsRepository,
            [FromServices] IAntiforgery antiForgeryService,
            [AsParameters] AuthorizeRequest request) =>
        {
            var client = clientRepository.FindClientById(request.ClientId);
            if (client == null || !client.RedirectUris.Contains(request.RedirectUri))
            {
                return Results.BadRequest();
            }

            var token = antiForgeryService.GetAndStoreTokens(context);
            var code = token.RequestToken!;

            if (!AreScopesValid(request, client))
            {
                return Results.BadRequest();
            }

            requestsRepository.Add(
                code,
                client.ClientId,
                request.RedirectUri,
                request.ResponseType,
                request.State);

            var html =
                $"""
                 <html>
                     <body>
                         <form action="/handle-form" method="POST">
                             <input name="{token.FormFieldName}" type="hidden" value="{token.RequestToken}">
                             <input type="text" name="comment" value="value">
                             <input type="submit">
                         </form>
                     </body
                 </html>
                 """;

            return Results.Content(html, "text/html");
        });
    }

    private static bool AreScopesValid(AuthorizeRequest authorizeRequest, Client client1)
    {
        var requestScopes = authorizeRequest
            .Scope?
            .Split(' ') ?? [];

        return requestScopes.All(x => client1.Scopes.Contains(x));
    }

}
