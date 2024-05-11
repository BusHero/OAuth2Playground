using Microsoft.AspNetCore.Mvc;

namespace AuthorizationServer;

internal sealed record AuthorizeRequest(
    [FromQuery(Name = "client_id")] string ClientId,
    [FromQuery(Name = "redirect_uri")] Uri RedirectUri,
    [FromQuery(Name = "response_type")] string ResponseType,
    [FromQuery(Name = "state")] string? State,
    [FromQuery(Name = "scope")] string[]? Scope);