namespace AuthorizationServer.Tests;

public sealed record AntiForgeryTokenResponse
{
    public string FormFieldName { get; init; } = null!;

    public string FormFieldValue { get; init; } = null!;

    public string CookieName { get; init; } = null!;

    public string? CookieValue { get; init; }
}