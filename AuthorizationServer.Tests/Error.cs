namespace AuthorizationServer.Tests;

internal sealed class Error
{
    public string Title { get; init; } = null!;

    public int Status { get; init; }

    public Dictionary<string, string[]> Errors { get; init; } = null!;
}