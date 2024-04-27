public sealed class Client
{
    public required string ClientId { get; init; }

    public required string ClientSecret { get; init; }

    public required Uri[] RedirectUris { get; init; }
}