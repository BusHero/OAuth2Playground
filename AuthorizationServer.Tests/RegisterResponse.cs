using System.Text.Json.Serialization;

namespace AuthorizationServer.Tests;

public sealed record RegisterResponse
{
    [JsonPropertyName("client_id")] public string ClientId { get; init; } = null!;

    [JsonPropertyName("client_secret")] public string ClientSecret { get; init; } = null!;

    [JsonPropertyName("grant_types")] public IReadOnlyCollection<string> GrantTypes { get; init; } = [];

    [JsonPropertyName("response_types")] public IReadOnlyCollection<string> ResponseTypes { get; init; } = [];

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod { get; init; } = null!;

    [JsonPropertyName("redirect_uris")] public IReadOnlyCollection<Uri> RedirectUris { get; init; } = [];

    [JsonPropertyName("scope")] public string Scope { get; init; } = null!;
}