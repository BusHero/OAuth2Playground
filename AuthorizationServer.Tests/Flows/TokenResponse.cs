using System.Text.Json.Serialization;

namespace AuthorizationServer.Tests.Flows;

internal sealed record TokenResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = null!;

    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = null!;

    [JsonPropertyName("expires_in")]
    public int ExperiesIn { get; set; }

    [JsonPropertyName("scope")]
    public string Scope { get; set; } = null!;

    public string[] ParseScopes() => Scope.Split(' ');
}
