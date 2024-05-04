using System.Text.Json.Serialization;

namespace WebApplication2;

public class Payload
{
    [JsonPropertyName("iss")] public string? Issuer { get; set; }

    [JsonPropertyName("sub")] public string? Subject { get; set; }

    [JsonPropertyName("aud")] public string? Audience { get; set; }

    [JsonPropertyName("iat")] public int? IssuedAt { get; set; }

    [JsonPropertyName("exp")] public int? ExpirationTime { get; set; }

    [JsonPropertyName("jti")] public string? JwtId { get; set; }
}