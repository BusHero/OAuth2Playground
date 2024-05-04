using System.Text.Json.Serialization;

namespace WebApplication2;

public class Header
{
    [JsonPropertyName("typ")] public string? Type { get; set; }

    [JsonPropertyName("alg")] public string? Algorithm { get; set; }
}