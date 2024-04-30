using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AuthorizationServer.Tests;

public static class StringExtensions
{
    private static string ToBase64String(this byte[] bytes)
        => Convert.ToBase64String(bytes);

    public static Uri ToUri(this string uri) => new(uri);

    private static string ToBase64String(this string input) =>
        Encoding
            .UTF8
            .GetBytes(input)
            .ToBase64String();

    private static byte[] GetBytes(this string input, Encoding encoding)
        => encoding.GetBytes(input);

    private static string ToBase64String(this object @object) =>
        JsonSerializer
            .Serialize(@object)
            .ToBase64String();

    public static string CreateHmac256SignedToken(
        this Dictionary<string, object> payload,
        string secret)
    {
        var header = new Dictionary<string, object>()
        {
            ["typ"] = "JWT",
            ["alg"] = "none",
        };

        var headerBase64 = header
            .ToBase64String();

        var payloadBase64 = payload
            .ToBase64String();

        var signature = HMACSHA256
            .HashData(
                secret.GetBytes(Encoding.ASCII),
                $"{headerBase64}.{payloadBase64}".GetBytes(Encoding.ASCII))
            .ToBase64String()
            .Replace("/", "_")
            .Replace("=", "");

        return $"{headerBase64}.{payloadBase64}.{signature}";
    }

    public static string CreateUnsignedToken(
        this Dictionary<string, object> payload)
    {
        var header = new Dictionary<string, object>()
        {
            ["typ"] = "JWT",
            ["alg"] = "none",
        };

        var headerBase64 = header
            .ToBase64String();

        var payloadBase64 = payload
            .ToBase64String();

        var token = $"{headerBase64}.{payloadBase64}.";

        return token;
    }
}