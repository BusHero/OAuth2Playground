using System.Text;
using System.Text.Json;

namespace AuthorizationServer;

internal static class StringExtensions
{
    private static string ToBase64String(this byte[] bytes)
        => Convert.ToBase64String(bytes);

    public static Uri ToUri(this string uri) => new(uri);

    public static string ToBase64String(this string input) =>
        Encoding
            .UTF8
            .GetBytes(input)
            .ToBase64String();

    public static string FromBase64String(this string input)
    {
        var bytes = Convert.FromBase64String(input);
        return Encoding.UTF8.GetString(bytes);
    }

    private static byte[] GetBytes(this string input, Encoding encoding)
        => encoding.GetBytes(input);

    private static string ToBase64String(this object @object) =>
        JsonSerializer
            .Serialize(@object)
            .ToBase64String();
}