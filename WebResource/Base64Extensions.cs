using System.Text;

namespace WebApplication2;

public static class Base64Extensions
{
    public static string FromBase64(this string base64)
    {
        var bytes = Convert.FromBase64String(base64);
        var @string = Encoding.UTF8.GetString(bytes);
        return @string;
    }
}