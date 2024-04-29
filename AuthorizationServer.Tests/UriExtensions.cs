namespace AuthorizationServer.Tests;

internal static class UriExtensions
{
    public static UriAssertions Should(this Uri? uri)
    {
        return new UriAssertions(uri);
    }
}