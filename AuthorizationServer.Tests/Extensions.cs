using Flurl.Http;

namespace AuthorizationServer.Tests;

internal static class Extensions
{
    public static IFlurlRequest CreateApproveEndpoint(this IFlurlClient client)
        => client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve");

    public static IReadOnlyDictionary<string, string> GetQueryParameters(
        this Uri uri)
    {
        var query = uri.GetComponents(UriComponents.Query, UriFormat.Unescaped);
        
        var dictionary = query
            .Split("&")
            .Select(x => x.Split('='))
            .ToDictionary(x => x[0], x => x[1]);

        return dictionary;
    }
}