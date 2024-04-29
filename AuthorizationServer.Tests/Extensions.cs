using Flurl.Http;

namespace AuthorizationServer.Tests;

internal static class Extensions
{
    public static HttpContent CreateFormUrlEncodedContent(
        this IEnumerable<KeyValuePair<string, string>> body)
        => new FormUrlEncodedContent(body);

    public static IFlurlRequest CreateApproveEndpoint(this IFlurlClient client)
        => client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve");

    public static IFlurlRequest CreateAuthorizationEndpoint(
        this IFlurlClient client,
        Client oauthClient) =>
        client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("client_id", oauthClient.ClientId);
}