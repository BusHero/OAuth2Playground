using Flurl.Http;

namespace AuthorizationServer.Tests;

internal static class Extensions
{
    public static IFlurlRequest CreateApproveEndpoint(this IFlurlClient client)
        => client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("approve");

    public static IFlurlRequest CreateAuthorizationEndpoint(this IFlurlClient client,
        Client oauthClient, 
        string state = "") =>
        client.Request()
            .AllowAnyHttpStatus()
            .WithAutoRedirect(false)
            .AppendPathSegment("authorize")
            .AppendQueryParam("response_type", "code")
            .AppendQueryParam("redirect_uri", oauthClient.RedirectUris[0])
            .AppendQueryParam("state", state)
            .AppendQueryParam("client_id", oauthClient.ClientId);
}