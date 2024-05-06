using System.Net.Http.Headers;
using Flurl.Http;

namespace AuthorizationServer.Tests;

internal static class FlurlExtensions
{
    public static T WithAuthorization<T>(
        this T obj,
        AuthenticationHeaderValue headerValue) where T : IHeadersContainer
    {
        return obj.WithHeader("Authorization", headerValue);
    }
}