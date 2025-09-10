using Flurl.Http;

namespace AuthorizationServer.Tests;

public sealed class AntiForgeryTokenTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>, IDisposable
{
    private readonly FlurlClient _client = new FlurlClient(authorizationServiceFactory.CreateDefaultClient());

    [Fact]
    public async Task FOo()
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("example")
            .GetAsync(cancellationToken: TestContext.Current.CancellationToken);

        var token = await AntiForgeryTokenExtractor
            .ExtractAntiForgeryValues(result.ResponseMessage);

        var data = new Dictionary<string, string?>
        {
            ["comment"] = "a new comment",
        };

        if (token.FormFieldName is not null)
        {
            data[token.FormFieldName] = token.FormFieldValue;
        }

        var result2 = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("handle-form")
            .WithCookie(token.CookieName, token.CookieValue)
            .PostUrlEncodedAsync(data, cancellationToken: TestContext.Current.CancellationToken);

        result2
            .StatusCode
            .Should()
            .Be(200);
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}