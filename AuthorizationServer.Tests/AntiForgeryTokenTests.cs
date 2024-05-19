using Flurl.Http;

namespace AuthorizationServer.Tests;

public class AntiForgeryTokenTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly FlurlClient _client = new FlurlClient(authorizationServiceFactory.CreateDefaultClient());

    [Fact]
    public async Task FOo()
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("example")
            .GetAsync();

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
            .PostUrlEncodedAsync(data);

        result2
            .StatusCode
            .Should()
            .Be(200);
    }
}