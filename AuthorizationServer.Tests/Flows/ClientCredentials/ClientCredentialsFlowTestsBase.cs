using AuthorizationServer.Tests;
using Microsoft.AspNetCore.Http;
using Shouldly;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace AuthorizationServer.Tests.Flows.ClientCredentials;

public abstract class ClientCredentialsFlowTestsBase(HttpClient client)
{
    private const string VALID_CLIENT_ID = "client.credentials.sample";
    private const string VALID_SECRET = "secret";
    private const string GRANT_TYPE = "client_credentials";
    private const string VALID_SCOPE_1 = "scope1";
    private const string VALID_SCOPE_2 = "scope2";
    private const string VALID_AUTHENTICATION_SCHEME = "Basic";
    private readonly Uri tokenUri = new("/connect/token", UriKind.Relative);

    [Theory]
    [InlineData(VALID_SCOPE_1)]
    [InlineData(VALID_SCOPE_2)]
    public async Task AuthenticationInHeaderReturnsOk(string scope)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", scope),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadFromJsonAsync<TokenResponse>(TestContext.Current.CancellationToken);

        content!.ShouldSatisfyAllConditions(
            x => x.AccessToken.ShouldNotBeNull(),
            x => x.TokenType.ShouldBe("Bearer"),
            x => x.ExperiesIn.ShouldBe(3600),
            x => x.Scope.ShouldBe(scope));
    }

    [Fact]
    public async Task AuthenticationInBodyReturnsOk()
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("client_id", VALID_CLIENT_ID),
            new KeyValuePair<string, string>("client_secret", VALID_SECRET),
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadFromJsonAsync<TokenResponse>(TestContext.Current.CancellationToken);

        content!.ShouldSatisfyAllConditions(
            x => x.AccessToken.ShouldNotBeNull(),
            x => x.TokenType.ShouldBe("Bearer"),
            x => x.ExperiesIn.ShouldBe(3600),
            x => x.Scope.ShouldBe(VALID_SCOPE_1));
    }

    [Fact]
    public async Task NoScopeReturnsOk()
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadFromJsonAsync<TokenResponse>(TestContext.Current.CancellationToken);
        content!.ShouldSatisfyAllConditions(
            x => x.AccessToken.ShouldNotBeNull(),
            x => x.TokenType.ShouldBe("Bearer"),
            x => x.ExperiesIn.ShouldBe(3600),
            x => x.ParseScopes().ShouldBe([VALID_SCOPE_1, VALID_SCOPE_2]));
    }

    [Theory, AutoData]
    public async Task RequestInvalidScopeReturnsBadRequest(string invalidScope)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", invalidScope),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task InvalidPasswordReturnsBadRequest(string invalidPassword)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{invalidPassword}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task InvalidClientReturnsBadRequest(string invalidClient)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{invalidClient}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task MissingGrantTypeReturnsBadRequest()
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task InvalidGrantTypeReturnsBadRequest(string invalidGrantType)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", invalidGrantType),
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task InvalidAuthenticationSchemeReturnsBadRequest(string invalidAuthenticationScheme)
    {
        using var body = new FormUrlEncodedContent([
            new KeyValuePair<string, string>("grant_type", GRANT_TYPE),
            new KeyValuePair<string, string>("scope", VALID_SCOPE_1),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            invalidAuthenticationScheme,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task NoFieldsInBodyReturnsBadRequest(string invalidAuthenticationScheme)
    {
        using var body = new FormUrlEncodedContent([]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            invalidAuthenticationScheme,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task NonFormDataReturnsBadRequest(string invalidAuthenticationScheme)
    {
        var body = JsonSerializer.Serialize(new { grant_type = GRANT_TYPE, scope = VALID_SCOPE_1, });
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = new StringContent(body),
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new AuthenticationHeaderValue(
            invalidAuthenticationScheme,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }
}
