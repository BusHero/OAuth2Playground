using AuthorizationServer.Tests;
using Microsoft.AspNetCore.Http;
using Phoesion.DevJwt;
using Shouldly;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

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
            new("grant_type", GRANT_TYPE),
            new("scope", scope),
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
    public async Task RequestProtectedResourceWithConfiguredAuthenticationReturnsOk()
    {
        using var body = new FormUrlEncodedContent([
            new ("grant_type", GRANT_TYPE),
            new ("scope", VALID_SCOPE_2),
        ]);
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            Content = body,
            RequestUri = tokenUri,
        };
        request.Headers.Authorization = new(
            VALID_AUTHENTICATION_SCHEME,
            Convert.ToBase64String(
                Encoding.UTF8.GetBytes($"{VALID_CLIENT_ID}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadFromJsonAsync<TokenResponse>(TestContext.Current.CancellationToken);
        var token = content!.AccessToken!;

        using var resourceClient = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:5002")
        };
        resourceClient.DefaultRequestHeaders.Authorization = new("Bearer", token);
        var result = await resourceClient.GetAsync("/identity", TestContext.Current.CancellationToken);
        result.EnsureSuccessStatusCode();

        var content2 = await result.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        content2.ShouldNotBeNullOrEmpty();
    }

    [Fact]
    public async Task NoTokenReturnsUnauthorized()
    {
        using var resourceClient = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:5002")
        };

        var result = await resourceClient.GetAsync("/identity", TestContext.Current.CancellationToken);

        result.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Theory, AutoData]
    public async Task NonJwtTokenReturnsUnauthorized(string invalidToken)
    {
        using var resourceClient = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:5002")
        };
        resourceClient.DefaultRequestHeaders.Authorization = new("Bearer", invalidToken);

        var result = await resourceClient.GetAsync("/identity", TestContext.Current.CancellationToken);

        result.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AdHocJwtTokenReturnsUnauthorized()
    {
        //var token = TokenGenerator.Create("https://localhost:5001/resources")
        //    .AddClaimIssuer("https://localhost:5001")
        //    .AddScope("scope1")
        //    .AddAudience("resource1")
        //    .AddClaim("client_id", "client.credentials.sample")
        //    .ExpiresIn(TimeSpan.FromDays(365))
        //    .Build();
        var token = @"eyJhbGciOiJSUzI1NiIsInR5cCI6ImF0K0pXVCIsImtpZCI6ImQ0MWFiYWRkZWQ5YmVhY2ZjNjJlZjk0YzJjODc2ZDZlIn0.eyJpc3MiOiJodHRwczovL2xvY2FsaG9zdDo1MDAxIiwibmJmIjoxNzU3Njg3NjE5LCJpYXQiOjE3NTc2ODc2MTksImV4cCI6MTc1NzY5MTIxOSwiYXVkIjpbInJlc291cmNlMSIsImh0dHBzOi8vbG9jYWxob3N0OjUwMDEvcmVzb3VyY2VzIl0sInNjb3BlIjpbInNjb3BlMiJdLCJjbGllbnRfaWQiOiJjbGllbnQuY3JlZGVudGlhbHMuc2FtcGxlIiwianRpIjoiMEU0QkYxRDBFNDRGOEJFOUE3QzdFMzREM0IzOUE1QzIifQ.pfMtV0CkJeObzI5P9JRkwd98l6yGmgwvPC1ubbsRo5XCmIe2_d6S8ycHvuz6nFvvPCNOTM7zydd3uFTM9CxB9PQPhywzDs6IUJHin5xTEbCdHNSOX-GqjO49_9ZGrTFoH4Z-5ktHjFr_3amKaW0K-fJ9U-Ghp6R_IMWJYsHLZFjmmD6ySwCwr9TAsmzlBZkeRBYRHGC49YrMzCD_d_pTpkSAS7gkzGraKLBJIGBw38y_9j4h9-MYwcC302_OTh2ML3HPSnuxqXtsCOumbR3_LwC50lRbeLlTS6xwZMEKPdSwNhKkYi-BLcoQRixo-SRbQpkaK9E-V8MCP1dsst3o6000BkK9ZPPMwMQmtBJ-rAZXzToPc8zbm541EuDePVWTYNUyMnr0HUhmcz8bv4XvWHaNpzjX-JYW-mXHrAo0_Goeo-G9du8y5wrA51z7jk2LyR1EzdMSjOwfzOtNCFc05XHpFHWtBoXmkNSEdL69Y47TlaaXDEoV5mOd8vIic0ceIy7wKpAw0zqtMISESXkYZRANONFpV0EgMK3Vy4zybWAAMrSbQkB2LOg_Wxdv5YMZMRL5Oh4SVp7QeuKhpNc2jG478C6krnSjnSymG9xXCcgaT0AbganWPPXFF-Rrt5IMPO8XktV5lpGtAQ0_FU8urkbkYn74VLdNge8qwI9UBxg";
        using var resourceClient = new HttpClient
        {
            BaseAddress = new Uri("https://localhost:5002")
        };
        resourceClient.DefaultRequestHeaders.Authorization = new("Bearer", token);

        var result = await resourceClient.GetAsync("/identity", TestContext.Current.CancellationToken);

        result.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task AuthenticationInBodyReturnsOk()
    {
        using var body = new FormUrlEncodedContent([
            new("client_id", VALID_CLIENT_ID),
            new("client_secret", VALID_SECRET),
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
            x => x.Scope.ShouldBe(VALID_SCOPE_1));
    }

    [Theory, AutoData]
    public async Task WrongAuthenticationInHeaderReturnsBadRequest(string invalidClientId)
    {
        using var body = new FormUrlEncodedContent([
            new("client_id", VALID_CLIENT_ID),
            new("client_secret", VALID_SECRET),
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
                Encoding.UTF8.GetBytes($"{invalidClientId}:{VALID_SECRET}")));
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.BadRequest);
    }

    [Theory, AutoData]
    public async Task WrongAuthenticationInBodyReturnsBadRequest(string invalidClientId)
    {
        using var body = new FormUrlEncodedContent([
            new("client_id", invalidClientId),
            new("client_secret", VALID_SECRET),
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
    }

    [Fact]
    public async Task AuthenticationInBodyAndHeaderReturnsOk()
    {
        using var body = new FormUrlEncodedContent([
            new("client_id", VALID_CLIENT_ID),
            new("client_secret", VALID_SECRET),
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
            new("grant_type", GRANT_TYPE),
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
            new("grant_type", GRANT_TYPE),
            new("scope", invalidScope),
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
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
            new("scope", VALID_SCOPE_1),
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
            new("grant_type", invalidGrantType),
            new("scope", VALID_SCOPE_1),
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
            new("grant_type", GRANT_TYPE),
            new("scope", VALID_SCOPE_1),
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
