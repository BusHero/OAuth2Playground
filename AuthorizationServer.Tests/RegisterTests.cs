using FluentAssertions.Execution;

namespace AuthorizationServer.Tests;

public sealed class RegisterTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient(),
        authorizationServiceFactory.ClientRepository);

    [Fact]
    public async Task HappyPath_Returns200()
    {
        var result = await _authenticator
            .PerformRegisterRequest(new RegisterRequest()
            {
                TokenEndpointAuthMethod = "secret_basic"
            });

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory]
    [InlineData("client_id")]
    [InlineData("client_secret")]
    [InlineData("token_endpoint_auth_method")]
    public async Task HappyPath_ResponseContainsExpectedKeys(string key)
    {
        var result = await _authenticator
            .PerformRegisterRequest(new()
            {
                TokenEndpointAuthMethod = "secret_basic"
            });

        var json = await result
            .GetJsonAsync<Dictionary<string, object>>();

        json.Should()
            .ContainKey(key)
            .WhoseValue
            .Should()
            .NotBeNull();
    }

    [Theory, AutoData]
    public async Task InvalidTokenEndpointAuthMethod(
        string tokenEndpointAuthMethod)
    {
        var result = await _authenticator
            .PerformRegisterRequest(new RegisterRequest
            {
                TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            });

        using (new AssertionScope())
        {
            result
                .StatusCode
                .Should()
                .Be(400);

            var json = await result
                .GetJsonAsync<Dictionary<string, string>>();

            json.Should()
                .ContainKey("error")
                .WhoseValue
                .Should()
                .Be("invalid_client_metadata");
        }
    }

    [Theory]
    [InlineData(null, "secret_basic")]
    [InlineData("secret_basic", "secret_basic")]
    [InlineData("secret_post", "secret_post")]
    public async Task ValidTokenEndpointAuthMethod_ReturnsAuthMethod(
        string? requestTokenEndpointAuthMethod,
        string responseTokenEndpointAuthMethod)
    {
        var result = await _authenticator
            .PerformRegisterRequest(new()
            {
                TokenEndpointAuthMethod = requestTokenEndpointAuthMethod,
            });

        var json = await result.GetJsonAsync<Dictionary<string, string>>();

        json.Should()
            .ContainKey("token_endpoint_auth_method")
            .WhoseValue
            .Should()
            .Be(responseTokenEndpointAuthMethod);
    }
}