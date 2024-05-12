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
            .PerformRegisterRequest(new()
            {
                TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }
}