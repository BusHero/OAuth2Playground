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
            .PerformRegisterRequest(RegisterRequest.Valid);

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory]
    [InlineData("client_id")]
    [InlineData("client_secret")]
    public async Task HappyPath_ResponseContainsExpectedKeys(string key)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid);

        var json = await result
            .GetJsonAsync<Dictionary<string, object>>();

        json.Should()
            .ContainKey(key)
            .WhoseValue
            .Should()
            .NotBeNull();
    }

    [Theory, AutoData]
    public async Task InvalidTokenEndpointAuthMethod_Returns400(
        string tokenEndpointAuthMethod)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                TokenEndpointAuthMethod = tokenEndpointAuthMethod
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory, AutoData]
    public async Task InvalidTokenEndpointAuthMethod_ReturnsError(
        string tokenEndpointAuthMethod)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                TokenEndpointAuthMethod = tokenEndpointAuthMethod
            });

        var json = await result
            .GetJsonAsync<Dictionary<string, string>>();

        json.Should()
            .ContainKey("error")
            .WhoseValue
            .Should()
            .Be("invalid_client_metadata");
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
            .PerformRegisterRequest(RegisterRequest.Valid with
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

    [Theory, AutoData]
    public async Task InvalidGrantTypeAndResponseType_Returns400(
        string grantType,
        string responseType)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                GrantTypes = [grantType],
                ResponseTypes = [responseType],
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Theory]
    [MemberData(nameof(ValidCombinations))]
    public async Task ValidCombinationOfResponseTypeAndGrantType_Returns200(
        DataFoo data)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                GrantTypes = data.RequestGrantType,
                ResponseTypes = data.RequestResponseType,
            });

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    public static TheoryData<DataFoo> ValidCombinations => new()
    {
        new DataFoo { RequestGrantType = [], RequestResponseType = [] },
        new DataFoo { RequestGrantType = [], RequestResponseType = ["code"] },
        new DataFoo { RequestGrantType = ["authorization_code"], RequestResponseType = [] },
        new DataFoo { RequestGrantType = ["authorization_code"], RequestResponseType = ["code"] },
        new DataFoo { RequestGrantType = ["refresh_token"], RequestResponseType = [] },
        new DataFoo { RequestGrantType = ["refresh_token"], RequestResponseType = ["code"] },
        new DataFoo { RequestGrantType = ["authorization_code", "refresh_token"], RequestResponseType = [] },
        new DataFoo { RequestGrantType = ["authorization_code", "refresh_token"], RequestResponseType = ["code"] },
    };
}

public sealed record DataFoo
{
    public required string[] RequestGrantType { get; init; }

    public required string[] RequestResponseType { get; init; }
}