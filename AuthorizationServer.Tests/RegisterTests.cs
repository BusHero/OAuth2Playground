using FluentAssertions.Execution;

namespace AuthorizationServer.Tests;

public sealed class RegisterTests(
    CustomAuthorizationServiceFactory authorizationServiceFactory)
    : IClassFixture<CustomAuthorizationServiceFactory>
{
    private readonly Authenticator _authenticator = new(
        authorizationServiceFactory.CreateDefaultClient());

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

        var json = await result.GetJsonAsync<RegisterResponse>();

        json.TokenEndpointAuthMethod
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

    [Theory, MemberData(nameof(ValidCombinations))]
    public async Task ValidCombinationOfResponseTypeAndGrantType_Returns200(
        BlahBlahCombination data)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                GrantTypes = data.GrantTypes,
                ResponseTypes = data.ResponseTypes,
            });

        result
            .StatusCode
            .Should()
            .Be(200);
    }

    [Theory, MemberData(nameof(ReturnBackCombinations))]
    public async Task ValidCombinationOfResponseTypeAndGrantType_ReturnsExpectedGrantTypesAndResponseTypes(
        ReturnBackCombination data)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                GrantTypes = data.InputGrantTypes,
                ResponseTypes = data.InputResponseTypes,
            });

        var json = await result.GetJsonAsync<RegisterResponse>();

        using (new AssertionScope())
        {
            json.GrantTypes
                .Should()
                .BeEquivalentTo(data.OutputGrantTypes);

            json.ResponseTypes
                .Should()
                .BeEquivalentTo(data.OutputResponseTypes);
        }
    }

    [Fact]
    public async Task RedirectUris_Missing_Returns400()
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                RedirectUris = [],
            });

        result
            .StatusCode
            .Should()
            .Be(400);
    }

    [Fact]
    public async Task RedirectUris_Missing_ReturnsExpectedErrorMessage()
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                RedirectUris = [],
            });

        var json = await result.GetJsonAsync<Dictionary<string, string>>();

        json.Should()
            .ContainKey("error")
            .WhoseValue
            .Should()
            .Be("invalid_redirect_uri");
    }

    [Theory, AutoData]
    public async Task RedirectUri_Valid_RedirectUrisAreReturned(
        Uri[] redirectUris)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                RedirectUris = redirectUris,
            });

        var json = await result.GetJsonAsync<RegisterResponse>();

        json.RedirectUris
            .Should()
            .BeEquivalentTo(redirectUris);
    }

    [Theory, AutoData]
    public async Task Scope_Valid_IsSendBack(
        string scope)
    {
        var result = await _authenticator
            .PerformRegisterRequest(RegisterRequest.Valid with
            {
                Scope = scope,
            });

        var json = await result.GetJsonAsync<RegisterResponse>();

        json.Scope
            .Should()
            .BeEquivalentTo(scope);
    }

    public static TheoryData<BlahBlahCombination> ValidCombinations => new()
    {
        new() { GrantTypes = [], ResponseTypes = [] },
        new() { GrantTypes = [], ResponseTypes = ["code"] },
        new() { GrantTypes = ["authorization_code"], ResponseTypes = [] },
        new() { GrantTypes = ["authorization_code"], ResponseTypes = ["code"] },
        new() { GrantTypes = ["refresh_token"], ResponseTypes = [] },
        new() { GrantTypes = ["refresh_token"], ResponseTypes = ["code"] },
        new() { GrantTypes = ["authorization_code", "refresh_token"], ResponseTypes = [] },
        new() { GrantTypes = ["authorization_code", "refresh_token"], ResponseTypes = ["code"] },
    };

    public static TheoryData<ReturnBackCombination> ReturnBackCombinations => new()
    {
        new()
        {
            InputGrantTypes = [],
            InputResponseTypes = [],
            OutputGrantTypes = ["authorization_code"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = [],
            InputResponseTypes = ["code"],
            OutputGrantTypes = ["authorization_code"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["authorization_code"],
            InputResponseTypes = [],
            OutputGrantTypes = ["authorization_code"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["authorization_code"],
            InputResponseTypes = ["code"],
            OutputGrantTypes = ["authorization_code"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["refresh_token"],
            InputResponseTypes = [],
            OutputGrantTypes = ["authorization_code", "refresh_token"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["refresh_token"],
            InputResponseTypes = ["code"],
            OutputGrantTypes = ["authorization_code", "refresh_token"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["authorization_code", "refresh_token"],
            InputResponseTypes = [],
            OutputGrantTypes = ["authorization_code", "refresh_token"],
            OutputResponseTypes = ["code"],
        },
        new()
        {
            InputGrantTypes = ["authorization_code", "refresh_token"],
            InputResponseTypes = ["code"],
            OutputGrantTypes = ["authorization_code", "refresh_token"],
            OutputResponseTypes = ["code"],
        },
    };

    public sealed record ReturnBackCombination
    {
        public required string[] InputGrantTypes { get; init; }

        public required string[] InputResponseTypes { get; init; }

        public required string[] OutputGrantTypes { get; init; }

        public required string[] OutputResponseTypes { get; init; }
    }

    public sealed record BlahBlahCombination
    {
        public required string[] GrantTypes { get; init; }

        public required string[] ResponseTypes { get; init; }
    }
}