using System.Diagnostics.CodeAnalysis;
using FluentAssertions.Execution;
using Flurl.Http;

namespace AuthorizationServer.Tests;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Local")]
public sealed class TokenTests(CustomFactory factory)
    : IClassFixture<CustomFactory>
{
    private readonly FlurlClient _client
        = new(factory.CreateDefaultClient());

    private readonly InMemoryClientRepository _clientRepository
        = factory.ClientRepository;

    [Theory, AutoData]
    public async Task BasicAuth_ReturnsBackCliendIdAndClientToken(
        string client,
        string secret)
    {
        var result = await _client
            .Request()
            .AppendPathSegment("token")
            .WithBasicAuth(client, secret)
            .PostAsync();

        using (new AssertionScope())
        {
            result.StatusCode.Should().Be(200);
            var json = await result.GetJsonAsync<SuccessResponse>();
            json.Should()
                .BeEquivalentTo(new SuccessResponse(client, secret));
        }
    }

    [Fact]
    public async Task NoAuth_Returns401()
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostAsync();

        using (new AssertionScope())
        {
            result.StatusCode.Should().Be(401);
            var error = await result.GetJsonAsync<ErrorResponse>();
            error.Error.Should().Be("invalid_client");
        }
    }

    [Theory, AutoData]
    public async Task ClientAndSecretInBody_ReturnsThem(
        string client,
        string secret)
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client,
                ["secret"] = secret,
            });

        using (new AssertionScope())
        {
            result.StatusCode.Should().Be(200);
            var json = await result.GetJsonAsync<SuccessResponse>();
            json.Should().BeEquivalentTo(new SuccessResponse(client, secret));
        }
    }

    [Theory, AutoData]
    public async Task DetailsInBothHeaderAndBody_401(
        string client,
        string secret)
    {
        var result = await _client
            .Request()
            .AllowAnyHttpStatus()
            .AppendPathSegment("token")
            .WithBasicAuth(client, secret)
            .PostUrlEncodedAsync(new Dictionary<string, string>
            {
                ["client"] = client,
                ["secret"] = secret,
            });

        using (new AssertionScope())
        {
            result.StatusCode.Should().Be(401);
            var error = await result.GetJsonAsync<ErrorResponse>();
            error.Error.Should().Be("invalid_client");
        }
    }

    private sealed record ErrorResponse(string Error);

    private sealed record SuccessResponse(string Client, string Secret);
}