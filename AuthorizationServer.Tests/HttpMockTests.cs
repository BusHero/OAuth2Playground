using System.Net;
using WireMock.Server;
using WireMock.FluentAssertions;

namespace AuthorizationServer.Tests;

public sealed class HttpMockTests
{
    [Fact]
    public async Task FullyConfigured()
    {
        using var server = WireMockServer.Start(8888);

        using var client = new HttpClient()
        {
            BaseAddress = new Uri("http://localhost:8888")
        };

        var result = await client.GetAsync("/hello", TestContext.Current.CancellationToken);

        result.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task FluentAssertions()
    {
        using var server = WireMockServer.Start(8888);

        using var client = new HttpClient()
        {
            BaseAddress = new Uri("http://localhost:8888")
        };

        var result = await client.GetAsync(new Uri("hello"), TestContext.Current.CancellationToken);

        server.Should()
            .HaveReceivedACall()
            .AtUrl("http://localhost:8888/hello");
    }
}