using System.Net;
using FluentAssertions;
using WireMock.Server;
using WireMock.FluentAssertions;

namespace AuthorizationServer.Tests;

public sealed class HttpMockTests
{
    [Fact]
    public async Task FullyConfigured()
    {
        using var server = WireMockServer.Start(8888);


        var client = new HttpClient()
        {
            BaseAddress = new Uri("http://localhost:8888")
        };

        var result = await client.GetAsync("hello");

        result.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task FluentAssertions()
    {
        using var server = WireMockServer.Start(8888);

        var client = new HttpClient()
        {
            BaseAddress = new Uri("http://localhost:8888")
        };

        var result = await client.GetAsync("hello");

        server.Should()
            .HaveReceivedACall()
            .AtUrl("http://localhost:8888/hello");
    }
}