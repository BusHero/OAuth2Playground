using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthorizationServer.Tests.Flows.ClientCredentials;

public sealed class TrustedImplementationTests(
    WebApplicationFactory<IdentityServerHost.Program> factory)
    : ClientCredentialsFlowTestsBase(factory.CreateClient()),
    IClassFixture<WebApplicationFactory<IdentityServerHost.Program>>;

public sealed class RealTrustedImplementationTests(
    RealTrustedImplementationTests.ClientFactory factory)
    : ClientCredentialsFlowTestsBase(factory.Client),
    IClassFixture<RealTrustedImplementationTests.ClientFactory>
{
    public class ClientFactory
    {
        public ClientFactory()
        {
            Client = new HttpClient
            {
                BaseAddress = new("https://localhost:5001/"),
            };
        }

        public HttpClient Client { get; }
    }
}
