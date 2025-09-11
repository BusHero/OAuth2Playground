using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthorizationServer.Tests.Flows.ClientCredentials;

public sealed class TrustedImplementationTests(
    WebApplicationFactory<IdentityServerHost.Program> factory)
    : ClientCredentialsFlowTestsBase(factory.CreateClient()),
    IClassFixture<WebApplicationFactory<IdentityServerHost.Program>>
{
}
