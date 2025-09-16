using Microsoft.AspNetCore.Mvc.Testing;

namespace AuthorizationServer.Tests.Flows.ClientCredentials;

public sealed class CustomImplementationTests(
    WebApplicationFactory<AuthorizationServer.Program> factory)
    : ClientCredentialsFlowTestsBase(factory.CreateClient()),
    IClassFixture<WebApplicationFactory<AuthorizationServer.Program>>;
