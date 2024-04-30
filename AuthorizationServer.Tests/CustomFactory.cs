using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace AuthorizationServer.Tests;

public sealed class CustomFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.RemoveAll(typeof(IClientRepository));
            services.AddSingleton<IClientRepository>(_ => ClientRepository);
        });
    }

    public InMemoryClientRepository ClientRepository { get; } = new();

}