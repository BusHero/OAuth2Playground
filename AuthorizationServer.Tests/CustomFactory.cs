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
            services.RemoveAll(typeof(IRequestsRepository));
            services.AddSingleton<IClientRepository>(_ => ClientRepository);
            services.AddSingleton<IRequestsRepository>(_ => RequestsRepository);
        });
    }

    public InMemoryClientRepository ClientRepository { get; } = new();

    public InMemoryRequestsRepository RequestsRepository { get; set; } = new();
}