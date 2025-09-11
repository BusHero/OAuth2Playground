// Copyright (c) Duende Software. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root for license information.

using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;
using System.Globalization;

namespace IdentityServerHost;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1515:Consider making public types internal", Justification = "Class used outside the assembly")]
public sealed class Program
{
    private static void Main(string[] args)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console(formatProvider: CultureInfo.InvariantCulture)
            .CreateBootstrapLogger();

        Log.Information("Starting up");

        try
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Host.UseSerilog((ctx, lc) => lc
                .MinimumLevel.Debug()
                .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
                .MinimumLevel.Override("System", LogEventLevel.Warning)
                .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information)
                .Enrich.FromLogContext()
                .WriteTo.Console(formatProvider: CultureInfo.InvariantCulture, outputTemplate: "[{Timestamp:HH:mm:ss} {Level}] {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}", theme: AnsiConsoleTheme.Code));

            var app = builder
                .ConfigureServices()
                .ConfigurePipeline();

            app.Run();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "Unhandled exception");
            throw;
        }
        finally
        {
            Log.Information("Shut down complete");
            Log.CloseAndFlush();
        }
    }
}