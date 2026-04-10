using System.Data;
using Activout.DatabaseClient.Dapper;
using Activout.DatabaseClient.Implementation;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Email;
using Nordray.WhiteRabbit.Infrastructure.Audit;
using Nordray.WhiteRabbit.Infrastructure.Grants;
using Nordray.WhiteRabbit.Infrastructure.LoginCodes;

namespace Nordray.WhiteRabbit.Infrastructure;

public static class InfrastructureServiceExtensions
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services, IConfiguration configuration)
    {
        // --- Database ---
        services.Configure<DatabaseOptions>(configuration.GetSection("Database"));

        // One connection per request (SQLite is fine with this)
        services.AddScoped<IDbConnection>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            return new SqliteConnection(opts.ConnectionString);
        });

        services.AddScoped<DatabaseClientBuilder>();

        services.AddScoped<IUserRepository>(sp =>
            sp.GetRequiredService<DatabaseClientBuilder>()
              .With(new DapperGateway(sp.GetRequiredService<IDbConnection>()))
              .Build<IUserRepository>());

        services.AddScoped<ILoginCodeRepository>(sp =>
            sp.GetRequiredService<DatabaseClientBuilder>()
              .With(new DapperGateway(sp.GetRequiredService<IDbConnection>()))
              .Build<ILoginCodeRepository>());

        // Initializer uses its own short-lived connection (only called once at startup)
        services.AddSingleton<DatabaseInitializer>(sp =>
        {
            var opts = sp.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            return new DatabaseInitializer(opts.ConnectionString);
        });

        // --- Email ---
        services.Configure<MailjetOptions>(configuration.GetSection("Mailjet"));
        services.AddSingleton<IEmailService, MailjetEmailService>();

        // --- Login codes ---
        services.Configure<LoginCodeOptions>(configuration.GetSection("LoginCode"));
        services.AddScoped<ILoginCodeService, LoginCodeService>();

        // --- Grants ---
        services.AddScoped<IGrantService, GrantService>();

        // --- Audit ---
        services.AddScoped<IAuditService, AuditService>();

        return services;
    }
}
