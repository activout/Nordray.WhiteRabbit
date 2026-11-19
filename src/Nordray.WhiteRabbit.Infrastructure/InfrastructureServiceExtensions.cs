using System.Data.Common;
using Activout.DatabaseClient.Dapper;
using Activout.DatabaseClient.Implementation;
using Activout.DatabaseClient.LibSql;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Audit;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Infrastructure.Email;
using Nordray.WhiteRabbit.Infrastructure.Encryption;
using Nordray.WhiteRabbit.Infrastructure.Grants;
using Nordray.WhiteRabbit.Infrastructure.LoginCodes;

namespace Nordray.WhiteRabbit.Infrastructure;

public static class InfrastructureServiceExtensions
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services, IConfiguration configuration)
    {
        // Lets Dapper read DateTime values stored as text. Global, so it is registered once here.
        SqliteTypeHandlers.Register();

        // --- Database ---
        services.Configure<DatabaseOptions>(configuration.GetSection("Database"));
        services.AddSingleton<DatabaseConnectionFactory>();

        // One connection per request, shared by every DAO in the request so they can share a transaction.
        services.AddScoped<DbConnection>(sp => sp.GetRequiredService<DatabaseConnectionFactory>().Create());

        AddDao<IUserRepository>(services);
        AddDao<ILoginCodeRepository>(services);
        AddDao<IGrantDao>(services);
        AddDao<IAuditDao>(services);
        AddDao<ICapabilityDao>(services);
        AddDao<IDataProtectionKeyDao>(services);

        services.AddSingleton<DatabaseInitializer>();

        // --- Key-ring encryption ---
        services.Configure<DataProtectionOptions>(configuration.GetSection("DataProtection"));
        services.AddSingleton<KeyRingEncryption>();

        // --- Who may sign in ---
        services.Configure<AccessOptions>(configuration.GetSection("Access"));
        services.AddSingleton(sp =>
        {
            // Follows configuration reloads, so removing an address takes effect without a restart.
            var monitor = sp.GetRequiredService<IOptionsMonitor<AccessOptions>>();
            var policy = new SignInPolicy(monitor.CurrentValue);
            monitor.OnChange(policy.Update);
            return policy;
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

    private static void AddDao<T>(IServiceCollection services) where T : class =>
        services.AddScoped(sp => new DatabaseClientBuilder()
            .With(new LibSqlGateway(sp.GetRequiredService<DbConnection>()))
            .Build<T>());
}
