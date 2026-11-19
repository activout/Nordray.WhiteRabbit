using Activout.DatabaseClient.Dapper;
using Activout.DatabaseClient.Implementation;
using Activout.DatabaseClient.LibSql;
using Microsoft.Extensions.Logging;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

/// <summary>Runs once at start-up, before requests are served: applies migrations and prunes old login codes.</summary>
public sealed class DatabaseInitializer(DatabaseConnectionFactory connections, ILoggerFactory loggerFactory)
{
    public async Task InitializeAsync(CancellationToken ct = default)
    {
        await using var connection = connections.Create();
        await new DatabaseMigrator(connection, loggerFactory.CreateLogger<DatabaseMigrator>()).MigrateAsync(ct);

        // Remove expired and old consumed codes to keep the table from growing unbounded.
        var loginCodes = new DatabaseClientBuilder().With(new LibSqlGateway(connection)).Build<ILoginCodeRepository>();
        await loginCodes.DeleteExpiredAsync(DateTime.UtcNow.AddHours(-24));
    }
}
