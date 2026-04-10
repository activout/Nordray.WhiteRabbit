using Dapper;
using Microsoft.Data.Sqlite;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public sealed class DatabaseInitializer(string connectionString)
{
    public async Task InitializeAsync()
    {
        DatabaseTypeHandlers.Register();

        var directory = Path.GetDirectoryName(
            new SqliteConnectionStringBuilder(connectionString).DataSource);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);

        await using var connection = new SqliteConnection(connectionString);
        await connection.OpenAsync();

        foreach (var statement in DatabaseSchema.Statements)
            await connection.ExecuteAsync(statement);

        foreach (var migration in DatabaseSchema.Migrations)
        {
            try { await connection.ExecuteAsync(migration); }
            catch { /* column already exists — safe to ignore */ }
        }

        // Remove expired and old consumed codes to keep the table from growing unbounded.
        var cutoff = DateTimeOffset.UtcNow.AddHours(-24).ToString("O");
        await connection.ExecuteAsync("""
            DELETE FROM LoginCodes
            WHERE ExpiresUtc < @cutoff
               OR (ConsumedUtc IS NOT NULL AND ConsumedUtc < @cutoff)
            """, new { cutoff });
    }
}
