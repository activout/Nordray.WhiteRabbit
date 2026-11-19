using System.Data.Common;
using Microsoft.Extensions.Logging.Abstractions;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Tests.Integration;

public class DatabaseMigratorTests
{
    [Fact]
    public async Task Migrate_EmptyDatabase_AppliesEveryMigrationAndNothingIsPending()
    {
        await using var db = await TestDatabase.CreateAsync(migrate: false);
        await using var connection = db.Factory.Create();
        var migrator = new DatabaseMigrator(connection, NullLogger<DatabaseMigrator>.Instance);

        Assert.Equal(DatabaseMigrator.Embedded.Select(m => m.Version), await migrator.PendingVersionsAsync());

        await migrator.MigrateAsync();

        Assert.Empty(await migrator.PendingVersionsAsync());
        Assert.Equal(DatabaseMigrator.Embedded.Count, await ScalarAsync(connection, "SELECT COUNT(*) FROM SchemaMigrations"));
        foreach (var table in new[] { "Users", "LoginCodes", "OAuthClients", "Capabilities", "Grants", "GrantCapabilities", "AuditEvents", "DataProtectionKeys" })
            Assert.Equal(1, await ScalarAsync(connection, $"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '{table}'"));
    }

    [Fact]
    public async Task Migrate_Twice_IsANoOp()
    {
        await using var db = await TestDatabase.CreateAsync();
        await using var connection = db.Factory.Create();
        var migrator = new DatabaseMigrator(connection, NullLogger<DatabaseMigrator>.Instance);

        await migrator.MigrateAsync();

        Assert.Equal(DatabaseMigrator.Embedded.Count, await ScalarAsync(connection, "SELECT COUNT(*) FROM SchemaMigrations"));
    }

    [Fact]
    public void Embedded_VersionsAreUniqueAndStartAtOne()
    {
        var versions = DatabaseMigrator.Embedded.Select(m => m.Version).ToList();
        Assert.Equal(1, versions[0]);
        Assert.Equal(versions.Count, versions.Distinct().Count());
        Assert.Equal(versions.OrderBy(v => v), versions);
    }

    [Fact]
    public void SplitStatements_DropsCommentsAndEmptyStatements()
    {
        var statements = DatabaseMigrator.SplitStatements("""
            -- a comment; with a semicolon
            CREATE TABLE A (Id INTEGER);

            CREATE TABLE B (Id INTEGER);
            ;
            """).ToList();

        Assert.Equal(["CREATE TABLE A (Id INTEGER)", "CREATE TABLE B (Id INTEGER)"], statements);
    }

    [Theory]
    [InlineData("Data Source=./data/white-rabbit.db", "./data/white-rabbit.db")]
    [InlineData("Data Source=file:/var/lib/wr.db", "/var/lib/wr.db")]
    [InlineData("Data Source=:memory:", null)]
    [InlineData("Data Source=https://example.lite.bunnydb.net;Auth Token=secret", null)]
    [InlineData("Data Source=libsql://example.turso.io", null)]
    public void LocalFilePath_RecognisesLocalFiles(string connectionString, string? expected) =>
        Assert.Equal(expected, DatabaseConnectionFactory.LocalFilePath(connectionString));

    private static async Task<long> ScalarAsync(DbConnection connection, string sql)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt64(await command.ExecuteScalarAsync());
    }
}
