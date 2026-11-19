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
        foreach (var table in new[] { "Users", "LoginCodes", "OAuthClients", "Capabilities", "Grants", "GrantCapabilities", "DataProtectionKeys", "WorkloadBindings", "CliSessions", "VirtualCredentials", "SecurityEvents" })
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
    public async Task Migrate_FailingMigration_IsRolledBackAndNotRecorded()
    {
        await using var db = await TestDatabase.CreateAsync(migrate: false);
        await using var connection = db.Factory.Create();
        var migrator = new DatabaseMigrator(connection, NullLogger<DatabaseMigrator>.Instance) { RetryDelay = TimeSpan.Zero };
        var broken = new DatabaseMigrator.Migration(1, "001_broken", "CREATE TABLE Half (Id INTEGER); INSERT INTO NoSuchTable VALUES (1);");

        await Assert.ThrowsAnyAsync<Exception>(() => migrator.MigrateAsync([broken]));

        Assert.Equal(0, await ScalarAsync(connection, "SELECT COUNT(*) FROM sqlite_master WHERE name = 'Half'"));
        Assert.Equal(0, await ScalarAsync(connection, "SELECT COUNT(*) FROM SchemaMigrations"));

        // Fixed and retried, it applies cleanly: nothing was left half-done.
        await migrator.MigrateAsync([broken with { Sql = "CREATE TABLE Half (Id INTEGER);" }]);
        Assert.Equal(1, await ScalarAsync(connection, "SELECT COUNT(*) FROM SchemaMigrations"));
    }

    [Fact]
    public async Task Migrate_TwoInstancesAtOnce_ApplyEachMigrationOnce()
    {
        await using var db = await TestDatabase.CreateAsync(migrate: false);
        await using var a = db.Factory.Create();
        await using var b = db.Factory.Create();
        var results = await Task.WhenAll(
            Task.Run(() => TryMigrate(a)),
            Task.Run(() => TryMigrate(b)));

        // Both succeed (the loser retries); neither leaves the schema half-applied or applies a migration twice.
        Assert.Equal([true, true], results);
        await using var check = db.Factory.Create();
        var migrator = new DatabaseMigrator(check, NullLogger<DatabaseMigrator>.Instance);
        await migrator.MigrateAsync();
        Assert.Empty(await migrator.PendingVersionsAsync());
        Assert.Equal(DatabaseMigrator.Embedded.Count, await ScalarAsync(check, "SELECT COUNT(*) FROM SchemaMigrations"));

        static async Task<bool> TryMigrate(DbConnection connection)
        {
            try
            {
                await new DatabaseMigrator(connection, NullLogger<DatabaseMigrator>.Instance).MigrateAsync();
                return true;
            }
            catch (InvalidOperationException)
            {
                return false;
            }
        }
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
            CREATE TABLE A (
                Id INTEGER -- trailing comment; also with a semicolon
            );

            CREATE TABLE B (Id INTEGER);
            ;
            """).ToList();

        Assert.Equal(2, statements.Count);
        Assert.Equal("CREATE TABLE A (\n    Id INTEGER\n)", statements[0].ReplaceLineEndings("\n"));
        Assert.Equal("CREATE TABLE B (Id INTEGER)", statements[1]);
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
