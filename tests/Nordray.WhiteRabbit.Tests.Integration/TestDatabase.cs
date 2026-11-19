using System.Data.Common;
using Activout.DatabaseClient.Dapper;
using Activout.DatabaseClient.Implementation;
using Activout.DatabaseClient.LibSql;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Tests.Integration;

/// <summary>A migrated libSQL database in a temporary file, deleted on dispose.</summary>
public sealed class TestDatabase : IAsyncDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "wr-tests-" + Guid.NewGuid().ToString("N"));

    private TestDatabase()
    {
        SqliteTypeHandlers.Register();
        ConnectionString = "Data Source=" + Path.Combine(_directory, "white-rabbit.db");
        Factory = new DatabaseConnectionFactory(Options.Create(new DatabaseOptions { ConnectionString = ConnectionString }));
    }

    public string ConnectionString { get; }
    public DatabaseConnectionFactory Factory { get; }

    public static async Task<TestDatabase> CreateAsync(bool migrate = true)
    {
        var db = new TestDatabase();
        if (migrate)
        {
            await using var connection = db.Factory.Create();
            await new DatabaseMigrator(connection, NullLogger<DatabaseMigrator>.Instance).MigrateAsync();
        }
        return db;
    }

    /// <summary>A DAO over its own connection. Pass the same connection to share a transaction.</summary>
    public static T Dao<T>(DbConnection connection) where T : class =>
        new DatabaseClientBuilder().With(new LibSqlGateway(connection)).Build<T>();

    public ValueTask DisposeAsync()
    {
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        return ValueTask.CompletedTask;
    }
}
