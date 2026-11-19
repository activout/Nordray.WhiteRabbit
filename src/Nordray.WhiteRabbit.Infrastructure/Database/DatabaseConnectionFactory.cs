using System.Data.Common;
using Microsoft.Extensions.Options;
using Nelknet.LibSQL.Data;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

/// <summary>
/// Creates libSQL connections. The same provider serves a local file, an in-memory test database and Bunny Database,
/// so development, tests and production run the same SQL through the same driver.
/// </summary>
public sealed class DatabaseConnectionFactory
{
    private readonly string _connectionString;

    public DatabaseConnectionFactory(IOptions<DatabaseOptions> options)
    {
        _connectionString = options.Value.ConnectionString;
        if (string.IsNullOrWhiteSpace(_connectionString))
            throw new InvalidOperationException("Database:ConnectionString is required.");

        var file = LocalFilePath(_connectionString);
        var directory = file is null ? null : Path.GetDirectoryName(Path.GetFullPath(file));
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
    }

    public DbConnection Create() => new LibSQLConnection(_connectionString);

    /// <summary>The path of a local database file, or null for a remote or in-memory database.</summary>
    internal static string? LocalFilePath(string connectionString)
    {
        var builder = new DbConnectionStringBuilder { ConnectionString = connectionString };
        if (!builder.TryGetValue("Data Source", out var value) || value is not string source || source.Length == 0)
            return null;
        if (source == ":memory:" || source.Contains("://", StringComparison.Ordinal))
            return null;
        return source.StartsWith("file:", StringComparison.OrdinalIgnoreCase) ? source["file:".Length..] : source;
    }
}
