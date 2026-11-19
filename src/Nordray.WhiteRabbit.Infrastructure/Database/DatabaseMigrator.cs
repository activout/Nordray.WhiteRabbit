using System.Data.Common;
using System.Reflection;
using Microsoft.Extensions.Logging;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

/// <summary>
/// Applies the embedded <c>Database/Schema/NNN_name.sql</c> files in order, once each, and records them in
/// <c>SchemaMigrations</c>. Bootstrap code, so it uses plain ADO.NET commands without parameters.
/// <para>
/// Each migration runs in one transaction together with its <c>SchemaMigrations</c> row, so a crash or error leaves
/// it either fully applied and recorded or not at all (SQLite and libSQL roll back DDL). The row is inserted first:
/// that takes the database's write lock, so a second instance starting at the same time cannot apply the same
/// migration. The libSQL provider neither waits for locks nor tells a lock apart from other errors, so a failed run
/// is retried a few times with a short back-off: an instance that lost the race then finds the migration applied,
/// while a genuinely broken migration is rolled back each time and finally fails start-up.
/// </para>
/// Never edit an applied migration; add a new numbered file.
/// </summary>
public sealed class DatabaseMigrator(DbConnection connection, ILogger<DatabaseMigrator> logger)
{
    private const string ResourcePrefix = "Schema.";

    public sealed record Migration(int Version, string Name, string Sql);

    /// <summary>All migrations shipped with this build, ordered by version.</summary>
    public static IReadOnlyList<Migration> Embedded { get; } = LoadEmbedded();

    private const int Attempts = 5;

    /// <summary>Back-off unit between attempts (grows quadratically). Tests shorten it.</summary>
    internal TimeSpan RetryDelay { get; init; } = TimeSpan.FromMilliseconds(100);

    public Task MigrateAsync(CancellationToken ct = default) => MigrateAsync(Embedded, ct);

    /// <summary>Applies the given migrations (the embedded ones in production; tests pass their own).</summary>
    internal async Task MigrateAsync(IEnumerable<Migration> migrations, CancellationToken ct = default)
    {
        var ordered = migrations.OrderBy(m => m.Version).ToList();
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await EnsureOpenAsync(ct);
                await ExecuteAsync(
                    "CREATE TABLE IF NOT EXISTS SchemaMigrations (Version INTEGER NOT NULL PRIMARY KEY, Name TEXT NOT NULL, AppliedUtc TEXT NOT NULL)",
                    ct);
                foreach (var migration in ordered)
                {
                    if (!(await AppliedVersionsAsync(ct)).Contains(migration.Version))
                        await ApplyAsync(migration, ct);
                }
                return;
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                if (attempt == Attempts)
                    throw new InvalidOperationException($"Database migration failed {Attempts} times; every failed migration was rolled back.", ex);
                logger.LogWarning(ex, "Database migration attempt {Attempt} failed (another instance may hold the lock); retrying", attempt);
                await Task.Delay(RetryDelay * (attempt * attempt), ct);
            }
        }
    }

    private async Task ApplyAsync(Migration migration, CancellationToken ct)
    {
        logger.LogInformation("Applying migration {Version} {Name}", migration.Version, migration.Name);
        await using var tx = await connection.BeginTransactionAsync(ct);

        // Version is an integer and Name comes from an embedded resource name checked in LoadEmbedded.
        var now = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss.fff", System.Globalization.CultureInfo.InvariantCulture);
        await ExecuteAsync(
            $"INSERT INTO SchemaMigrations (Version, Name, AppliedUtc) VALUES ({migration.Version}, '{migration.Name}', '{now}')", ct, tx);

        // Statement by statement: libSQL over HTTP does not accept a multi-statement batch in one command.
        foreach (var statement in SplitStatements(migration.Sql))
            await ExecuteAsync(statement, ct, tx);

        await tx.CommitAsync(ct);
    }

    /// <summary>Migrations shipped with this build that the database has not applied. Used by the readiness check.</summary>
    public async Task<IReadOnlyList<int>> PendingVersionsAsync(CancellationToken ct = default)
    {
        await EnsureOpenAsync(ct);
        var applied = await TableExistsAsync("SchemaMigrations", ct) ? await AppliedVersionsAsync(ct) : [];
        return Embedded.Select(m => m.Version).Where(v => !applied.Contains(v)).ToList();
    }

    /// <summary>
    /// Splits a migration into statements. <c>--</c> comments, whole-line or trailing, are removed first, so a
    /// comment may contain semicolons. Migrations must therefore not contain <c>--</c> or <c>;</c> inside string literals.
    /// </summary>
    internal static IEnumerable<string> SplitStatements(string sql) =>
        string.Join('\n', sql.Split('\n').Select(StripComment))
            .Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => s.Length > 0);

    private static string StripComment(string line)
    {
        var comment = line.IndexOf("--", StringComparison.Ordinal);
        return (comment < 0 ? line : line[..comment]).TrimEnd();
    }

    private async Task<HashSet<int>> AppliedVersionsAsync(CancellationToken ct)
    {
        var applied = new HashSet<int>();
        await using var command = connection.CreateCommand();
        command.CommandText = "SELECT Version FROM SchemaMigrations";
        await using var reader = await command.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            applied.Add(Convert.ToInt32(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture));
        return applied;
    }

    private async Task<bool> TableExistsAsync(string table, CancellationToken ct)
    {
        await using var command = connection.CreateCommand();
        // table is a compile-time constant, never user input.
        command.CommandText = $"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = '{table}'";
        return Convert.ToInt64(await command.ExecuteScalarAsync(ct), System.Globalization.CultureInfo.InvariantCulture) > 0;
    }

    private async Task EnsureOpenAsync(CancellationToken ct)
    {
        if (connection.State != System.Data.ConnectionState.Open)
            await connection.OpenAsync(ct);
    }

    private async Task ExecuteAsync(string sql, CancellationToken ct, DbTransaction? transaction = null)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Transaction = transaction;
        await command.ExecuteNonQueryAsync(ct);
    }

    private static IReadOnlyList<Migration> LoadEmbedded()
    {
        var assembly = typeof(DatabaseMigrator).Assembly;
        var migrations = new List<Migration>();
        foreach (var resource in assembly.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal)))
        {
            var name = Path.GetFileNameWithoutExtension(resource[ResourcePrefix.Length..]);
            var underscore = name.IndexOf('_');
            if (underscore <= 0 || !int.TryParse(name[..underscore], out var version)
                || !name.All(c => char.IsAsciiLetterOrDigit(c) || c == '_'))
                throw new InvalidOperationException($"Migration resource '{resource}' must be named NNN_name.sql (letters, digits, underscores).");
            using var stream = assembly.GetManifestResourceStream(resource)!;
            using var reader = new StreamReader(stream);
            migrations.Add(new Migration(version, name, reader.ReadToEnd()));
        }

        var duplicate = migrations.GroupBy(m => m.Version).FirstOrDefault(g => g.Count() > 1);
        if (duplicate is not null)
            throw new InvalidOperationException($"Two migrations share version {duplicate.Key}.");
        return migrations.OrderBy(m => m.Version).ToList();
    }
}
