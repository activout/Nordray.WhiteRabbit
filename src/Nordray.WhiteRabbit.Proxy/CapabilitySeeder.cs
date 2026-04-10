using System.Data;
using Dapper;
using Nordray.WhiteRabbit.Bunny;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Seeds the Capabilities table from the hard-coded BunnyOperationRegistry.
/// Called once at startup after the schema has been created.
/// Uses INSERT OR IGNORE so it is safe to run on every boot.
/// </summary>
public sealed class CapabilitySeeder(IDbConnection db, BunnyOperationRegistry registry)
{
    public async Task SeedAsync()
    {
        var now = DateTimeOffset.UtcNow.ToString("O");
        var seeded = new HashSet<string>();

        // Group by capability and take the lexicographically first OperationId as the
        // canonical source of DisplayName/Description, making seeding deterministic
        // regardless of the order operations appear in the registry.
        var capabilityOps = registry.GetAll()
            .Where(op => op.RequiredCapability is not null)
            .GroupBy(op => op.RequiredCapability!)
            .Select(g => g.OrderBy(op => op.OperationId).First());

        foreach (var op in capabilityOps)
        {
            await db.ExecuteAsync("""
                INSERT OR IGNORE INTO Capabilities (Name, DisplayName, Description, CreatedUtc)
                VALUES (@name, @displayName, @description, @now)
                """,
                new
                {
                    name = op.RequiredCapability,
                    displayName = op.ConsentTitle,
                    description = op.ConsentDescription,
                    now,
                });
        }
    }
}
