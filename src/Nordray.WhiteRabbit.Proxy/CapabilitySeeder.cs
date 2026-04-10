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

        foreach (var op in registry.GetAll())
        {
            if (op.RequiredCapability is null) continue;
            if (!seeded.Add(op.RequiredCapability)) continue;

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
