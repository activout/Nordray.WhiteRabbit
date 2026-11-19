using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Proxy;

/// <summary>
/// Seeds the Capabilities table from the hard-coded BunnyOperationRegistry.
/// Called once at startup after the migrations have run. Inserts only missing
/// capabilities, so it is safe to run on every boot.
/// </summary>
public sealed class CapabilitySeeder(ICapabilityDao capabilities, BunnyOperationRegistry registry)
{
    public async Task SeedAsync()
    {
        var now = DateTime.UtcNow;

        // Group by capability and take the lexicographically first OperationId as the
        // canonical source of DisplayName/Description, making seeding deterministic
        // regardless of the order operations appear in the registry.
        var capabilityOps = registry.GetAll()
            .Where(op => op.RequiredCapability is not null)
            .GroupBy(op => op.RequiredCapability!)
            .Select(g => g.OrderBy(op => op.OperationId, StringComparer.Ordinal).First());

        foreach (var op in capabilityOps)
            await capabilities.EnsureAsync(op.RequiredCapability!, op.ConsentTitle, op.ConsentDescription, now);
    }
}
