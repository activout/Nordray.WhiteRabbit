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

        foreach (var capability in registry.GetCapabilities())
            await capabilities.EnsureAsync(capability.Name, capability.Title, capability.Description, now);
    }
}
