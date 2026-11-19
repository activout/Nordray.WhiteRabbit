using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Infrastructure.Grants;

public sealed class GrantService(IGrantDao grants) : IGrantService
{
    public async Task<IReadOnlySet<string>> GetGrantedCapabilitiesAsync(
        string userEmail, string clientId, CancellationToken ct = default) =>
        (await grants.ListGrantedCapabilitiesAsync(userEmail, clientId)).ToHashSet();

    public async Task StoreGrantAsync(
        string userEmail, string clientId, IEnumerable<string> capabilities, CancellationToken ct = default)
    {
        var capList = capabilities.ToList();
        var now = DateTime.UtcNow;

        using var tx = grants.BeginTransaction();
        var userId = await grants.FindUserIdAsync(userEmail, tx)
            ?? throw new InvalidOperationException($"User not found: {userEmail}");

        // Auto-register the client on first consent
        await grants.EnsureClientAsync(clientId, now, tx);
        var oauthClientId = await grants.FindClientIdAsync(clientId, tx);

        // Revoke any existing active grant and replace it
        await grants.RevokeActiveAsync(userId, oauthClientId, now, tx);
        var grantId = await grants.InsertAsync(userId, oauthClientId, now, tx);
        foreach (var capability in capList)
            await grants.AddCapabilityAsync(grantId, capability, tx);

        tx.Commit();
    }
}
