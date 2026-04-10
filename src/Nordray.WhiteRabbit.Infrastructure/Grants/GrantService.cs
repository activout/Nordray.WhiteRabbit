using System.Data;
using Dapper;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.Infrastructure.Grants;

public sealed class GrantService(IDbConnection db) : IGrantService
{
    public async Task<IReadOnlySet<string>> GetGrantedCapabilitiesAsync(
        string userEmail, string clientId, CancellationToken ct = default)
    {
        var names = await db.QueryAsync<string>("""
            SELECT c.Name
            FROM Grants g
            JOIN GrantCapabilities gc ON gc.GrantId = g.Id
            JOIN Capabilities c      ON c.Id        = gc.CapabilityId
            JOIN Users u             ON u.Id        = g.UserId
            JOIN OAuthClients oc     ON oc.Id       = g.ClientId
            WHERE u.Email     = @userEmail
              AND oc.ClientId = @clientId
              AND g.RevokedUtc IS NULL
            """, new { userEmail, clientId });

        return names.ToHashSet();
    }

    public async Task StoreGrantAsync(
        string userEmail, string clientId, IEnumerable<string> capabilities, CancellationToken ct = default)
    {
        var capList = capabilities.ToList();
        var now = DateTimeOffset.UtcNow.ToString("O");

        var userId = await db.ExecuteScalarAsync<long?>(
            "SELECT Id FROM Users WHERE Email = @userEmail", new { userEmail });
        if (userId is null)
            throw new InvalidOperationException($"User not found: {userEmail}");

        // Auto-register the client on first consent
        await db.ExecuteAsync(
            "INSERT OR IGNORE INTO OAuthClients (ClientId, ClientName, IsActive, CreatedUtc) VALUES (@clientId, @clientId, 1, @now)",
            new { clientId, now });
        var oauthClientId = await db.ExecuteScalarAsync<long>(
            "SELECT Id FROM OAuthClients WHERE ClientId = @clientId", new { clientId });

        // Revoke any existing active grant and replace it
        await db.ExecuteAsync(
            "UPDATE Grants SET RevokedUtc = @now WHERE UserId = @userId AND ClientId = @oauthClientId AND RevokedUtc IS NULL",
            new { now, userId, oauthClientId });

        await db.ExecuteAsync(
            "INSERT INTO Grants (UserId, ClientId, CreatedUtc) VALUES (@userId, @oauthClientId, @now)",
            new { userId, oauthClientId, now });
        var grantId = await db.ExecuteScalarAsync<long>("SELECT last_insert_rowid()");

        foreach (var cap in capList)
        {
            var capId = await db.ExecuteScalarAsync<long?>(
                "SELECT Id FROM Capabilities WHERE Name = @cap", new { cap });
            if (capId is null) continue;

            await db.ExecuteAsync(
                "INSERT OR IGNORE INTO GrantCapabilities (GrantId, CapabilityId) VALUES (@grantId, @capId)",
                new { grantId, capId });
        }
    }
}
