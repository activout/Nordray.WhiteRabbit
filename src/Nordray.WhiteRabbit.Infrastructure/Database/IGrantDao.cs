using System.Data;
using Activout.DatabaseClient;
using Activout.DatabaseClient.Attributes;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface IGrantDao : IWithTransactions
{
    [SqlQuery("""
        SELECT c.Name
        FROM Grants g
        JOIN GrantCapabilities gc ON gc.GrantId = g.Id
        JOIN Capabilities c      ON c.Id        = gc.CapabilityId
        JOIN Users u             ON u.Id        = g.UserId
        JOIN OAuthClients oc     ON oc.Id       = g.ClientId
        WHERE u.Email     = @userEmail
          AND oc.ClientId = @clientId
          AND g.RevokedUtc IS NULL
        """)]
    Task<IEnumerable<string>> ListGrantedCapabilitiesAsync([Bind("userEmail")] string userEmail, [Bind("clientId")] string clientId);

    [SqlQuery("SELECT Id FROM Users WHERE Email = @email")]
    Task<long?> FindUserIdAsync([Bind("email")] string email, IDbTransaction? transaction);

    /// <summary>Registers the client on first consent; a no-op when it already exists.</summary>
    [SqlUpdate("INSERT OR IGNORE INTO OAuthClients (ClientId, ClientName, IsActive, CreatedUtc) VALUES (@clientId, @clientId, 1, @now)")]
    Task EnsureClientAsync([Bind("clientId")] string clientId, [Bind("now")] DateTime now, IDbTransaction? transaction);

    [SqlQuery("SELECT Id FROM OAuthClients WHERE ClientId = @clientId")]
    Task<long> FindClientIdAsync([Bind("clientId")] string clientId, IDbTransaction? transaction);

    [SqlUpdate("UPDATE Grants SET RevokedUtc = @now WHERE UserId = @userId AND ClientId = @clientId AND RevokedUtc IS NULL")]
    Task RevokeActiveAsync([Bind("userId")] long userId, [Bind("clientId")] long clientId, [Bind("now")] DateTime now, IDbTransaction? transaction);

    [SqlQuery("INSERT INTO Grants (UserId, ClientId, CreatedUtc) VALUES (@userId, @clientId, @now) RETURNING Id")]
    Task<long> InsertAsync([Bind("userId")] long userId, [Bind("clientId")] long clientId, [Bind("now")] DateTime now, IDbTransaction? transaction);

    /// <summary>Adds the capability to the grant if a capability with that name exists; unknown names are ignored.</summary>
    [SqlUpdate("""
        INSERT OR IGNORE INTO GrantCapabilities (GrantId, CapabilityId)
        SELECT @grantId, Id FROM Capabilities WHERE Name = @capability
        """)]
    Task AddCapabilityAsync([Bind("grantId")] long grantId, [Bind("capability")] string capability, IDbTransaction? transaction);
}
