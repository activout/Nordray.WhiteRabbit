namespace Nordray.WhiteRabbit.Core.Services;

public interface IGrantService
{
    /// <summary>
    /// Returns the capability names the user has actively granted to the given OIDC client.
    /// </summary>
    Task<IReadOnlySet<string>> GetGrantedCapabilitiesAsync(string userEmail, string clientId, CancellationToken ct = default);

    /// <summary>
    /// Persists a new grant for the given capabilities, revoking any earlier grant
    /// for the same user + client pair before inserting the new one.
    /// </summary>
    Task StoreGrantAsync(string userEmail, string clientId, IEnumerable<string> capabilities, CancellationToken ct = default);
}
