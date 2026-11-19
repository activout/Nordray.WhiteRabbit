using System.Security.Claims;

namespace Nordray.WhiteRabbit.Core.Access;

/// <summary>Works out which OIDC client a validated bearer token was issued to.</summary>
public static class OidcClientIdentity
{
    /// <summary>
    /// The client the token was issued to, or null when that is ambiguous or not an allowed client.
    /// <c>azp</c> (authorised party) wins when present. Otherwise the token must have exactly one audience.
    /// A token with several audiences and no <c>azp</c> is rejected rather than guessed.
    /// </summary>
    public static string? Resolve(ClaimsPrincipal user, IReadOnlySet<string> allowedClients)
    {
        var audiences = user.FindAll("aud").Select(c => c.Value).Where(v => v.Length > 0).Distinct(StringComparer.Ordinal).ToList();
        var azp = user.FindFirst("azp")?.Value;

        string? client;
        if (!string.IsNullOrEmpty(azp))
            client = audiences.Contains(azp, StringComparer.Ordinal) ? azp : null;
        else
            client = audiences.Count == 1 ? audiences[0] : null;

        return client is not null && allowedClients.Contains(client) ? client : null;
    }
}
