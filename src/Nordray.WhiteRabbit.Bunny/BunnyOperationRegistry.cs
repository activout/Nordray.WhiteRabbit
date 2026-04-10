using Nordray.WhiteRabbit.Core;

namespace Nordray.WhiteRabbit.Bunny;

/// <summary>
/// Hard-coded registry of every supported proxied bunny.net operation.
/// This is the sole runtime authority for which routes are proxied and what permissions they require.
/// Never add an operation here without a code review. Never auto-generate entries from OpenAPI alone.
/// Incoming paths mirror the bunny.net API path under /proxy/api.bunny.net/.
/// </summary>
public sealed class BunnyOperationRegistry
{
    private const string BunnyApiBase = "https://api.bunny.net";

    private static readonly BunnyOperation[] All =
    [
        // --- Core Platform: Regions (auth-only, no capability required) ---
        new BunnyOperation(
            OperationId: "core.region.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/region",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/region",
            CredentialKind: BunnyCredentialKind.None,
            RequiredCapability: null,
            RequiresAuthenticationOnly: true,
            ConsentTitle: "List regions",
            ConsentDescription: "Read the list of available bunny.net regions."),

        // --- Core Platform: Statistics ---
        new BunnyOperation(
            OperationId: "core.statistics.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/statistics",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/statistics",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "statistics.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read statistics",
            ConsentDescription: "Read account-level traffic and billing statistics."),

        // --- Core Platform: Pull Zones ---
        new BunnyOperation(
            OperationId: "core.pullzone.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/pullzone",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/pullzone",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "pullzone.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List pull zones",
            ConsentDescription: "Read the list of pull zones on the account."),

        new BunnyOperation(
            OperationId: "core.pullzone.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/pullzone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/pullzone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "pullzone.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read pull zone",
            ConsentDescription: "Read configuration details for a specific pull zone."),

        new BunnyOperation(
            OperationId: "core.pullzone.add",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/pullzone",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/pullzone",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "pullzone.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Create pull zone",
            ConsentDescription: "Create a new pull zone on the account."),

        new BunnyOperation(
            OperationId: "core.pullzone.update",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/pullzone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/pullzone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "pullzone.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Update pull zone",
            ConsentDescription: "Update configuration for an existing pull zone."),

        new BunnyOperation(
            OperationId: "core.pullzone.delete",
            IncomingMethod: "DELETE",
            IncomingPathTemplate: "/proxy/api.bunny.net/pullzone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/pullzone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "pullzone.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Delete pull zone",
            ConsentDescription: "Delete a pull zone from the account."),

        // --- Core Platform: DNS ---
        new BunnyOperation(
            OperationId: "core.dns.zone.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/dnszone",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/dnszone",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "dns.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List DNS zones",
            ConsentDescription: "Read the list of DNS zones on the account."),

        new BunnyOperation(
            OperationId: "core.dns.zone.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/dnszone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/dnszone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "dns.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read DNS zone",
            ConsentDescription: "Read configuration for a specific DNS zone."),

        new BunnyOperation(
            OperationId: "core.dns.zone.add",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/dnszone",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/dnszone",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "dns.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Create DNS zone",
            ConsentDescription: "Create a new DNS zone on the account."),

        new BunnyOperation(
            OperationId: "core.dns.zone.update",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/dnszone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/dnszone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "dns.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Update DNS zone",
            ConsentDescription: "Update configuration for an existing DNS zone."),

        new BunnyOperation(
            OperationId: "core.dns.zone.delete",
            IncomingMethod: "DELETE",
            IncomingPathTemplate: "/proxy/api.bunny.net/dnszone/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/dnszone/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "dns.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Delete DNS zone",
            ConsentDescription: "Delete a DNS zone from the account."),

        // --- Shield ---
        new BunnyOperation(
            OperationId: "shield.zone.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/shield/zones",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/shield/zones",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "shield.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List Shield zones",
            ConsentDescription: "Read the list of Shield zones on the account."),

        new BunnyOperation(
            OperationId: "shield.zone.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/shield/zones/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/shield/zones/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "shield.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read Shield zone",
            ConsentDescription: "Read configuration for a specific Shield zone."),

        new BunnyOperation(
            OperationId: "shield.zone.update",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/shield/zones/{id}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/shield/zones/{id}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "shield.write",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Update Shield zone",
            ConsentDescription: "Update configuration for an existing Shield zone."),
    ];

    public IReadOnlyList<BunnyOperation> GetAll() => All;

    /// <summary>
    /// Finds a registered operation by matching the HTTP method and full incoming path
    /// (e.g. GET /proxy/api.bunny.net/pullzone/123). Path template parameters like {id}
    /// match any single non-empty path segment.
    /// </summary>
    public BunnyOperation? FindByRequest(string method, string path)
    {
        var upperMethod = method.ToUpperInvariant();
        foreach (var op in All)
        {
            if (!string.Equals(op.IncomingMethod, upperMethod, StringComparison.Ordinal)) continue;
            if (MatchesTemplate(op.IncomingPathTemplate, path)) return op;
        }
        return null;
    }

    private static bool MatchesTemplate(string template, string path)
    {
        var templateSegments = template.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var pathSegments = path.Split('/', StringSplitOptions.RemoveEmptyEntries);

        if (templateSegments.Length != pathSegments.Length) return false;

        for (var i = 0; i < templateSegments.Length; i++)
        {
            var t = templateSegments[i];
            if (t.StartsWith('{') && t.EndsWith('}')) continue; // route parameter — matches any segment
            if (!string.Equals(t, pathSegments[i], StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }
}
