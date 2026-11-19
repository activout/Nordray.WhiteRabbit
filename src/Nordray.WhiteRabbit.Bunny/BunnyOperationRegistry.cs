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

        // --- Core Platform: User ---
        // BunnyCLI reads it for `bunny whoami` and for the account ID (`apps deploy` uses it as the registry
        // namespace).
        new BunnyOperation(
            OperationId: "core.user.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/user",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/user",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "account.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read account details",
            ConsentDescription: "Read the account's ID, owner, contact, billing and address details."),

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

        // --- Magic Containers and Bunny Database (Phase 6) ---
        // Reviewed against BunnyCLI 0.22.0's OpenAPI specs. Left out on purpose: log forwarding (its responses carry
        // tokens), registry changes and single-registry reads, volume and endpoint changes, and database groups.

        new BunnyOperation(
            OperationId: "mc.app.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List container apps",
            ConsentDescription: "Read the list of Magic Containers apps on the account."),

        new BunnyOperation(
            OperationId: "mc.app.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read container app",
            ConsentDescription: "Read a Magic Containers app's configuration. Environment variable values are redacted.",
            RedactJsonFields: ["containerTemplates[].environmentVariables[].value"]),

        new BunnyOperation(
            OperationId: "mc.app.overview",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/overview",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/overview",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read container app overview",
            ConsentDescription: "Read a Magic Containers app's status overview."),

        new BunnyOperation(
            OperationId: "mc.container.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/containers/{containerId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/containers/{containerId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read container",
            ConsentDescription: "Read one container of a Magic Containers app. Environment variable values are redacted.",
            RedactJsonFields: ["environmentVariables[].value"]),

        new BunnyOperation(
            OperationId: "mc.region.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/regions",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/regions",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List container regions",
            ConsentDescription: "Read the regions Magic Containers apps can run in."),

        new BunnyOperation(
            OperationId: "mc.registry.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/registries",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/registries",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List container registries",
            ConsentDescription: "Read the container registries configured on the account. Password fragments are redacted.",
            RedactJsonFields: ["items[].firstPasswordSymbols", "items[].lastPasswordSymbols"]),

        new BunnyOperation(
            OperationId: "mc.container.update",
            IncomingMethod: "PATCH",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/containers/{containerId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/containers/{containerId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.deploy",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Update container",
            ConsentDescription: "Change a container of a Magic Containers app, e.g. its image. This deploys new code.",
            RedactJsonFields: ["environmentVariables[].value"],
            // Only the image: environment variables need mc.env, and endpoints, volumes, probes and the entry point
            // are not covered by any capability.
            AllowedBodyFields: ["image", "imageName", "imageNamespace", "imageTag", "imageDigest", "imageRegistryId", "imagePullPolicy"]),

        new BunnyOperation(
            OperationId: "mc.app.deploy",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/deploy",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/deploy",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.deploy",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Deploy container app",
            ConsentDescription: "Deploy a Magic Containers app."),

        new BunnyOperation(
            OperationId: "mc.app.restart",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/restart",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/restart",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.deploy",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Restart container app",
            ConsentDescription: "Restart a Magic Containers app."),

        new BunnyOperation(
            OperationId: "mc.container.env.set",
            IncomingMethod: "PUT",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}/containers/{containerId}/env",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}/containers/{containerId}/env",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.env",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Set container environment variables",
            ConsentDescription: "Replace a container's environment variables. Values sent back redacted keep their current value; new values are never shown again.",
            RedactJsonFields: ["environmentVariables[].value"],
            RestoreRedactedEnvironmentFrom: "/mc/apps/{appId}/containers/{containerId}"),

        new BunnyOperation(
            OperationId: "mc.app.create",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.manage",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Create container app",
            ConsentDescription: "Create a Magic Containers app, e.g. a preview deployment.",
            RedactJsonFields: ["containerTemplates[].environmentVariables[].value"]),

        new BunnyOperation(
            OperationId: "mc.app.delete",
            IncomingMethod: "DELETE",
            IncomingPathTemplate: "/proxy/api.bunny.net/mc/apps/{appId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/mc/apps/{appId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "mc.manage",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Delete container app",
            ConsentDescription: "Delete a Magic Containers app and its containers, e.g. to clean up a preview deployment."),

        new BunnyOperation(
            OperationId: "db.config.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v1/config",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v1/config",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read database configuration",
            ConsentDescription: "Read Bunny Database regions and configuration."),

        new BunnyOperation(
            OperationId: "db.config.limits",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v1/config/limits",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v1/config/limits",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read database limits",
            ConsentDescription: "Read Bunny Database account limits."),

        new BunnyOperation(
            OperationId: "db.config.optimal",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v1/config/optimal",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v1/config/optimal",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read optimal database regions",
            ConsentDescription: "Read the recommended Bunny Database regions."),

        new BunnyOperation(
            OperationId: "db.database.list",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v2/databases",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v2/databases",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "List databases",
            ConsentDescription: "Read the list of Bunny Database databases."),

        new BunnyOperation(
            OperationId: "db.live.metrics",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v1/live/live_db",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v1/live/live_db",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read database status",
            ConsentDescription: "Read whether Bunny Database databases are active, as `bunny db list` shows it.",
            // A read despite POST: the body only names the databases ({"db_ids": [...]}).
            AllowedBodyFields: ["db_ids"]),

        new BunnyOperation(
            OperationId: "db.database.get",
            IncomingMethod: "GET",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v2/databases/{dbId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v2/databases/{dbId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.read",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Read database",
            ConsentDescription: "Read a Bunny Database database's details."),

        new BunnyOperation(
            OperationId: "db.database.create",
            IncomingMethod: "POST",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v2/databases",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v2/databases",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.manage",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Create database",
            ConsentDescription: "Create a Bunny Database database."),

        new BunnyOperation(
            OperationId: "db.database.delete",
            IncomingMethod: "DELETE",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v2/databases/{dbId}",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v2/databases/{dbId}",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.manage",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Delete database",
            ConsentDescription: "Delete a Bunny Database and its data, e.g. to clean up a preview deployment."),

        new BunnyOperation(
            OperationId: "db.token.generate",
            IncomingMethod: "PUT",
            IncomingPathTemplate: "/proxy/api.bunny.net/database/v2/databases/{dbId}/auth/generate",
            DestinationBaseUrl: BunnyApiBase,
            DestinationPathTemplate: "/database/v2/databases/{dbId}/auth/generate",
            CredentialKind: BunnyCredentialKind.AccountApiKey,
            RequiredCapability: "db.token",
            RequiresAuthenticationOnly: false,
            ConsentTitle: "Create database token",
            ConsentDescription: "Create an access token for a Bunny Database database. The token grants direct access to that database."),
    ];

    private static readonly CapabilityDescription[] Capabilities =
    [
        new("account.read", "Read account details",
            "Read the account's ID, the owner's name and email, roles, balance, billing details and address. " +
            "`bunny whoami` and `bunny apps deploy` need it."),
        new("statistics.read", "Read statistics", "Read account-level traffic and billing statistics."),
        new("pullzone.read", "Read pull zones", "List the pull zones on the account and read their configuration."),
        new("pullzone.write", "Manage pull zones", "Create, change and delete any pull zone on the account."),
        new("dns.read", "Read DNS zones", "List the DNS zones on the account and read their configuration and records."),
        new("dns.write", "Manage DNS zones", "Create, change and delete any DNS zone on the account."),
        new("shield.read", "Read Shield zones", "List the Shield zones on the account and read their configuration."),
        new("shield.write", "Change Shield zones", "Change the configuration of any Shield zone on the account."),
        new("mc.read", "Read container apps",
            "List every Magic Containers app on the account and read its configuration, containers, status, regions " +
            "and the account's container registries. Environment variable values and registry password fragments are redacted."),
        new("mc.deploy", "Deploy container apps",
            "Change the image of any container of any Magic Containers app on the account, deploy and restart apps. " +
            "This runs new code with the app's existing secrets."),
        new("mc.env", "Set container environment variables",
            "Replace the environment variables of any container on the account. Current values are never shown, but " +
            "they can be overwritten or removed, and the new values reach the running code."),
        new("mc.manage", "Create and delete container apps",
            "Create Magic Containers apps, and delete any app on the account with its containers, e.g. preview deployments."),
        new("db.read", "Read databases",
            "List every Bunny Database database on the account and read its details, the account's limits and the available regions."),
        new("db.manage", "Create and delete databases",
            "Create Bunny Database databases, and delete any database on the account with all its data."),
        new("db.token", "Create database tokens",
            "Create full-access tokens for any Bunny Database database on the account. A token gives direct access to that database's data."),
    ];

    public IReadOnlyList<BunnyOperation> GetAll() => All;

    /// <summary>Every capability an operation requires, with the description shown to the person approving it.</summary>
    public IReadOnlyList<CapabilityDescription> GetCapabilities() => Capabilities;

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
