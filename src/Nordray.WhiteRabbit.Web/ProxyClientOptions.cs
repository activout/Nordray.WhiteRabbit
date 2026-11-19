namespace Nordray.WhiteRabbit.Web;

/// <summary>The OIDC client IDs whose tokens the Bunny proxy accepts (<c>Proxy:AllowedClientIds</c>).</summary>
public sealed class ProxyClientOptions(IEnumerable<string> allowedClientIds)
{
    public IReadOnlySet<string> AllowedClientIds { get; } =
        allowedClientIds.Where(id => !string.IsNullOrWhiteSpace(id)).Select(id => id.Trim()).ToHashSet(StringComparer.Ordinal);
}
