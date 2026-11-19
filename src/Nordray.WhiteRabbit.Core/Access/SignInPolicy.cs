namespace Nordray.WhiteRabbit.Core.Access;

public sealed class AccessOptions
{
    /// <summary>Addresses that may sign in, compared case-insensitively.</summary>
    public List<string> AllowedEmails { get; set; } = [];

    /// <summary>Domains whose addresses may sign in, e.g. <c>example.com</c>. Subdomains are not included.</summary>
    public List<string> AllowedDomains { get; set; } = [];
}

/// <summary>
/// Who may use this White Rabbit instance. Empty lists allow nobody: an operator must name the users or domains,
/// so a public instance never collects other people's Bunny API keys by accident.
/// </summary>
public sealed class SignInPolicy
{
    private readonly HashSet<string> _emails;
    private readonly HashSet<string> _domains;

    public SignInPolicy(AccessOptions options)
    {
        _emails = options.AllowedEmails.Select(Normalize).Where(e => e.Length > 0).ToHashSet(StringComparer.Ordinal);
        _domains = options.AllowedDomains.Select(d => Normalize(d).TrimStart('@')).Where(d => d.Length > 0).ToHashSet(StringComparer.Ordinal);
    }

    public bool AllowsAnyone => _emails.Count > 0 || _domains.Count > 0;

    public bool IsAllowed(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;
        var normalized = Normalize(email);
        var at = normalized.LastIndexOf('@');
        if (at <= 0 || at == normalized.Length - 1 || normalized.IndexOf('@') != at)
            return false;
        return _emails.Contains(normalized) || _domains.Contains(normalized[(at + 1)..]);
    }

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();
}
