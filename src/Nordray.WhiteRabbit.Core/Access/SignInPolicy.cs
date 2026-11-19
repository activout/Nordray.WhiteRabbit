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
    private sealed record Lists(HashSet<string> Emails, HashSet<string> Domains);

    private volatile Lists _lists;

    public SignInPolicy(AccessOptions options) => _lists = Build(options);

    /// <summary>
    /// Replaces the lists, e.g. when configuration is reloaded. Takes effect on the next check: sessions and tokens of
    /// a removed address are refused from then on.
    /// </summary>
    public void Update(AccessOptions options) => _lists = Build(options);

    private static Lists Build(AccessOptions options) => new(
        options.AllowedEmails.Select(Normalize).Where(e => e.Length > 0).ToHashSet(StringComparer.Ordinal),
        options.AllowedDomains.Select(d => Normalize(d).TrimStart('@')).Where(d => d.Length > 0).ToHashSet(StringComparer.Ordinal));

    public bool AllowsAnyone => _lists.Emails.Count > 0 || _lists.Domains.Count > 0;

    public bool IsAllowed(string? email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;
        var normalized = Normalize(email);
        var at = normalized.LastIndexOf('@');
        if (at <= 0 || at == normalized.Length - 1 || normalized.IndexOf('@') != at)
            return false;
        var lists = _lists;
        return lists.Emails.Contains(normalized) || lists.Domains.Contains(normalized[(at + 1)..]);
    }

    private static string Normalize(string value) => value.Trim().ToLowerInvariant();
}
