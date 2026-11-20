using Nordray.WhiteRabbit.Core.Federation;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>Settings for the rabbit CLI endpoints (<c>Cli</c> section).</summary>
public sealed class CliOptions
{
    /// <summary>How long a <c>/cli/login</c> code may wait for the CLI to redeem it. The CLI does so at once.</summary>
    public TimeSpan LoginCodeLifetime { get; set; } = TimeSpan.FromMinutes(2);

    public TimeSpan HumanSessionLifetime { get; set; } = TimeSpan.FromHours(8);
    public TimeSpan WorkloadSessionLifetime { get; set; } = TimeSpan.FromMinutes(60);
    public TimeSpan CredentialLifetime { get; set; } = TimeSpan.FromMinutes(5);
}

/// <summary>Trusted CI identity-token issuers (<c>Federation</c> section).</summary>
public sealed class FederationOptions
{
    /// <summary>
    /// The audience CI tokens must be issued for, distinct per environment (e.g. <c>whiterabbit:test</c>),
    /// so a token requested for one environment is refused by the other.
    /// </summary>
    public string Audience { get; set; } = "";

    /// <summary>Upper bound on a CI token's own lifetime (exp - iat).</summary>
    public TimeSpan MaxTokenLifetime { get; set; } = TimeSpan.FromHours(2);

    public List<TrustedIssuer> Issuers { get; set; } = [];
}

public sealed class TrustedIssuer
{
    /// <summary>Short name stored in bindings and audit records, e.g. "github" or "codebahn".</summary>
    public string Name { get; set; } = "";
    public IssuerKind Kind { get; set; }
    /// <summary>The exact <c>iss</c> value, e.g. https://token.actions.githubusercontent.com.</summary>
    public string Url { get; set; } = "";
}
