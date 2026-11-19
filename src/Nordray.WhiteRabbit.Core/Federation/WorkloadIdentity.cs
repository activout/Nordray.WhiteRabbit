namespace Nordray.WhiteRabbit.Core.Federation;

public enum IssuerKind
{
    GitHub,
    Forgejo,
}

/// <summary>
/// The claims of a CI identity token whose issuer, audience, signature, algorithm and lifetime have already been
/// verified. Every value comes from the token; none is trusted until a binding matches it exactly.
/// </summary>
public sealed record WorkloadIdentity
{
    /// <summary>The configured issuer name, e.g. "github" or "codebahn".</summary>
    public required string IssuerName { get; init; }
    public required IssuerKind IssuerKind { get; init; }
    public required string IssuerUrl { get; init; }
    public required string Subject { get; init; }
    public string? Repository { get; init; }
    public string? RepositoryId { get; init; }
    public string? RepositoryOwner { get; init; }
    public string? RepositoryOwnerId { get; init; }
    public string? Ref { get; init; }
    public string? WorkflowRef { get; init; }
    public string? JobWorkflowRef { get; init; }
    public string? Environment { get; init; }
    public string? EventName { get; init; }
    public string? RunId { get; init; }
    public string? RunAttempt { get; init; }
    public string? Sha { get; init; }
    public string? Actor { get; init; }
}
