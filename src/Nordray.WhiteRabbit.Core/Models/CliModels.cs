namespace Nordray.WhiteRabbit.Core.Models;

/// <summary>The kinds of principal a White Rabbit CLI session can belong to.</summary>
public static class PrincipalTypes
{
    public const string Human = "human";
    public const string GitHubWorkload = "github_workload";
    public const string ForgejoWorkload = "forgejo_workload";
}

/// <summary>A CI workload that may act for its owner with the listed capabilities. All timestamps UTC.</summary>
public sealed record WorkloadBinding
{
    public long Id { get; init; }
    public long OwnerUserId { get; init; }
    public string Issuer { get; init; } = "";
    public string Repository { get; init; } = "";
    public string? RepositoryId { get; init; }
    public string? RepositoryOwnerId { get; init; }
    public string Ref { get; init; } = "";
    public string WorkflowRef { get; init; } = "";
    public string? JobWorkflowRef { get; init; }
    public string? Environment { get; init; }
    /// <summary>Space-separated.</summary>
    public string EventNames { get; init; } = "";
    /// <summary>Space-separated.</summary>
    public string Capabilities { get; init; } = "";
    public string? Description { get; init; }
    public DateTime CreatedUtc { get; init; }
    public DateTime? RevokedUtc { get; init; }
}

public sealed record CliSession
{
    public string Id { get; init; } = "";
    public string TokenHash { get; init; } = "";
    public string PrincipalType { get; init; } = "";
    public long UserId { get; init; }
    public string Subject { get; init; } = "";
    public string Issuer { get; init; } = "";
    public string? ClientId { get; init; }
    public long? BindingId { get; init; }
    public string? Repository { get; init; }
    public string? RepositoryId { get; init; }
    public string? WorkflowRef { get; init; }
    public string? Ref { get; init; }
    public string? RunId { get; init; }
    public DateTime CreatedUtc { get; init; }
    public DateTime ExpiresUtc { get; init; }
    public DateTime? RevokedUtc { get; init; }
}

public sealed record VirtualCredential
{
    public string Id { get; init; } = "";
    public string KeyHash { get; init; } = "";
    public string SessionId { get; init; } = "";
    /// <summary>Space-separated.</summary>
    public string Capabilities { get; init; } = "";
    public DateTime CreatedUtc { get; init; }
    public DateTime ExpiresUtc { get; init; }
    public DateTime? RevokedUtc { get; init; }
}

/// <summary>One row of the security audit trail. Never put tokens, keys, codes or query strings in it.</summary>
public sealed record SecurityEvent
{
    public DateTime OccurredUtc { get; init; } = DateTime.UtcNow;
    public required string EventType { get; init; }
    public required string Outcome { get; init; }
    public string? Reason { get; init; }
    public string? PrincipalType { get; init; }
    public string? Subject { get; init; }
    public string? Issuer { get; init; }
    public long? UserId { get; init; }
    public string? ClientId { get; init; }
    public long? BindingId { get; init; }
    public string? SessionId { get; init; }
    public string? CredentialId { get; init; }
    public string? Repository { get; init; }
    public string? RepositoryId { get; init; }
    public string? WorkflowRef { get; init; }
    public string? Ref { get; init; }
    public string? RunId { get; init; }
    public string? OperationId { get; init; }
    public string? HttpMethod { get; init; }
    public string? Path { get; init; }
    public int? HttpStatus { get; init; }
    public int? UpstreamStatus { get; init; }
    public string? CorrelationId { get; init; }
    public string? Detail { get; init; }

    public const string Allowed = "allowed";
    public const string Denied = "denied";
}

/// <summary>Helpers for the space-separated name lists stored in the database.</summary>
public static class NameList
{
    public static IReadOnlySet<string> Parse(string? value) =>
        (value ?? "").Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet(StringComparer.Ordinal);

    public static string Format(IEnumerable<string> names) =>
        string.Join(' ', names.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal));
}
