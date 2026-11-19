using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Core.Federation;

/// <summary>
/// Which CI identities a workload binding accepts. Every compared value must match exactly; there are no patterns.
/// A binding without a ref accepts any branch or tag. Its workflow is then <c>&lt;repository&gt;/&lt;path&gt;</c>, and the
/// repository's own protections (who may push which refs, GitHub environments) decide which refs are trusted.
/// </summary>
public static class BindingRules
{
    /// <summary>Events that run code from someone other than the repository's maintainers. Never allowed.</summary>
    public static readonly IReadOnlySet<string> ForbiddenEvents = new HashSet<string>(StringComparer.Ordinal)
    {
        "pull_request", "pull_request_target", "pull_request_review", "pull_request_review_comment",
        "issue_comment", "fork", "workflow_run",
    };

    public static readonly IReadOnlyList<string> DefaultEvents = ["push", "workflow_dispatch"];

    public sealed record MatchResult(WorkloadBinding? Binding, string? DenialReason);

    /// <summary>
    /// The one active binding that accepts the identity, or a denial reason. Several matching bindings are an
    /// ambiguity and are denied rather than merged.
    /// </summary>
    public static MatchResult Match(WorkloadIdentity identity, IEnumerable<WorkloadBinding> bindings)
    {
        if (CheckIdentity(identity) is { } invalid)
            return new MatchResult(null, invalid);

        var matches = bindings.Where(b => b.RevokedUtc is null && Accepts(b, identity)).Take(2).ToList();
        return matches.Count switch
        {
            0 => new MatchResult(null, "no_matching_binding"),
            1 => new MatchResult(matches[0], null),
            _ => new MatchResult(null, "ambiguous_binding"),
        };
    }

    private static string? CheckIdentity(WorkloadIdentity id)
    {
        if (string.IsNullOrEmpty(id.Repository) || string.IsNullOrEmpty(id.Ref) || string.IsNullOrEmpty(id.WorkflowRef)
            || string.IsNullOrEmpty(id.EventName))
            return "missing_claims";
        if (id.IssuerKind == IssuerKind.GitHub && string.IsNullOrEmpty(id.RepositoryId))
            return "missing_claims";
        if (ForbiddenEvents.Contains(id.EventName))
            return "event_not_allowed";
        if (!IsBranchOrTag(id.Ref))
            return "ref_not_allowed";
        // The workflow definition must come from the ref being built, so a branch cannot run another ref's workflow.
        if (!id.WorkflowRef.EndsWith("@" + id.Ref, StringComparison.Ordinal))
            return "workflow_ref_mismatch";
        return null;
    }

    private static bool Accepts(WorkloadBinding b, WorkloadIdentity id)
    {
        if (!string.Equals(b.Issuer, id.IssuerName, StringComparison.Ordinal)) return false;
        if (!string.Equals(b.Repository, id.Repository, StringComparison.Ordinal)) return false;
        // CheckIdentity has made sure the identity's workflow_ref ends with "@" + its ref.
        var workflowRef = b.Ref.Length == 0 ? b.WorkflowRef + "@" + id.Ref : b.WorkflowRef;
        if (b.Ref.Length > 0 && !string.Equals(b.Ref, id.Ref, StringComparison.Ordinal)) return false;
        if (!string.Equals(workflowRef, id.WorkflowRef, StringComparison.Ordinal)) return false;
        if (!NameList.Parse(b.EventNames).Contains(id.EventName!)) return false;

        if (id.IssuerKind == IssuerKind.GitHub)
        {
            // Immutable IDs: a deleted and re-created repository or owner with the same name does not match.
            if (!string.Equals(b.RepositoryId, id.RepositoryId, StringComparison.Ordinal)) return false;
            if (b.RepositoryOwnerId is not null && !string.Equals(b.RepositoryOwnerId, id.RepositoryOwnerId, StringComparison.Ordinal)) return false;
            if (b.JobWorkflowRef is not null && !string.Equals(b.JobWorkflowRef, id.JobWorkflowRef, StringComparison.Ordinal)) return false;
            if (b.Environment is not null && !string.Equals(b.Environment, id.Environment, StringComparison.Ordinal)) return false;
        }
        return true;
    }

    /// <summary>Validation of a binding before it is stored. Returns problems; empty means valid.</summary>
    public static IReadOnlyList<string> Validate(WorkloadBinding b, IssuerKind kind, IReadOnlySet<string> knownCapabilities)
    {
        var errors = new List<string>();
        if (!IsRepositoryName(b.Repository)) errors.Add("repository must be owner/name");
        if (b.Ref.Length > 0 && !IsBranchOrTag(b.Ref)) errors.Add("ref must start with refs/heads/ or refs/tags/, or be empty for any ref");
        var workflowPath = b.Ref.Length > 0 && b.WorkflowRef.EndsWith("@" + b.Ref, StringComparison.Ordinal)
            ? b.WorkflowRef[..^(b.Ref.Length + 1)]
            : b.WorkflowRef;
        if (!workflowPath.StartsWith(b.Repository + "/", StringComparison.Ordinal) || workflowPath.Length == b.Repository.Length + 1
            || workflowPath.Contains('@') || (b.Ref.Length > 0 && workflowPath == b.WorkflowRef))
            errors.Add("workflow_ref must be <repository>/<workflow path>@<ref>, or <repository>/<workflow path> without a ref");

        var events = NameList.Parse(b.EventNames);
        if (events.Count == 0) errors.Add("at least one event is required");
        foreach (var e in events.Where(ForbiddenEvents.Contains)) errors.Add($"event '{e}' runs untrusted code and cannot be allowed");

        var capabilities = NameList.Parse(b.Capabilities);
        foreach (var c in capabilities.Where(c => !knownCapabilities.Contains(c))) errors.Add($"unknown capability '{c}'");

        if (kind == IssuerKind.GitHub)
        {
            if (string.IsNullOrEmpty(b.RepositoryId) || !b.RepositoryId.All(char.IsAsciiDigit))
                errors.Add("repository_id (numeric) is required for GitHub");
            if (b.RepositoryOwnerId is not null && !b.RepositoryOwnerId.All(char.IsAsciiDigit))
                errors.Add("repository_owner_id must be numeric");
        }
        else
        {
            // Forgejo tokens carry none of these claims; a binding requiring them could never match.
            if (b.RepositoryId is not null || b.RepositoryOwnerId is not null || b.JobWorkflowRef is not null || b.Environment is not null)
                errors.Add("repository_id, repository_owner_id, job_workflow_ref and environment are GitHub-only");
        }
        return errors;
    }

    private static bool IsBranchOrTag(string? reference) =>
        reference is not null
        && ((reference.StartsWith("refs/heads/", StringComparison.Ordinal) && reference.Length > "refs/heads/".Length)
            || (reference.StartsWith("refs/tags/", StringComparison.Ordinal) && reference.Length > "refs/tags/".Length));

    private static bool IsRepositoryName(string? name)
    {
        if (string.IsNullOrEmpty(name)) return false;
        var parts = name.Split('/');
        return parts.Length == 2 && parts.All(p => p.Length > 0 && p.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.'));
    }
}
