using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Tests.Unit;

public class BindingRulesTests
{
    private static readonly IReadOnlySet<string> Known = new HashSet<string> { "statistics.read", "dns.read" };

    private static WorkloadBinding GitHubBinding() => new()
    {
        Id = 1,
        OwnerUserId = 7,
        Issuer = "github",
        Repository = "acme/app",
        RepositoryId = "100",
        Ref = "refs/heads/main",
        WorkflowRef = "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        EventNames = "push workflow_dispatch",
        Capabilities = "statistics.read",
    };

    private static WorkloadIdentity GitHubIdentity() => new()
    {
        IssuerName = "github",
        IssuerKind = IssuerKind.GitHub,
        IssuerUrl = "https://token.actions.githubusercontent.com",
        Subject = "repo:acme/app:ref:refs/heads/main",
        Repository = "acme/app",
        RepositoryId = "100",
        Ref = "refs/heads/main",
        WorkflowRef = "acme/app/.github/workflows/deploy.yml@refs/heads/main",
        EventName = "push",
    };

    [Fact]
    public void ExactMatch_ReturnsTheBinding() =>
        Assert.Equal(1, BindingRules.Match(GitHubIdentity(), [GitHubBinding()]).Binding?.Id);

    [Fact]
    public void RevokedBinding_NeverMatches() =>
        Assert.Equal("no_matching_binding", BindingRules.Match(GitHubIdentity(), [GitHubBinding() with { RevokedUtc = DateTime.UtcNow }]).DenialReason);

    [Fact]
    public void SameNameButDifferentRepositoryId_DoesNotMatch() =>
        Assert.Null(BindingRules.Match(GitHubIdentity() with { RepositoryId = "200" }, [GitHubBinding()]).Binding);

    [Fact]
    public void OwnerIdWhenBound_MustMatch()
    {
        var binding = GitHubBinding() with { RepositoryOwnerId = "5" };
        Assert.Null(BindingRules.Match(GitHubIdentity() with { RepositoryOwnerId = "6" }, [binding]).Binding);
        Assert.NotNull(BindingRules.Match(GitHubIdentity() with { RepositoryOwnerId = "5" }, [binding]).Binding);
    }

    [Fact]
    public void ReusableWorkflow_JobWorkflowRefWhenBound_MustMatch()
    {
        var binding = GitHubBinding() with { JobWorkflowRef = "acme/shared/.github/workflows/deploy.yml@refs/tags/v1" };
        Assert.Null(BindingRules.Match(GitHubIdentity() with { JobWorkflowRef = "acme/shared/.github/workflows/deploy.yml@refs/heads/main" }, [binding]).Binding);
        Assert.NotNull(BindingRules.Match(GitHubIdentity() with { JobWorkflowRef = "acme/shared/.github/workflows/deploy.yml@refs/tags/v1" }, [binding]).Binding);
    }

    [Fact]
    public void BindingForAnotherIssuer_DoesNotMatch() =>
        Assert.Null(BindingRules.Match(GitHubIdentity() with { IssuerName = "codebahn" }, [GitHubBinding()]).Binding);

    [Theory]
    [InlineData("pull_request")]
    [InlineData("pull_request_target")]
    [InlineData("workflow_run")]
    [InlineData("issue_comment")]
    public void UntrustedEvents_AreDeniedEvenIfABindingListedThem(string eventName)
    {
        var binding = GitHubBinding() with { EventNames = "push " + eventName };
        Assert.Equal("event_not_allowed", BindingRules.Match(GitHubIdentity() with { EventName = eventName }, [binding]).DenialReason);
    }

    [Theory]
    [InlineData("refs/pull/1/merge")]
    [InlineData("refs/heads/")]
    [InlineData("main")]
    public void NonBranchOrTagRefs_AreDenied(string reference) =>
        Assert.Equal("ref_not_allowed", BindingRules.Match(
            GitHubIdentity() with { Ref = reference, WorkflowRef = "acme/app/.github/workflows/deploy.yml@" + reference }, [GitHubBinding()]).DenialReason);

    [Fact]
    public void WorkflowFromAnotherRef_IsDenied() =>
        Assert.Equal("workflow_ref_mismatch", BindingRules.Match(
            GitHubIdentity() with { WorkflowRef = "acme/app/.github/workflows/deploy.yml@refs/heads/feature" }, [GitHubBinding()]).DenialReason);

    [Fact]
    public void TwoMatchingBindings_AreAmbiguous() =>
        Assert.Equal("ambiguous_binding", BindingRules.Match(GitHubIdentity(), [GitHubBinding(), GitHubBinding() with { Id = 2 }]).DenialReason);

    [Fact]
    public void GitHubTokenWithoutRepositoryId_IsDenied() =>
        Assert.Equal("missing_claims", BindingRules.Match(GitHubIdentity() with { RepositoryId = null }, [GitHubBinding()]).DenialReason);

    [Fact]
    public void Forgejo_MatchesOnNamesAndIgnoresGitHubOnlyFields()
    {
        var binding = GitHubBinding() with { Issuer = "codebahn", RepositoryId = null, WorkflowRef = "acme/app/.forgejo/workflows/deploy.yml@refs/heads/main" };
        var identity = GitHubIdentity() with
        {
            IssuerName = "codebahn",
            IssuerKind = IssuerKind.Forgejo,
            RepositoryId = null,
            WorkflowRef = "acme/app/.forgejo/workflows/deploy.yml@refs/heads/main",
        };
        Assert.NotNull(BindingRules.Match(identity, [binding]).Binding);
    }

    [Fact]
    public void Validate_AcceptsAWellFormedGitHubBinding() =>
        Assert.Empty(BindingRules.Validate(GitHubBinding(), IssuerKind.GitHub, Known));

    [Theory]
    [InlineData("repository")]
    [InlineData("ref")]
    [InlineData("workflow_ref")]
    [InlineData("events")]
    [InlineData("pull_request")]
    [InlineData("capability")]
    [InlineData("repository_id")]
    public void Validate_RejectsProblems(string problem)
    {
        var b = GitHubBinding();
        b = problem switch
        {
            "repository" => b with { Repository = "not-a-repo", WorkflowRef = "not-a-repo/x.yml@refs/heads/main" },
            "ref" => b with { Ref = "main", WorkflowRef = "acme/app/x.yml@main" },
            "workflow_ref" => b with { WorkflowRef = "other/app/.github/workflows/deploy.yml@refs/heads/main" },
            "events" => b with { EventNames = "" },
            "pull_request" => b with { EventNames = "push pull_request" },
            "capability" => b with { Capabilities = "statistics.read account.delete" },
            "repository_id" => b with { RepositoryId = null },
            _ => throw new ArgumentException(problem),
        };
        Assert.NotEmpty(BindingRules.Validate(b, IssuerKind.GitHub, Known));
    }

    [Fact]
    public void Validate_ForgejoBindingCannotUseGitHubOnlyFields()
    {
        var b = GitHubBinding() with { Issuer = "codebahn" };
        Assert.NotEmpty(BindingRules.Validate(b, IssuerKind.Forgejo, Known));
        Assert.Empty(BindingRules.Validate(b with { RepositoryId = null }, IssuerKind.Forgejo, Known));
    }
}

public class OpaqueTokenTests
{
    [Fact]
    public void Generate_IsPrefixedUniqueAndRecognised()
    {
        var a = OpaqueToken.Generate(OpaqueToken.VirtualKeyPrefix);
        var b = OpaqueToken.Generate(OpaqueToken.VirtualKeyPrefix);
        Assert.NotEqual(a, b);
        Assert.True(OpaqueToken.LooksLike(a, OpaqueToken.VirtualKeyPrefix));
        Assert.False(OpaqueToken.LooksLike(a, OpaqueToken.SessionPrefix));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("wrk_short")]
    [InlineData("wrk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+")]
    [InlineData("real-bunny-key-0123456789abcdef0123456789abcdef")]
    public void LooksLike_RejectsAnythingElse(string? value) =>
        Assert.False(OpaqueToken.LooksLike(value, OpaqueToken.VirtualKeyPrefix));

    [Fact]
    public void Hash_IsStableAndDoesNotContainTheToken()
    {
        var token = OpaqueToken.Generate(OpaqueToken.SessionPrefix);
        Assert.Equal(OpaqueToken.Hash(token), OpaqueToken.Hash(token));
        Assert.Equal(64, OpaqueToken.Hash(token).Length);
        Assert.DoesNotContain(token[4..12], OpaqueToken.Hash(token));
    }
}
