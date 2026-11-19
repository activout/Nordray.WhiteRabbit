using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>
/// The common internal principal behind a CLI session or a virtual credential: who it is, whose Bunny key it uses
/// and what it may do right now.
/// </summary>
public sealed record CliPrincipal(CliSession Session, User Owner, WorkloadBinding? Binding, IReadOnlySet<string> Capabilities)
{
    public SecurityEvent Describe(string eventType, string outcome) => new()
    {
        EventType = eventType,
        Outcome = outcome,
        PrincipalType = Session.PrincipalType,
        Subject = Session.Subject,
        Issuer = Session.Issuer,
        UserId = Owner.Id,
        ClientId = Session.ClientId,
        BindingId = Session.BindingId,
        SessionId = Session.Id,
        Repository = Session.Repository,
        RepositoryId = Session.RepositoryId,
        WorkflowRef = Session.WorkflowRef,
        Ref = Session.Ref,
        RunId = Session.RunId,
    };
}

/// <summary>
/// Rebuilds a session's principal on every use, so revoking a grant or a binding, or removing the owner from the
/// sign-in allow-list, takes effect immediately rather than when the session expires.
/// </summary>
public sealed class CliPrincipalResolver(
    IUserRepository users,
    IWorkloadBindingDao bindings,
    IGrantService grants,
    SignInPolicy signInPolicy)
{
    public sealed record Result(CliPrincipal? Principal, string? DenialReason);

    public async Task<Result> ResolveAsync(CliSession session, DateTime now)
    {
        if (session.RevokedUtc is not null) return new Result(null, "session_revoked");
        if (session.ExpiresUtc <= now) return new Result(null, "session_expired");

        var owner = await users.FindByIdAsync(session.UserId);
        if (owner is null) return new Result(null, "owner_missing");
        if (!signInPolicy.IsAllowed(owner.Email)) return new Result(null, "user_not_allowed");

        if (session.PrincipalType == PrincipalTypes.Human)
        {
            var granted = await grants.GetGrantedCapabilitiesAsync(owner.Email, session.ClientId ?? "");
            return new Result(new CliPrincipal(session, owner, null, granted), null);
        }

        var binding = session.BindingId is { } id ? await bindings.FindAsync(id) : null;
        if (binding is null || binding.RevokedUtc is not null || binding.OwnerUserId != owner.Id)
            return new Result(null, "binding_revoked");
        return new Result(new CliPrincipal(session, owner, binding, NameList.Parse(binding.Capabilities)), null);
    }
}
