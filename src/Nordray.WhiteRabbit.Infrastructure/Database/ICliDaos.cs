using Activout.DatabaseClient.Attributes;
using Nordray.WhiteRabbit.Core.Models;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

public interface IWorkloadBindingDao
{
    [SqlQuery("""
        INSERT INTO WorkloadBindings (OwnerUserId, Issuer, Repository, RepositoryId, RepositoryOwnerId, Ref, WorkflowRef,
                                      JobWorkflowRef, Environment, EventNames, Capabilities, Description, CreatedUtc)
        VALUES (@OwnerUserId, @Issuer, @Repository, @RepositoryId, @RepositoryOwnerId, @Ref, @WorkflowRef,
                @JobWorkflowRef, @Environment, @EventNames, @Capabilities, @Description, @CreatedUtc)
        RETURNING Id
        """)]
    Task<long> InsertAsync([BindProperties] WorkloadBinding binding);

    [SqlQuery("SELECT * FROM WorkloadBindings WHERE Issuer = @issuer AND RevokedUtc IS NULL ORDER BY Id")]
    Task<IEnumerable<WorkloadBinding>> ListActiveByIssuerAsync([Bind("issuer")] string issuer);

    [SqlQuery("SELECT * FROM WorkloadBindings WHERE OwnerUserId = @ownerUserId AND RevokedUtc IS NULL ORDER BY Id")]
    Task<IEnumerable<WorkloadBinding>> ListActiveByOwnerAsync([Bind("ownerUserId")] long ownerUserId);

    [SqlQuery("SELECT * FROM WorkloadBindings WHERE Id = @id")]
    Task<WorkloadBinding?> FindAsync([Bind("id")] long id);

    /// <summary>Returns 1 when the owner had the active binding.</summary>
    [SqlUpdate("UPDATE WorkloadBindings SET RevokedUtc = @now WHERE Id = @id AND OwnerUserId = @ownerUserId AND RevokedUtc IS NULL")]
    Task<int> RevokeAsync([Bind("id")] long id, [Bind("ownerUserId")] long ownerUserId, [Bind("now")] DateTime now);
}

public interface ICliSessionDao
{
    [SqlUpdate("""
        INSERT INTO CliSessions (Id, TokenHash, PrincipalType, UserId, Subject, Issuer, ClientId, BindingId, Repository,
                                 RepositoryId, WorkflowRef, Ref, RunId, CreatedUtc, ExpiresUtc)
        VALUES (@Id, @TokenHash, @PrincipalType, @UserId, @Subject, @Issuer, @ClientId, @BindingId, @Repository,
                @RepositoryId, @WorkflowRef, @Ref, @RunId, @CreatedUtc, @ExpiresUtc)
        """)]
    Task InsertAsync([BindProperties] CliSession session);

    [SqlQuery("SELECT * FROM CliSessions WHERE TokenHash = @tokenHash")]
    Task<CliSession?> FindByTokenHashAsync([Bind("tokenHash")] string tokenHash);

    [SqlQuery("SELECT * FROM CliSessions WHERE Id = @id")]
    Task<CliSession?> FindAsync([Bind("id")] string id);

    [SqlUpdate("UPDATE CliSessions SET RevokedUtc = @now WHERE Id = @id AND RevokedUtc IS NULL")]
    Task<int> RevokeAsync([Bind("id")] string id, [Bind("now")] DateTime now);
}

public interface IVirtualCredentialDao
{
    [SqlUpdate("""
        INSERT INTO VirtualCredentials (Id, KeyHash, SessionId, Capabilities, CreatedUtc, ExpiresUtc)
        VALUES (@Id, @KeyHash, @SessionId, @Capabilities, @CreatedUtc, @ExpiresUtc)
        """)]
    Task InsertAsync([BindProperties] VirtualCredential credential);

    [SqlQuery("SELECT * FROM VirtualCredentials WHERE KeyHash = @keyHash")]
    Task<VirtualCredential?> FindByKeyHashAsync([Bind("keyHash")] string keyHash);

    [SqlUpdate("UPDATE VirtualCredentials SET RevokedUtc = @now WHERE SessionId = @sessionId AND RevokedUtc IS NULL")]
    Task<int> RevokeBySessionAsync([Bind("sessionId")] string sessionId, [Bind("now")] DateTime now);

    [SqlUpdate("UPDATE VirtualCredentials SET RevokedUtc = @now WHERE Id = @id AND SessionId = @sessionId AND RevokedUtc IS NULL")]
    Task<int> RevokeAsync([Bind("id")] string id, [Bind("sessionId")] string sessionId, [Bind("now")] DateTime now);
}

public interface ISecurityEventDao
{
    [SqlUpdate("""
        INSERT INTO SecurityEvents (OccurredUtc, EventType, Outcome, Reason, PrincipalType, Subject, Issuer, UserId, ClientId,
                                    BindingId, SessionId, CredentialId, Repository, RepositoryId, WorkflowRef, Ref, RunId,
                                    OperationId, HttpMethod, Path, HttpStatus, UpstreamStatus, CorrelationId, Detail)
        VALUES (@OccurredUtc, @EventType, @Outcome, @Reason, @PrincipalType, @Subject, @Issuer, @UserId, @ClientId,
                @BindingId, @SessionId, @CredentialId, @Repository, @RepositoryId, @WorkflowRef, @Ref, @RunId,
                @OperationId, @HttpMethod, @Path, @HttpStatus, @UpstreamStatus, @CorrelationId, @Detail)
        """)]
    Task InsertAsync([BindProperties] SecurityEvent securityEvent);
}
