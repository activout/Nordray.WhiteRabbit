using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>
/// The rabbit CLI's API:
/// <list type="bullet">
/// <item><c>POST /api/cli/exchange</c>: a Dex, GitHub or Forgejo identity token for a White Rabbit session.</item>
/// <item><c>POST /api/cli/credentials</c>: a session for a short-lived virtual Bunny credential.</item>
/// <item><c>GET /api/cli/whoami</c>, <c>POST /api/cli/revoke</c>.</item>
/// <item><c>/api/admin/bindings</c>: an interactive human session manages its own workload bindings.</item>
/// </list>
/// </summary>
public static class CliEndpoints
{
    public const string SessionPolicy = "CliSession";
    public const string HumanPolicy = "CliHuman";
    public const string ExchangeRateLimit = "cli-exchange";
    public const string ApiRateLimit = "cli-api";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static void MapCliEndpoints(this WebApplication app)
    {
        var cli = app.MapGroup("/api/cli");
        cli.MapPost("/exchange", Exchange).RequireRateLimiting(ExchangeRateLimit).AllowAnonymous();
        cli.MapPost("/credentials", IssueCredential).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);
        cli.MapGet("/whoami", WhoAmI).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);
        cli.MapPost("/revoke", Revoke).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);

        var admin = app.MapGroup("/api/admin/bindings").RequireAuthorization(HumanPolicy).RequireRateLimiting(ApiRateLimit);
        admin.MapGet("/", ListBindings);
        admin.MapPost("/", CreateBinding);
        admin.MapDelete("/{id:long}", RevokeBinding);
    }

    // ---------------------------------------------------------------- exchange

    public sealed record ExchangeRequest(string? SubjectToken);

    private static async Task<IResult> Exchange(
        HttpContext ctx,
        IdentityTokenValidator validator,
        IUserRepository users,
        IWorkloadBindingDao bindings,
        ICliSessionDao sessions,
        CliPrincipalResolver resolver,
        SignInPolicy signInPolicy,
        IOptions<CliOptions> cliOptions,
        SecurityAudit audit)
    {
        var (request, invalid) = await ReadJsonAsync<ExchangeRequest>(ctx);
        if (invalid is not null) return invalid;
        if (string.IsNullOrWhiteSpace(request?.SubjectToken))
            return Error(StatusCodes.Status400BadRequest, "invalid_request", "subject_token is required");

        var validation = await validator.ValidateAsync(request.SubjectToken.Trim(), ctx.RequestAborted);
        if (validation.Token is null)
            return await DenyExchange(audit, validation.DenialReason!, validation.UnverifiedIssuer, null);

        var now = DateTime.UtcNow;
        var options = cliOptions.Value;
        CliSession session;

        if (validation.Token.Workload is null)
        {
            // A human: the Dex ID token the rabbit CLI received through the browser login.
            var email = validation.Token.Token.TryGetPayloadValue<string>("email", out var e) ? e : null;
            var user = email is null ? null : await users.FindByEmailAsync(email);
            if (user is null || !signInPolicy.IsAllowed(email))
                return await DenyExchange(audit, "user_not_allowed", validation.Token.IssuerUrl, null);

            session = NewSession(now, options.HumanSessionLifetime) with
            {
                PrincipalType = PrincipalTypes.Human,
                UserId = user.Id,
                Subject = user.Subject,
                Issuer = validation.Token.IssuerUrl,
                ClientId = options.DexClientId,
            };
        }
        else
        {
            var identity = IdentityTokenValidator.ToWorkloadIdentity(validation.Token);
            var match = BindingRules.Match(identity, await bindings.ListActiveByIssuerAsync(identity.IssuerName));
            if (match.Binding is null)
                return await DenyExchange(audit, match.DenialReason!, identity.IssuerUrl, identity);

            session = NewSession(now, options.WorkloadSessionLifetime) with
            {
                PrincipalType = identity.IssuerKind == IssuerKind.GitHub ? PrincipalTypes.GitHubWorkload : PrincipalTypes.ForgejoWorkload,
                UserId = match.Binding.OwnerUserId,
                Subject = identity.Subject,
                Issuer = identity.IssuerUrl,
                BindingId = match.Binding.Id,
                Repository = identity.Repository,
                RepositoryId = identity.RepositoryId,
                WorkflowRef = identity.WorkflowRef,
                Ref = identity.Ref,
                RunId = identity.RunId,
            };
        }

        // The owner must still be allowed, and a workload's binding must belong to them.
        var resolved = await resolver.ResolveAsync(session, now);
        if (resolved.Principal is null)
            return await DenyExchange(audit, resolved.DenialReason!, session.Issuer, null);

        var token = OpaqueToken.Generate(OpaqueToken.SessionPrefix);
        session = session with { TokenHash = OpaqueToken.Hash(token) };
        await sessions.InsertAsync(session);
        await audit.RecordAsync(resolved.Principal.Describe("cli.exchange", SecurityEvent.Allowed) with { HttpStatus = 200 });

        return Results.Json(new
        {
            AccessToken = token,
            TokenType = "Bearer",
            ExpiresIn = (int)(session.ExpiresUtc - now).TotalSeconds,
            ExpiresAt = session.ExpiresUtc,
            Principal = Describe(resolved.Principal),
        }, Json);
    }

    private static CliSession NewSession(DateTime now, TimeSpan lifetime) => new()
    {
        Id = Guid.NewGuid().ToString("N"),
        CreatedUtc = now,
        ExpiresUtc = now + lifetime,
    };

    private static async Task<IResult> DenyExchange(SecurityAudit audit, string reason, string? issuer, WorkloadIdentity? identity)
    {
        await audit.RecordAsync(new SecurityEvent
        {
            EventType = "cli.exchange",
            Outcome = SecurityEvent.Denied,
            Reason = reason,
            Issuer = issuer,
            Subject = identity?.Subject,
            Repository = identity?.Repository,
            RepositoryId = identity?.RepositoryId,
            WorkflowRef = identity?.WorkflowRef,
            Ref = identity?.Ref,
            RunId = identity?.RunId,
            HttpStatus = 401,
        });
        return Error(StatusCodes.Status401Unauthorized, "access_denied", reason);
    }

    // ---------------------------------------------------------------- credentials

    public sealed record CredentialRequest(string[]? Capabilities);

    private static async Task<IResult> IssueCredential(
        HttpContext ctx,
        CliPrincipalResolver resolver,
        IVirtualCredentialDao credentials,
        IOptions<CliOptions> cliOptions,
        SecurityAudit audit)
    {
        var now = DateTime.UtcNow;
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "cli.credential", now);
        if (principal is null) return denied!;

        var (request, invalid) = await ReadJsonAsync<CredentialRequest>(ctx);
        if (invalid is not null) return invalid;
        var requested = request?.Capabilities is { Length: > 0 } list ? list.ToHashSet(StringComparer.Ordinal) : principal.Capabilities.ToHashSet(StringComparer.Ordinal);
        var missing = requested.Where(c => !principal.Capabilities.Contains(c)).Order(StringComparer.Ordinal).ToList();
        if (missing.Count > 0)
        {
            await audit.RecordAsync(principal.Describe("cli.credential", SecurityEvent.Denied) with
            {
                Reason = "capability_not_available",
                HttpStatus = 403,
                Detail = JsonSerializer.Serialize(new { missing }),
            });
            return Results.Json(new { Error = "capability_not_available", Capabilities = missing }, Json, statusCode: StatusCodes.Status403Forbidden);
        }

        var expires = Min(now + cliOptions.Value.CredentialLifetime, principal.Session.ExpiresUtc);
        var key = OpaqueToken.Generate(OpaqueToken.VirtualKeyPrefix);
        var credential = new VirtualCredential
        {
            Id = Guid.NewGuid().ToString("N"),
            KeyHash = OpaqueToken.Hash(key),
            SessionId = principal.Session.Id,
            Capabilities = NameList.Format(requested),
            CreatedUtc = now,
            ExpiresUtc = expires,
        };
        await credentials.InsertAsync(credential);
        await audit.RecordAsync(principal.Describe("cli.credential", SecurityEvent.Allowed) with { CredentialId = credential.Id, HttpStatus = 200 });

        return Results.Json(new
        {
            AccessKey = key,
            CredentialId = credential.Id,
            ExpiresIn = (int)(expires - now).TotalSeconds,
            ExpiresAt = expires,
            Capabilities = NameList.Parse(credential.Capabilities).Order(StringComparer.Ordinal),
        }, Json);
    }

    // ---------------------------------------------------------------- whoami / revoke

    private static async Task<IResult> WhoAmI(HttpContext ctx, CliPrincipalResolver resolver, SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "cli.whoami", DateTime.UtcNow);
        return principal is null ? denied! : Results.Json(Describe(principal), Json);
    }

    public sealed record RevokeRequest(string? CredentialId);

    private static async Task<IResult> Revoke(
        HttpContext ctx, ICliSessionDao sessions, IVirtualCredentialDao credentials, SecurityAudit audit)
    {
        var session = CliSessionAuthenticationHandler.SessionOf(ctx)!;
        var (request, invalid) = await ReadJsonAsync<RevokeRequest>(ctx);
        if (invalid is not null) return invalid;
        var now = DateTime.UtcNow;
        var describe = new SecurityEvent
        {
            EventType = "cli.revoke",
            Outcome = SecurityEvent.Allowed,
            PrincipalType = session.PrincipalType,
            Subject = session.Subject,
            Issuer = session.Issuer,
            UserId = session.UserId,
            BindingId = session.BindingId,
            SessionId = session.Id,
            HttpStatus = 204,
        };

        if (!string.IsNullOrEmpty(request?.CredentialId))
        {
            // Only the session's own credentials can be revoked this way.
            if (await credentials.RevokeAsync(request.CredentialId, session.Id, now) == 0)
                return Error(StatusCodes.Status404NotFound, "not_found", "no such active credential in this session");
            await audit.RecordAsync(describe with { CredentialId = request.CredentialId });
            return Results.NoContent();
        }

        await credentials.RevokeBySessionAsync(session.Id, now);
        await sessions.RevokeAsync(session.Id, now);
        await audit.RecordAsync(describe);
        return Results.NoContent();
    }

    // ---------------------------------------------------------------- admin: workload bindings

    public sealed record BindingRequest(
        string? Issuer,
        string? Repository,
        string? RepositoryId,
        string? RepositoryOwnerId,
        string? Ref,
        string? WorkflowRef,
        string? JobWorkflowRef,
        string? Environment,
        string[]? Events,
        string[]? Capabilities,
        string? Description);

    private static async Task<IResult> ListBindings(
        HttpContext ctx, IWorkloadBindingDao bindings, CliPrincipalResolver resolver, SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.binding.list", DateTime.UtcNow);
        if (principal is null) return denied!;
        return Results.Json((await bindings.ListActiveByOwnerAsync(principal.Owner.Id)).Select(DescribeBinding), Json);
    }

    private static async Task<IResult> CreateBinding(
        HttpContext ctx,
        IWorkloadBindingDao bindings,
        CliPrincipalResolver resolver,
        BunnyOperationRegistry registry,
        IOptions<FederationOptions> federation,
        SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.binding.create", DateTime.UtcNow);
        if (principal is null) return denied!;

        var (request, invalid) = await ReadJsonAsync<BindingRequest>(ctx);
        if (invalid is not null) return invalid;
        var issuer = federation.Value.Issuers.FirstOrDefault(i => string.Equals(i.Name, request?.Issuer, StringComparison.Ordinal));
        if (request is null || issuer is null)
            return Error(StatusCodes.Status400BadRequest, "invalid_request",
                "issuer must be one of: " + string.Join(", ", federation.Value.Issuers.Select(i => i.Name)));

        var binding = new WorkloadBinding
        {
            OwnerUserId = principal.Owner.Id,
            Issuer = issuer.Name,
            Repository = request.Repository?.Trim() ?? "",
            RepositoryId = Blank(request.RepositoryId),
            RepositoryOwnerId = Blank(request.RepositoryOwnerId),
            Ref = request.Ref?.Trim() ?? "",
            WorkflowRef = request.WorkflowRef?.Trim() ?? "",
            JobWorkflowRef = Blank(request.JobWorkflowRef),
            Environment = Blank(request.Environment),
            EventNames = NameList.Format(request.Events is { Length: > 0 } events ? events : BindingRules.DefaultEvents),
            Capabilities = NameList.Format(request.Capabilities ?? []),
            Description = Blank(request.Description),
            CreatedUtc = DateTime.UtcNow,
        };

        var known = registry.GetAll().Select(op => op.RequiredCapability).OfType<string>().ToHashSet(StringComparer.Ordinal);
        var errors = BindingRules.Validate(binding, issuer.Kind, known);
        if (errors.Count > 0)
            return Results.Json(new { Error = "invalid_binding", Problems = errors }, Json, statusCode: StatusCodes.Status400BadRequest);

        var id = await bindings.InsertAsync(binding);
        binding = (await bindings.FindAsync(id))!;
        await audit.RecordAsync(principal.Describe("admin.binding.create", SecurityEvent.Allowed) with
        {
            BindingId = id,
            HttpStatus = 201,
            Detail = JsonSerializer.Serialize(new { after = DescribeBinding(binding) }, Json),
        });
        return Results.Json(DescribeBinding(binding), Json, statusCode: StatusCodes.Status201Created);
    }

    private static async Task<IResult> RevokeBinding(
        long id, HttpContext ctx, IWorkloadBindingDao bindings, CliPrincipalResolver resolver, SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.binding.revoke", DateTime.UtcNow);
        if (principal is null) return denied!;

        var before = await bindings.FindAsync(id);
        if (before is null || await bindings.RevokeAsync(id, principal.Owner.Id, DateTime.UtcNow) == 0)
            return Error(StatusCodes.Status404NotFound, "not_found", "no such active binding");

        await audit.RecordAsync(principal.Describe("admin.binding.revoke", SecurityEvent.Allowed) with
        {
            BindingId = id,
            HttpStatus = 204,
            Detail = JsonSerializer.Serialize(new { before = DescribeBinding(before) }, Json),
        });
        return Results.NoContent();
    }

    // ---------------------------------------------------------------- helpers

    private static async Task<(CliPrincipal? Principal, IResult? Denied)> ResolveAsync(
        HttpContext ctx, CliPrincipalResolver resolver, SecurityAudit audit, string eventType, DateTime now)
    {
        var session = CliSessionAuthenticationHandler.SessionOf(ctx)!;
        var result = await resolver.ResolveAsync(session, now);
        if (result.Principal is not null) return (result.Principal, null);

        await audit.RecordAsync(new SecurityEvent
        {
            EventType = eventType,
            Outcome = SecurityEvent.Denied,
            Reason = result.DenialReason,
            PrincipalType = session.PrincipalType,
            Subject = session.Subject,
            UserId = session.UserId,
            BindingId = session.BindingId,
            SessionId = session.Id,
            HttpStatus = 403,
        });
        return (null, Error(StatusCodes.Status403Forbidden, "access_denied", result.DenialReason!));
    }

    private static object Describe(CliPrincipal p) => new
    {
        Type = p.Session.PrincipalType,
        Subject = p.Session.Subject,
        Email = p.Session.PrincipalType == PrincipalTypes.Human ? p.Owner.Email : null,
        Owner = p.Owner.Email,
        Issuer = p.Session.Issuer,
        ClientId = p.Session.ClientId,
        BindingId = p.Session.BindingId,
        Repository = p.Session.Repository,
        RepositoryId = p.Session.RepositoryId,
        Ref = p.Session.Ref,
        WorkflowRef = p.Session.WorkflowRef,
        RunId = p.Session.RunId,
        Capabilities = p.Capabilities.Order(StringComparer.Ordinal),
        SessionExpiresAt = p.Session.ExpiresUtc,
    };

    private static object DescribeBinding(WorkloadBinding b) => new
    {
        b.Id,
        b.Issuer,
        b.Repository,
        b.RepositoryId,
        b.RepositoryOwnerId,
        b.Ref,
        b.WorkflowRef,
        b.JobWorkflowRef,
        b.Environment,
        Events = NameList.Parse(b.EventNames).Order(StringComparer.Ordinal),
        Capabilities = NameList.Parse(b.Capabilities).Order(StringComparer.Ordinal),
        b.Description,
        b.CreatedUtc,
    };

    /// <summary>
    /// Reads an optional JSON body. No body at all gives (null, null), and the caller applies its defaults. A body
    /// that is present but not JSON, malformed or of the wrong shape is a 400/415 error, never treated as empty:
    /// a broken revoke request must not revoke the whole session.
    /// </summary>
    private static async Task<(T? Value, IResult? Error)> ReadJsonAsync<T>(HttpContext ctx) where T : class
    {
        var request = ctx.Request;
        var hasBody = request.ContentLength is > 0
            || (request.ContentLength is null && (request.Headers.TransferEncoding.Count > 0 || request.ContentType is not null));
        if (!hasBody)
            return (null, null);
        if (!request.HasJsonContentType())
            return (null, Error(StatusCodes.Status415UnsupportedMediaType, "invalid_request", "the body must be application/json"));
        try
        {
            var value = await request.ReadFromJsonAsync<T>(Json, ctx.RequestAborted);
            return value is null
                ? (null, Error(StatusCodes.Status400BadRequest, "invalid_request", "the body must be a JSON object"))
                : (value, null);
        }
        catch (JsonException)
        {
            return (null, Error(StatusCodes.Status400BadRequest, "invalid_request", "the body is not valid JSON for this request"));
        }
    }

    private static IResult Error(int status, string error, string reason) =>
        Results.Json(new { Error = error, Reason = reason }, Json, statusCode: status);

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

    private static DateTime Min(DateTime a, DateTime b) => a < b ? a : b;
}
