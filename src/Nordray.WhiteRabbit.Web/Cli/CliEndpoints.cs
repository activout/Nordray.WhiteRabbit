using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Web.Proxy;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>
/// The rabbit CLI's API:
/// <list type="bullet">
/// <item><c>POST /api/cli/exchange</c>: a <c>/cli/login</c> code (human) or a GitHub/Forgejo identity token (CI) for a White Rabbit session.</item>
/// <item><c>POST /api/cli/credentials</c>: a session for a short-lived virtual Bunny credential.</item>
/// <item><c>GET /api/cli/whoami</c>, <c>POST /api/cli/revoke</c>.</item>
/// <item><c>/api/admin/bindings</c>, <c>/api/admin/bunny-key</c>: an interactive human session manages its own workload
/// bindings and Bunny API key.</item>
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
        cli.MapGet("/config", Config).RequireRateLimiting(ApiRateLimit).AllowAnonymous();
        cli.MapPost("/exchange", Exchange).RequireRateLimiting(ExchangeRateLimit).AllowAnonymous();
        cli.MapPost("/credentials", IssueCredential).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);
        cli.MapGet("/whoami", WhoAmI).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);
        cli.MapPost("/revoke", Revoke).RequireAuthorization(SessionPolicy).RequireRateLimiting(ApiRateLimit);

        var admin = app.MapGroup("/api/admin/bindings").RequireAuthorization(HumanPolicy).RequireRateLimiting(ApiRateLimit);
        admin.MapGet("/", ListBindings);
        admin.MapPost("/", CreateBinding);
        admin.MapDelete("/{id:long}", RevokeBinding);

        app.MapGet("/api/admin/audit", ListAudit).RequireAuthorization(HumanPolicy).RequireRateLimiting(ApiRateLimit);

        var key = app.MapGroup("/api/admin/bunny-key").RequireAuthorization(HumanPolicy).RequireRateLimiting(ApiRateLimit);
        key.MapPut("/", SetBunnyKey);
        key.MapDelete("/", RemoveBunnyKey);
    }

    // ---------------------------------------------------------------- discovery

    /// <summary>
    /// What the rabbit CLI needs to know about this instance, so it only has to be told the server URL: the audience
    /// CI tokens must be requested for (empty when CI federation is off) and the capabilities. Nothing here is secret.
    /// </summary>
    private static IResult Config(IOptions<FederationOptions> federation, BunnyOperationRegistry registry) =>
        Results.Json(new
        {
            FederationAudience = federation.Value.Issuers.Count > 0 ? federation.Value.Audience : "",
            Capabilities = registry.GetCapabilities()
                .OrderBy(c => c.Name, StringComparer.Ordinal)
                .Select(c => new { c.Name, c.Title, c.Description }),
        }, Json);

    // ---------------------------------------------------------------- exchange

    /// <summary>Either <c>code</c> + <c>code_verifier</c> from <c>/cli/login</c>, or a CI <c>subject_token</c>.</summary>
    public sealed record ExchangeRequest(string? SubjectToken, string? Code, string? CodeVerifier);

    /// <summary>The issuer recorded on human sessions: White Rabbit's own sign-in.</summary>
    public const string HumanIssuer = "white-rabbit";
    public const string CliClientId = "rabbit-cli";

    private static async Task<IResult> Exchange(
        HttpContext ctx,
        IdentityTokenValidator validator,
        IUserRepository users,
        IWorkloadBindingDao bindings,
        ICliLoginCodeDao loginCodes,
        ICliSessionDao sessions,
        CliPrincipalResolver resolver,
        IOptions<CliOptions> cliOptions,
        SecurityAudit audit)
    {
        var (request, invalid) = await ReadJsonAsync<ExchangeRequest>(ctx);
        if (invalid is not null) return invalid;
        var hasCode = !string.IsNullOrWhiteSpace(request?.Code);
        if (hasCode == !string.IsNullOrWhiteSpace(request?.SubjectToken))
            return Error(StatusCodes.Status400BadRequest, "invalid_request", "send either code and code_verifier, or subject_token");

        var now = DateTime.UtcNow;
        var options = cliOptions.Value;
        CliSession session;

        if (hasCode)
        {
            // A human: the one-time code /cli/login sent to the CLI's loopback listener. It is consumed before the
            // verifier is checked, so a wrong guess burns it.
            var code = request!.Code!.Trim();
            var login = OpaqueToken.LooksLike(code, OpaqueToken.LoginCodePrefix)
                ? await loginCodes.ConsumeAsync(OpaqueToken.Hash(code), now)
                : null;
            if (login is null)
                return await DenyExchange(audit, "invalid_login_code", HumanIssuer, null);
            if (!Pkce.Matches(request.CodeVerifier, login.CodeChallenge))
                return await DenyExchange(audit, "code_verifier_mismatch", HumanIssuer, null);
            var user = await users.FindByIdAsync(login.UserId);
            if (user is null)
                return await DenyExchange(audit, "owner_missing", HumanIssuer, null);

            session = NewSession(now, options.HumanSessionLifetime) with
            {
                PrincipalType = PrincipalTypes.Human,
                UserId = user.Id,
                Subject = user.Subject,
                Issuer = HumanIssuer,
                ClientId = CliClientId,
            };
        }
        else
        {
            var validation = await validator.ValidateAsync(request!.SubjectToken!.Trim(), ctx.RequestAborted);
            if (validation.Token is null)
                return await DenyExchange(audit, validation.DenialReason!, validation.UnverifiedIssuer, null);

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

    // ---------------------------------------------------------------- admin: audit

    public const int MaxAuditEvents = 500;

    /// <summary>
    /// The caller's own security events: everything recorded with them as the owner, including their CI workloads'
    /// exchanges and proxy calls. Events with no known owner (e.g. a token from an untrusted issuer) are not included.
    /// </summary>
    private static async Task<IResult> ListAudit(
        HttpContext ctx, ISecurityEventDao events, CliPrincipalResolver resolver, SecurityAudit audit,
        [Microsoft.AspNetCore.Mvc.FromQuery(Name = "since")] DateTime? since,
        [Microsoft.AspNetCore.Mvc.FromQuery(Name = "binding_id")] long? bindingId,
        [Microsoft.AspNetCore.Mvc.FromQuery(Name = "limit")] int? limit)
    {
        var now = DateTime.UtcNow;
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.audit.list", now);
        if (principal is null) return denied!;
        if (limit is < 1 or > MaxAuditEvents)
            return Error(StatusCodes.Status400BadRequest, "invalid_request", $"limit must be 1-{MaxAuditEvents}");

        var from = since?.ToUniversalTime() ?? now.AddHours(-24);
        var list = await events.ListForOwnerAsync(principal.Owner.Id, from, bindingId, limit ?? 50);
        return Results.Json(list.Select(e => e with { UserId = null }), Json);
    }

    // ---------------------------------------------------------------- admin: Bunny API key

    public sealed record BunnyKeyRequest(string? ApiKey);

    /// <summary>Stores the owner's bunny.net API key, protected with the database key ring. Never echoed or audited.</summary>
    private static async Task<IResult> SetBunnyKey(
        HttpContext ctx, IUserRepository users, IDataProtectionProvider dataProtection, CliPrincipalResolver resolver, SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.bunny_key.set", DateTime.UtcNow);
        if (principal is null) return denied!;
        var (request, invalid) = await ReadJsonAsync<BunnyKeyRequest>(ctx);
        if (invalid is not null) return invalid;
        var apiKey = request?.ApiKey?.Trim();
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length > 256 || apiKey.Any(char.IsWhiteSpace))
            return Error(StatusCodes.Status400BadRequest, "invalid_request", "api_key must be a bunny.net API key");

        await users.UpdateBunnyApiKeyAsync(principal.Owner.Id, dataProtection.CreateProtector(BunnyProxyGate.KeyPurpose).Protect(apiKey));
        await audit.RecordAsync(principal.Describe("admin.bunny_key.set", SecurityEvent.Allowed) with { HttpStatus = 204 });
        return Results.NoContent();
    }

    private static async Task<IResult> RemoveBunnyKey(
        HttpContext ctx, IUserRepository users, CliPrincipalResolver resolver, SecurityAudit audit)
    {
        var (principal, denied) = await ResolveAsync(ctx, resolver, audit, "admin.bunny_key.remove", DateTime.UtcNow);
        if (principal is null) return denied!;
        await users.UpdateBunnyApiKeyAsync(principal.Owner.Id, null);
        await audit.RecordAsync(principal.Describe("admin.bunny_key.remove", SecurityEvent.Allowed) with { HttpStatus = 204 });
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
        HasBunnyKey = !string.IsNullOrEmpty(p.Owner.BunnyApiKey),
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
