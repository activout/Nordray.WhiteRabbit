using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Web.Cli;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Nordray.WhiteRabbit.Web.Proxy;

/// <summary>
/// Decides every Bunny proxy request before YARP forwards it. A request authenticates with either
/// <list type="bullet">
/// <item>a virtual credential in <c>AccessKey</c> (from <c>/api/cli/credentials</c>), or</item>
/// <item>a Dex token issued to a configured proxy client (<c>Proxy:AllowedClientIds</c>).</item>
/// </list>
/// Both resolve to an owner and a set of effective capabilities; then the registry's capability is required and
/// the owner's own Bunny key is injected server side. The inbound <c>AccessKey</c> and <c>Authorization</c> headers
/// are always removed by the route transforms, so neither is forwarded upstream.
/// </summary>
public sealed class BunnyProxyGate(
    ProxyClientOptions proxyClients,
    SignInPolicy signInPolicy,
    IDataProtectionProvider dataProtection)
{
    public const string AccessKeyItem = "bunny.access-key";
    private readonly IDataProtector _bunnyKeyProtector = dataProtection.CreateProtector("BunnyApiKey.v1");

    private sealed record Caller(User Owner, IReadOnlySet<string> Capabilities, SecurityEvent Audit);

    public async Task InvokeAsync(HttpContext ctx, Func<Task> next, RouteModel route)
    {
        var metadata = route.Config.Metadata!;
        var operationId = route.Config.RouteId["bunny.".Length..];
        var audit = ctx.RequestServices.GetRequiredService<SecurityAudit>();
        var now = DateTime.UtcNow;

        var (caller, denial) = ctx.Request.Headers.ContainsKey("AccessKey")
            ? await FromVirtualKeyAsync(ctx, now)
            : await FromDexTokenAsync(ctx);

        if (caller is null)
        {
            var (status, error, describe) = denial!.Value;
            await audit.RecordAsync(describe with { OperationId = operationId, HttpStatus = status });
            await WriteError(ctx, status, error);
            return;
        }

        var allowedEvent = caller.Audit with { EventType = "proxy.request", OperationId = operationId };

        // Capability check: every operation not marked authentication-only needs its capability.
        if (metadata["AuthOnly"] != "true")
        {
            var capability = metadata["Capability"];
            if (!caller.Capabilities.Contains(capability))
            {
                await audit.RecordAsync(allowedEvent with { Outcome = SecurityEvent.Denied, Reason = "capability_not_granted", HttpStatus = 403 });
                await WriteError(ctx, 403, $$"""{"error":"capability_not_granted","required":"{{capability}}"}""");
                return;
            }
        }

        // Inject the owner's own bunny.net API key via Items, so the route transform adds it after header copying.
        if (metadata["CredentialKind"] == "AccountApiKey")
        {
            var reason = TryUnprotectKey(caller.Owner, out var plaintextKey);
            if (reason is not null)
            {
                await audit.RecordAsync(allowedEvent with { Outcome = SecurityEvent.Denied, Reason = reason, HttpStatus = 403 });
                await WriteError(ctx, 403, """{"error":"bunny_api_key_not_configured","detail":"Go to /settings to add your bunny.net API key."}""");
                return;
            }
            ctx.Items[AccessKeyItem] = plaintextKey;
        }

        await next();

        // A forwarding failure (unreachable upstream, timeout) has no upstream status.
        var forwardError = ctx.Features.Get<IForwarderErrorFeature>();
        await audit.RecordAsync(allowedEvent with
        {
            Outcome = SecurityEvent.Allowed,
            HttpStatus = ctx.Response.StatusCode,
            UpstreamStatus = forwardError is null ? ctx.Response.StatusCode : null,
            Reason = forwardError is null ? null : "upstream_" + forwardError.Error.ToString().ToLowerInvariant(),
        });
    }

    private async Task<(Caller?, (int, string, SecurityEvent)?)> FromVirtualKeyAsync(HttpContext ctx, DateTime now)
    {
        var key = ctx.Request.Headers["AccessKey"].ToString();
        var denied = new SecurityEvent { EventType = "proxy.request", Outcome = SecurityEvent.Denied };

        // Anything that is not a White Rabbit virtual key, including a real Bunny key, is refused outright.
        if (!OpaqueToken.LooksLike(key, OpaqueToken.VirtualKeyPrefix))
            return (null, (401, """{"error":"invalid_access_key"}""", denied with { Reason = "invalid_access_key" }));

        var credentials = ctx.RequestServices.GetRequiredService<IVirtualCredentialDao>();
        var credential = await credentials.FindByKeyHashAsync(OpaqueToken.Hash(key));
        if (credential is null)
            return (null, (401, """{"error":"invalid_access_key"}""", denied with { Reason = "unknown_credential" }));
        denied = denied with { CredentialId = credential.Id, SessionId = credential.SessionId };
        if (credential.RevokedUtc is not null)
            return (null, (401, """{"error":"invalid_access_key"}""", denied with { Reason = "credential_revoked" }));
        if (credential.ExpiresUtc <= now)
            return (null, (401, """{"error":"access_key_expired"}""", denied with { Reason = "credential_expired" }));

        var session = await ctx.RequestServices.GetRequiredService<ICliSessionDao>().FindAsync(credential.SessionId);
        if (session is null)
            return (null, (401, """{"error":"invalid_access_key"}""", denied with { Reason = "session_missing" }));

        var resolved = await ctx.RequestServices.GetRequiredService<CliPrincipalResolver>().ResolveAsync(session, now);
        if (resolved.Principal is null)
        {
            var describe = denied with
            {
                Reason = resolved.DenialReason,
                PrincipalType = session.PrincipalType,
                Subject = session.Subject,
                UserId = session.UserId,
                BindingId = session.BindingId,
            };
            return (null, (403, $$"""{"error":"access_denied","reason":"{{resolved.DenialReason}}"}""", describe));
        }

        // Never broader than what the credential was issued for, nor than what the principal may do now.
        var effective = NameList.Parse(credential.Capabilities).Where(resolved.Principal.Capabilities.Contains).ToHashSet(StringComparer.Ordinal);
        var audit = resolved.Principal.Describe("proxy.request", SecurityEvent.Allowed) with { CredentialId = credential.Id };
        return (new Caller(resolved.Principal.Owner, effective, audit), null);
    }

    private async Task<(Caller?, (int, string, SecurityEvent)?)> FromDexTokenAsync(HttpContext ctx)
    {
        var denied = new SecurityEvent { EventType = "proxy.request", Outcome = SecurityEvent.Denied };

        if (ctx.User.Identity?.IsAuthenticated != true)
            return (null, (401, """{"error":"unauthenticated"}""", denied with { Reason = "unauthenticated" }));

        // azp (authorized party) wins; otherwise the token must have exactly one audience. Cookie sessions have
        // neither and must use a registered OIDC client instead.
        var email = ctx.User.FindFirstValue(ClaimTypes.Email);
        var clientId = OidcClientIdentity.Resolve(ctx.User, proxyClients.AllowedClientIds);
        denied = denied with { PrincipalType = PrincipalTypes.Human, Subject = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), ClientId = clientId };
        if (clientId is null)
            return (null, (403, """{"error":"proxy_requires_oidc","detail":"The proxy is only accessible via OIDC client tokens. Use a registered client application."}""",
                denied with { Reason = "no_oidc_client" }));

        if (!signInPolicy.IsAllowed(email))
            return (null, (403, """{"error":"user_not_allowed"}""", denied with { Reason = "user_not_allowed" }));

        var owner = await ctx.RequestServices.GetRequiredService<IUserRepository>().FindByEmailAsync(email!);
        if (owner is null)
            return (null, (403, """{"error":"user_not_allowed"}""", denied with { Reason = "owner_missing" }));

        var granted = await ctx.RequestServices.GetRequiredService<IGrantService>().GetGrantedCapabilitiesAsync(owner.Email, clientId);
        var audit = denied with { Outcome = SecurityEvent.Allowed, UserId = owner.Id, Issuer = ctx.User.FindFirstValue("iss") };
        return (new Caller(owner, granted, audit), null);
    }

    /// <summary>Returns a denial reason, or null with the decrypted key.</summary>
    private string? TryUnprotectKey(User owner, out string plaintextKey)
    {
        plaintextKey = "";
        if (string.IsNullOrEmpty(owner.BunnyApiKey))
            return "no_api_key";
        try
        {
            plaintextKey = _bunnyKeyProtector.Unprotect(owner.BunnyApiKey);
            return null;
        }
        catch (CryptographicException)
        {
            return "key_decryption_failed";
        }
    }

    private static Task WriteError(HttpContext ctx, int status, string json)
    {
        ctx.Response.StatusCode = status;
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsync(json);
    }
}
