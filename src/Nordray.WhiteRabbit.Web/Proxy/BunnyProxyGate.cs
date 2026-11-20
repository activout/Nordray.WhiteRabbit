using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Web.Cli;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Model;

namespace Nordray.WhiteRabbit.Web.Proxy;

/// <summary>
/// Decides every Bunny proxy request before YARP forwards it. A request authenticates with a virtual credential in
/// <c>AccessKey</c> (from <c>/api/cli/credentials</c>), which resolves to an owner and a set of effective
/// capabilities; then the registry's capability is required and
/// the owner's own Bunny key is injected server side. The inbound <c>AccessKey</c> and <c>Authorization</c> headers
/// are always removed by the route transforms, so neither is forwarded upstream.
/// </summary>
public sealed class BunnyProxyGate(IDataProtectionProvider dataProtection)
{
    public const string AccessKeyItem = "bunny.access-key";
    /// <summary>Data Protection purpose for the stored Bunny API keys. Changing it makes every stored key unreadable.</summary>
    public const string KeyPurpose = "BunnyApiKey.v1";
    private readonly IDataProtector _bunnyKeyProtector = dataProtection.CreateProtector(KeyPurpose);

    private sealed record Caller(User Owner, IReadOnlySet<string> Capabilities, SecurityEvent Audit);

    public async Task InvokeAsync(HttpContext ctx, Func<Task> next, RouteModel route)
    {
        var metadata = route.Config.Metadata!;
        var operationId = route.Config.RouteId["bunny.".Length..];
        var audit = ctx.RequestServices.GetRequiredService<SecurityAudit>();
        var now = DateTime.UtcNow;

        var (caller, denial) = await FromVirtualKeyAsync(ctx, now);

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
                await WriteError(ctx, 403, """{"error":"bunny_api_key_not_configured","detail":"Run rabbit admin key set to add your bunny.net API key."}""");
                return;
            }
            ctx.Items[AccessKeyItem] = plaintextKey;
        }

        await next();

        // A forwarding failure (unreachable upstream, timeout) has no upstream status. Neither has a request White
        // Rabbit refused after authorising it (e.g. a body field that is not allowed). When White Rabbit replaced
        // Bunny's answer (e.g. an unredactable body), Bunny's own status is kept next to the one the caller got.
        var forwardError = ctx.Features.Get<IForwarderErrorFeature>();
        var localReason = ctx.Items[ProxyRequestBodyPolicy.LocalReasonItem] as string;
        var upstreamStatus = ctx.Items[ProxyRequestBodyPolicy.UpstreamStatusItem] as int?;
        if (forwardError is null && localReason is null) upstreamStatus = ctx.Response.StatusCode;
        await audit.RecordAsync(allowedEvent with
        {
            Outcome = SecurityEvent.Allowed,
            HttpStatus = ctx.Response.StatusCode,
            UpstreamStatus = forwardError is null ? upstreamStatus : null,
            Reason = forwardError is not null ? "upstream_" + forwardError.Error.ToString().ToLowerInvariant() : localReason,
        });
    }

    private async Task<(Caller?, (int, string, SecurityEvent)?)> FromVirtualKeyAsync(HttpContext ctx, DateTime now)
    {
        var key = ctx.Request.Headers["AccessKey"].ToString();
        var denied = new SecurityEvent { EventType = "proxy.request", Outcome = SecurityEvent.Denied };

        if (string.IsNullOrEmpty(key))
            return (null, (401, """{"error":"unauthenticated"}""", denied with { Reason = "unauthenticated" }));
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
