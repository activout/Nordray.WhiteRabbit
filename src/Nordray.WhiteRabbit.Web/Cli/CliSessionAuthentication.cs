using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>
/// Authenticates <c>Authorization: Bearer wrs_…</c> White Rabbit CLI sessions. Only the CLI and admin endpoints
/// accept this scheme; the Bunny proxy does not, and virtual credentials are never accepted here.
/// </summary>
public sealed class CliSessionAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    ICliSessionDao sessions)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "CliSession";
    public const string SessionItem = "WhiteRabbit.CliSession";
    public const string PrincipalTypeClaim = "wr:principal_type";
    public const string SessionIdClaim = "wr:session_id";

    /// <summary>True when the request carries a White Rabbit session token, used to pick this scheme.</summary>
    public static bool Carries(HttpRequest request) =>
        request.Headers.Authorization.ToString().StartsWith("Bearer " + OpaqueToken.SessionPrefix, StringComparison.Ordinal);

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Carries(Request)) return AuthenticateResult.NoResult();
        var token = Request.Headers.Authorization.ToString()["Bearer ".Length..].Trim();
        if (!OpaqueToken.LooksLike(token, OpaqueToken.SessionPrefix)) return AuthenticateResult.Fail("malformed session token");

        var session = await sessions.FindByTokenHashAsync(OpaqueToken.Hash(token));
        if (session is null) return AuthenticateResult.Fail("unknown session");
        if (session.RevokedUtc is not null) return AuthenticateResult.Fail("session revoked");
        if (session.ExpiresUtc <= DateTime.UtcNow) return AuthenticateResult.Fail("session expired");

        Context.Items[SessionItem] = session;
        var identity = new ClaimsIdentity(
            [new Claim(SessionIdClaim, session.Id), new Claim(PrincipalTypeClaim, session.PrincipalType)], SchemeName);
        return AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), SchemeName));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = "Bearer";
        return Task.CompletedTask;
    }

    public static CliSession? SessionOf(HttpContext ctx) => ctx.Items[SessionItem] as CliSession;
}
