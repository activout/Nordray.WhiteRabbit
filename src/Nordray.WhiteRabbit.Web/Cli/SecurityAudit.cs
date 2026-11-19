using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Cli;

/// <summary>
/// Writes the security audit trail. Fills in the request's correlation ID, method and path (never the query
/// string), and mirrors each event to the structured log without any secret.
/// </summary>
public sealed class SecurityAudit(ISecurityEventDao events, IHttpContextAccessor http, ILogger<SecurityAudit> logger)
{
    public async Task RecordAsync(SecurityEvent securityEvent)
    {
        var ctx = http.HttpContext;
        var e = securityEvent with
        {
            CorrelationId = securityEvent.CorrelationId ?? (ctx is null ? null : CorrelationId.Get(ctx)),
            HttpMethod = securityEvent.HttpMethod ?? ctx?.Request.Method,
            Path = securityEvent.Path ?? ctx?.Request.Path.Value,
        };
        logger.LogInformation(
            "Security event {EventType} {Outcome} {Reason} principal={PrincipalType} subject={Subject} binding={BindingId} credential={CredentialId} operation={OperationId} status={HttpStatus} upstream={UpstreamStatus} correlation={CorrelationId}",
            e.EventType, e.Outcome, e.Reason, e.PrincipalType, e.Subject, e.BindingId, e.CredentialId, e.OperationId, e.HttpStatus, e.UpstreamStatus, e.CorrelationId);
        await events.InsertAsync(e);
    }
}

/// <summary>
/// One correlation ID per request: the caller's <c>X-Correlation-ID</c> when it is a safe token, otherwise a new
/// one. Returned in the response header and recorded with every audit event of the request.
/// </summary>
public static class CorrelationId
{
    public const string Header = "X-Correlation-ID";
    private const string ItemKey = "WhiteRabbit.CorrelationId";

    public static string Get(HttpContext ctx) => ctx.Items[ItemKey] as string ?? Assign(ctx);

    public static IApplicationBuilder UseCorrelationId(this IApplicationBuilder app) => app.Use(async (ctx, next) =>
    {
        var id = Assign(ctx);
        ctx.Response.OnStarting(() =>
        {
            ctx.Response.Headers[Header] = id;
            return Task.CompletedTask;
        });
        await next();
    });

    private static string Assign(HttpContext ctx)
    {
        var supplied = ctx.Request.Headers[Header].ToString();
        var id = supplied.Length is > 0 and <= 64 && supplied.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.')
            ? supplied
            : Guid.NewGuid().ToString("N");
        ctx.Items[ItemKey] = id;
        return id;
    }
}
