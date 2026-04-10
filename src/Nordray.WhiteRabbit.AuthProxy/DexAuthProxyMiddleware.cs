using System.Security.Claims;
using Microsoft.AspNetCore.Http;

namespace Nordray.WhiteRabbit.AuthProxy;

/// <summary>
/// Sits in front of the Dex /auth endpoint.
/// Strips any client-supplied X-Remote-* headers, then either redirects unauthenticated
/// users to /login or passes the authenticated user's email into HttpContext.Items so
/// the YARP transformer can inject it as X-Remote-User before forwarding to Dex.
/// </summary>
public sealed class DexAuthProxyMiddleware(RequestDelegate next)
{
    public const string RemoteUserKey = "WhiteRabbit.RemoteUser";

    public async Task InvokeAsync(HttpContext context)
    {
        // Security: always strip client-supplied identity headers before any auth check
        context.Request.Headers.Remove("X-Remote-User");
        context.Request.Headers.Remove("X-Remote-Groups");
        context.Request.Headers.Remove("X-Remote-Extra");

        if (context.User.Identity?.IsAuthenticated != true)
        {
            var returnUrl = context.Request.Path + context.Request.QueryString;
            context.Response.Redirect("/login?returnUrl=" + Uri.EscapeDataString(returnUrl));
            return;
        }

        var email = context.User.FindFirstValue(ClaimTypes.Email);
        if (email is not null)
            context.Items[RemoteUserKey] = email;

        await next(context);
    }

    public static string? GetRemoteUser(HttpContext context) =>
        context.Items.TryGetValue(RemoteUserKey, out var val) ? val as string : null;
}
