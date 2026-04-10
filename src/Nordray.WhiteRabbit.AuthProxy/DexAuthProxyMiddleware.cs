using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.AuthProxy;

/// <summary>
/// Sits in front of the Dex /auth endpoint.
/// 1. Strips any client-supplied X-Remote-* headers (security boundary).
/// 2. Redirects unauthenticated users to /login.
/// 3. For OIDC authorization requests, checks that the user has already granted
///    the requested capabilities to the client. Redirects to /consent if not.
/// 4. Sets the authenticated user's email in HttpContext.Items so the YARP
///    transformer can inject it as X-Remote-User before forwarding to Dex.
/// </summary>
public sealed class DexAuthProxyMiddleware(RequestDelegate next)
{
    public const string RemoteUserKey = "WhiteRabbit.RemoteUser";

    // Standard OIDC scopes that do not map to White Rabbit capabilities.
    private static readonly HashSet<string> OidcStandardScopes =
        ["openid", "email", "profile", "offline_access", "address", "phone"];

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

        // For OIDC authorization requests, enforce capability grants before forwarding to Dex
        var clientId = context.Request.Query["client_id"].ToString();
        if (!string.IsNullOrEmpty(clientId) && email is not null)
        {
            var requestedCapabilities = ParseCapabilities(context.Request.Query["scope"].ToString());

            if (requestedCapabilities.Count > 0)
            {
                var grantService = context.RequestServices.GetRequiredService<IGrantService>();
                var granted = await grantService.GetGrantedCapabilitiesAsync(email, clientId);

                if (!requestedCapabilities.IsSubsetOf(granted))
                {
                    var returnUrl = context.Request.Path + context.Request.QueryString;
                    context.Response.Redirect("/consent?returnUrl=" + Uri.EscapeDataString(returnUrl));
                    return;
                }
            }
        }

        if (email is not null)
            context.Items[RemoteUserKey] = email;

        await next(context);
    }

    public static string? GetRemoteUser(HttpContext context) =>
        context.Items.TryGetValue(RemoteUserKey, out var val) ? val as string : null;

    private static HashSet<string> ParseCapabilities(string scope) =>
        scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
             .Where(s => !OidcStandardScopes.Contains(s))
             .ToHashSet();
}
