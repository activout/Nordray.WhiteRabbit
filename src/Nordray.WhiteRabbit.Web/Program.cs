using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.RateLimiting;
using Nordray.WhiteRabbit.AuthProxy;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Infrastructure;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Proxy;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);
var configuration = builder.Configuration;

// --- Infrastructure (DB, email, login codes) ---
builder.Services.AddInfrastructure(configuration);

// --- Bunny operation registry (singleton — the registry is immutable) ---
builder.Services.AddSingleton<BunnyOperationRegistry>();

// --- Authentication: cookie session for White Rabbit's own UI ---
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/login";
        options.Cookie.Name = "WhiteRabbit.Session";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
    });

builder.Services.AddAuthorization();

// --- Rate limiting (IP-based; per-email rate limiting is in LoginCodeService) ---
builder.Services.AddRateLimiter(opts =>
{
    opts.AddFixedWindowLimiter("login", o =>
    {
        o.PermitLimit = 20;
        o.Window = TimeSpan.FromHours(1);
        o.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        o.QueueLimit = 0;
    });
    opts.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
});

// --- YARP: hardcoded Dex proxy routes ---
// The Dex cluster address is environment-specific; everything else is fixed.
var dexAddress = configuration["Dex:InternalAddress"] ?? "http://dex:5556";

var dexRoutes = new List<RouteConfig>
{
    new() { RouteId = "dex-auth",      ClusterId = "dex", Match = new RouteMatch { Path = "/auth/{**catch}" } },
    new() { RouteId = "dex-discovery", ClusterId = "dex", Match = new RouteMatch { Path = "/.well-known/openid-configuration" } },
    new() { RouteId = "dex-token",     ClusterId = "dex", Match = new RouteMatch { Path = "/token" } },
    new() { RouteId = "dex-keys",      ClusterId = "dex", Match = new RouteMatch { Path = "/keys" } },
    new() { RouteId = "dex-userinfo",  ClusterId = "dex", Match = new RouteMatch { Path = "/userinfo" } },
    new() { RouteId = "dex-callback",  ClusterId = "dex", Match = new RouteMatch { Path = "/callback/{**catch}" } },
};

var dexClusters = new List<ClusterConfig>
{
    new()
    {
        ClusterId = "dex",
        Destinations = new Dictionary<string, DestinationConfig>
        {
            ["primary"] = new() { Address = dexAddress },
        },
    },
};

builder.Services.AddReverseProxy()
    .LoadFromMemory(dexRoutes, dexClusters)
    .AddTransforms(ctx =>
    {
        // Inject the authenticated user's email as X-Remote-User before forwarding to Dex
        if (ctx.Route.RouteId == "dex-auth")
        {
            ctx.AddRequestTransform(transform =>
            {
                var email = DexAuthProxyMiddleware.GetRemoteUser(transform.HttpContext);
                if (email is not null)
                    transform.ProxyRequest.Headers.TryAddWithoutValidation("X-Remote-User", email);
                return ValueTask.CompletedTask;
            });
        }
    });

// --- UI ---
builder.Services.AddRazorPages();

// -----------------------------------------------------------------------
var app = builder.Build();
// -----------------------------------------------------------------------

// Ensure database schema exists before handling any requests
await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// Dex authproxy middleware: intercepts /auth (but not /auth/email/* which are White Rabbit's own endpoints)
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/auth", StringComparison.OrdinalIgnoreCase)
        && !ctx.Request.Path.StartsWithSegments("/auth/email", StringComparison.OrdinalIgnoreCase),
    branch => branch.UseMiddleware<DexAuthProxyMiddleware>());

// --- Health endpoints ---
app.MapGet("/.well-known/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/.well-known/ready", (DatabaseInitializer _) => Results.Ok(new { status = "ready" }));

// --- Razor Pages (login, consent, grants) ---
app.MapRazorPages();

// --- Bunny API proxy: /proxy/api.bunny.net/{**path} ---
// Requests are validated against BunnyOperationRegistry before being forwarded.
// Unsupported paths → 404. Unauthenticated → 401. Missing capability → 403.
app.Map("/proxy/api.bunny.net/{**path}",
    (HttpContext ctx, IHttpForwarder forwarder, BunnyOperationRegistry registry, IUserRepository users)
        => BunnyForwarder.HandleAsync(ctx, forwarder, registry, users));

// --- YARP (Dex proxy) ---
app.MapReverseProxy();

app.Run();
