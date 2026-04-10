using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Nordray.WhiteRabbit.AuthProxy;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Proxy;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

// Secrets are never stored in appsettings files. All sensitive values must be
// supplied as WhiteRabbit_* environment variables (__ maps to : in config hierarchy).
// Example: WhiteRabbit_Mailjet__ApiKey=xxx  →  Mailjet:ApiKey
builder.Configuration.AddEnvironmentVariables(prefix: "WhiteRabbit_");

var configuration = builder.Configuration;

// --- Infrastructure (DB, email, login codes, grants) ---
builder.Services.AddInfrastructure(configuration);

// --- Bunny operation registry (singleton — immutable) ---
builder.Services.AddSingleton<BunnyOperationRegistry>();

// --- Capability seeder (scoped — uses IDbConnection) ---
builder.Services.AddScoped<CapabilitySeeder>();

// --- Authentication ---
// Cookie for White Rabbit UI; JWT Bearer for OIDC clients calling the proxy.
// A policy scheme selects the right handler based on the presence of Authorization header.
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = "SmartScheme";
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddPolicyScheme("SmartScheme", "Cookie or Bearer", options =>
{
    options.ForwardDefaultSelector = ctx =>
        ctx.Request.Headers.ContainsKey("Authorization")
            ? JwtBearerDefaults.AuthenticationScheme
            : CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
{
    options.LoginPath = "/login";
    options.Cookie.Name = "WhiteRabbit.Session";
    options.Cookie.HttpOnly = true;
    options.Cookie.SameSite = SameSiteMode.Lax;
    options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
    options.ExpireTimeSpan = TimeSpan.FromHours(8);
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    // Dex is the token authority. White Rabbit proxies its well-known endpoints
    // so the issuer URL is White Rabbit's own address in production.
    options.Authority = configuration["Dex:IssuerUrl"];
    options.RequireHttpsMetadata = false; // HTTPS enforced at the edge in production
    options.TokenValidationParameters = new()
    {
        ValidateAudience = false, // Audience varies per client; issuer + signature are sufficient
    };
});

builder.Services.AddAuthorization();

// --- Rate limiting ---
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

// Ensure database schema exists and capabilities are seeded before serving requests
await app.Services.GetRequiredService<DatabaseInitializer>().InitializeAsync();
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<CapabilitySeeder>().SeedAsync();
}

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

// DexAuthProxyMiddleware intercepts /auth/* (but not /auth/email/* which are White Rabbit endpoints)
app.UseWhen(
    ctx => ctx.Request.Path.StartsWithSegments("/auth", StringComparison.OrdinalIgnoreCase)
        && !ctx.Request.Path.StartsWithSegments("/auth/email", StringComparison.OrdinalIgnoreCase),
    branch => branch.UseMiddleware<DexAuthProxyMiddleware>());

// --- Health endpoints ---
app.MapGet("/.well-known/health", () => Results.Ok(new { status = "healthy" }));
app.MapGet("/.well-known/ready", (DatabaseInitializer _) => Results.Ok(new { status = "ready" }));

// --- Razor Pages ---
app.MapRazorPages();

// --- Bunny API proxy ---
app.Map("/proxy/api.bunny.net/{**path}",
    (HttpContext ctx, IHttpForwarder forwarder, BunnyOperationRegistry registry,
     IUserRepository users, IGrantService grants)
        => BunnyForwarder.HandleAsync(ctx, forwarder, registry, users, grants));

// --- YARP (Dex proxy) ---
app.MapReverseProxy();

app.Run();
