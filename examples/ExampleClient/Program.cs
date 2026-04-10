using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

// Secrets are never stored in appsettings files. Supply via environment:
//   Oidc__ClientSecret=<your-secret>
var configuration = builder.Configuration;

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Cookie.Name = "ExampleClient.Session";
    options.LoginPath = "/";
})
.AddOpenIdConnect(options =>
{
    // White Rabbit proxies all Dex OIDC endpoints — authority is White Rabbit's public URL.
    options.Authority = configuration["WhiteRabbit:BaseUrl"] ?? throw new InvalidOperationException("Missing White Rabbit base URL configuration");
    options.ClientId = configuration["Oidc:ClientId"] ?? throw new InvalidOperationException("Missing OIDC client ID configuration");
    options.ClientSecret = configuration["Oidc:ClientSecret"] ?? throw new InvalidOperationException("Missing OIDC client secret configuration");
    options.ResponseType = "code";
    options.SaveTokens = true;               // stores access_token for proxy calls
    options.RequireHttpsMetadata = false;    // White Rabbit runs on HTTP in dev
    options.GetClaimsFromUserInfoEndpoint = true;

    // Request the capabilities this client needs.
    // White Rabbit will show a consent screen if they haven't been granted yet.
    options.Scope.Clear();
    options.Scope.Add("openid");
    options.Scope.Add("email");
    options.Scope.Add("offline_access");
    options.Scope.Add("pullzone.read");
    options.Scope.Add("statistics.read");

    options.SignedOutRedirectUri = "/signed-out";

    options.Events.OnRemoteFailure = ctx =>
    {
        // User clicked "Deny" on the consent screen — redirect home with a message
        // rather than letting the exception bubble up as a 500.
        if (ctx.Failure?.Message.Contains("access_denied") == true)
        {
            ctx.Response.Redirect("/?denied=1");
            ctx.HandleResponse();
            return Task.CompletedTask;
        }

        // Any other OIDC error: redirect home with a generic message.
        ctx.Response.Redirect("/?error=1");
        ctx.HandleResponse();
        return Task.CompletedTask;
    };
});

builder.Services.AddAuthorization();
builder.Services.AddRazorPages();

// Named HttpClient that calls the White Rabbit proxy.
// In Docker the base URL may differ from the public OIDC authority — see appsettings.
builder.Services.AddHttpClient("white-rabbit", (sp, client) =>
{
    var baseUrl = configuration["WhiteRabbit:ProxyBaseUrl"]
               ?? configuration["WhiteRabbit:BaseUrl"]
               ?? "http://localhost:8080";
    client.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
});

var app = builder.Build();

app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapRazorPages();

// Clear the local cookie session. Dex does not implement end_session_endpoint
// so there is no OIDC back-channel sign-out to perform; the access token expires naturally.
app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    ctx.Response.Redirect("/signed-out");
}).RequireAuthorization();

app.Run();
