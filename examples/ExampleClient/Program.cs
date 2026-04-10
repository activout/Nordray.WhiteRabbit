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
    options.Authority = configuration["WhiteRabbit:BaseUrl"];
    options.ClientId = configuration["Oidc:ClientId"];
    options.ClientSecret = configuration["Oidc:ClientSecret"];
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

// Trigger sign-out of both cookie and OIDC sessions.
app.MapPost("/logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    await ctx.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme,
        new AuthenticationProperties { RedirectUri = "/signed-out" });
}).RequireAuthorization();

app.Run();
