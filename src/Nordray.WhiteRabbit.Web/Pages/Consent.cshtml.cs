using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Nordray.WhiteRabbit.Bunny;
using Nordray.WhiteRabbit.Core.Services;

namespace Nordray.WhiteRabbit.Web.Pages;

[Authorize]
public sealed class ConsentModel(IGrantService grants, BunnyOperationRegistry registry) : PageModel
{
    private static readonly HashSet<string> OidcStandardScopes =
        ["openid", "email", "profile", "offline_access", "address", "phone"];

    [BindProperty]
    public string ReturnUrl { get; set; } = "/";

    public string ClientId { get; private set; } = "";
    public IReadOnlyList<CapabilityViewModel> Capabilities { get; private set; } = [];
    public IReadOnlyList<string> AuthOnlyOperations { get; private set; } = [];

    public IActionResult OnGet(string returnUrl)
    {
        ReturnUrl = returnUrl;
        Populate(returnUrl);
        return Page();
    }

    public async Task<IActionResult> OnPostApproveAsync()
    {
        Populate(ReturnUrl);

        var email = User.FindFirstValue(ClaimTypes.Email)!;
        var capabilities = Capabilities.Select(c => c.Name);
        await grants.StoreGrantAsync(email, ClientId, capabilities);

        return LocalRedirect(Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : "/");
    }

    // Denial ends on White Rabbit's own page. White Rabbit does not know which redirect URIs each Dex client
    // registered, so redirecting to the requested redirect_uri would be an open redirect.
    public IActionResult OnPostDenyAsync() => RedirectToPage("/Index");

    private void Populate(string returnUrl)
    {
        var oidcParams = ParseOidcParams(returnUrl);

        ClientId = oidcParams.GetValueOrDefault("client_id", "");

        var scopes = oidcParams.GetValueOrDefault("scope", "")
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(s => !OidcStandardScopes.Contains(s))
            .ToHashSet();

        var allOps = registry.GetAll();

        Capabilities = registry.GetCapabilities()
            .Where(c => scopes.Contains(c.Name))
            .Select(c => new CapabilityViewModel(c.Name, c.Title, c.Description))
            .ToList();

        AuthOnlyOperations = allOps
            .Where(op => op.RequiresAuthenticationOnly)
            .Select(op => op.ConsentTitle)
            .Distinct()
            .ToList();
    }

    private static Dictionary<string, string> ParseOidcParams(string returnUrl)
    {
        // returnUrl is a path+query like /auth?client_id=...&scope=...
        var queryIndex = returnUrl.IndexOf('?');
        if (queryIndex < 0) return [];

        return QueryHelpers.ParseQuery(returnUrl[(queryIndex + 1)..])
            .Where(kv => kv.Value.Count > 0)
            .ToDictionary(kv => kv.Key, kv => kv.Value.ToString());
    }

    public sealed record CapabilityViewModel(string Name, string DisplayName, string Description);
}
