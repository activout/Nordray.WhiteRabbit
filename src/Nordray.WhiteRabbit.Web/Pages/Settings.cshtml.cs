using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Pages;

[Authorize]
public sealed class SettingsModel(IUserRepository users, IDataProtectionProvider dataProtection) : PageModel
{
    private readonly IDataProtector _protector = dataProtection.CreateProtector("BunnyApiKey.v1");

    [BindProperty]
    public string ApiKey { get; set; } = "";

    public bool HasApiKey { get; private set; }
    public string? SuccessMessage { get; private set; }
    public string? ErrorMessage { get; private set; }

    public async Task OnGetAsync()
    {
        var user = await GetCurrentUserAsync();
        HasApiKey = !string.IsNullOrEmpty(user?.BunnyApiKey);
    }

    public async Task<IActionResult> OnPostAsync()
    {
        var user = await GetCurrentUserAsync();
        if (user is null)
            return RedirectToPage("/Login");

        if (string.IsNullOrWhiteSpace(ApiKey))
        {
            HasApiKey = !string.IsNullOrEmpty(user.BunnyApiKey);
            ErrorMessage = "API key cannot be empty.";
            return Page();
        }

        await users.UpdateBunnyApiKeyAsync(user.Id, _protector.Protect(ApiKey.Trim()));
        HasApiKey = true;
        SuccessMessage = "API key saved.";
        return Page();
    }

    private async Task<Core.Models.User?> GetCurrentUserAsync()
    {
        var email = User.FindFirstValue(ClaimTypes.Email);
        return email is not null ? await users.FindByEmailAsync(email) : null;
    }
}
