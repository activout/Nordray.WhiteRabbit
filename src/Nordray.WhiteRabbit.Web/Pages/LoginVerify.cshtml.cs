using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.Database;

namespace Nordray.WhiteRabbit.Web.Pages;

[EnableRateLimiting("login-verify")]
public sealed class LoginVerifyModel(
    ILoginCodeService loginCodes,
    IUserRepository users,
    ILogger<LoginVerifyModel> logger) : PageModel
{
    [BindProperty]
    public string Email { get; set; } = "";

    [BindProperty]
    public string Code { get; set; } = "";

    [BindProperty]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public void OnGet(string email, string? returnUrl)
    {
        Email = email;
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        var verified = await loginCodes.VerifyAsync(Email, Code.Trim());
        if (!verified)
        {
            logger.LogWarning("Failed login code verification for {Email}", Email);
            ErrorMessage = "The code is incorrect or has expired. Please try again.";
            return Page();
        }

        logger.LogInformation("Successful login for {Email}", Email);

        var now = DateTimeOffset.UtcNow;
        var user = await users.FindByEmailAsync(Email);

        if (user is null)
        {
            user = new User
            {
                Subject = Guid.NewGuid().ToString(),
                Email = Email,
                CreatedUtc = now,
                LastLoginUtc = now,
            };
            await users.InsertAsync(user);
            // Re-fetch to get the assigned Id
            user = await users.FindByEmailAsync(Email);
        }
        else
        {
            await users.UpdateLastLoginAsync(user.Id, now);
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Email, Email),
            new Claim(ClaimTypes.Name, Email),
            new Claim(ClaimTypes.NameIdentifier, user!.Subject),
        };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        var principal = new ClaimsPrincipal(identity);

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            principal,
            new AuthenticationProperties { IsPersistent = false });

        return Redirect(SafeReturnUrl(ReturnUrl));
    }

    // Only allow relative URLs to prevent open-redirect attacks
    private static string SafeReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrEmpty(returnUrl)
            && Uri.TryCreate(returnUrl, UriKind.Relative, out _)
            && returnUrl.StartsWith('/'))
        {
            return returnUrl;
        }
        return "/";
    }
}
