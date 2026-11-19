using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Nordray.WhiteRabbit.Core.Access;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.LoginCodes;

namespace Nordray.WhiteRabbit.Web.Pages;

public sealed class LoginModel(ILoginCodeService loginCodes, SignInPolicy signInPolicy, ILogger<LoginModel> logger) : PageModel
{
    [BindProperty]
    public string Email { get; set; } = "";

    [BindProperty]
    public string? ReturnUrl { get; set; }

    public string? ErrorMessage { get; private set; }

    public void OnGet(string? returnUrl)
    {
        ReturnUrl = returnUrl;
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
            return Page();

        if (!IsValidEmail(Email))
        {
            ErrorMessage = "Please enter a valid email address.";
            return Page();
        }

        var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // An address that may not sign in gets the same response as one that may, so the form does not reveal
        // the allow-list, but no code is created or sent.
        if (!signInPolicy.IsAllowed(Email))
        {
            logger.LogWarning("Login code refused: address not on the sign-in allow-list");
            return RedirectToPage("/LoginVerify", new { email = Email, returnUrl = ReturnUrl });
        }

        try
        {
            await loginCodes.GenerateAndSendAsync(Email, ip);
            logger.LogInformation("Login code requested for {Email}", Email);
        }
        catch (RateLimitExceededException)
        {
            // Answered like any other request: a different response would reveal that the address is allowed.
            logger.LogWarning("Login code refused: per-address rate limit reached");
        }

        return RedirectToPage("/LoginVerify", new
        {
            email = Email,
            returnUrl = ReturnUrl,
        });
    }

    private static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email)) return false;
        var atIndex = email.IndexOf('@');
        return atIndex > 0 && atIndex < email.Length - 2 && email.LastIndexOf('@') == atIndex;
    }
}
