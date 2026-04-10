using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Nordray.WhiteRabbit.Core.Services;
using Nordray.WhiteRabbit.Infrastructure.LoginCodes;

namespace Nordray.WhiteRabbit.Web.Pages;

public sealed class LoginModel(ILoginCodeService loginCodes, ILogger<LoginModel> logger) : PageModel
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

        try
        {
            await loginCodes.GenerateAndSendAsync(Email, ip);
            logger.LogInformation("Login code requested for {Email}", Email);
        }
        catch (RateLimitExceededException ex)
        {
            ErrorMessage = ex.Message;
            return Page();
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
