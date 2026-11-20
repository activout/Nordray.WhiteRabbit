using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Nordray.WhiteRabbit.Core.Federation;
using Nordray.WhiteRabbit.Core.Models;
using Nordray.WhiteRabbit.Infrastructure.Database;
using Nordray.WhiteRabbit.Web.Cli;

namespace Nordray.WhiteRabbit.Web.Pages;

/// <summary>
/// The rabbit CLI's browser sign-in. The CLI opens this page with its loopback port, a state value and a PKCE S256
/// challenge; after the email-code sign-in and an explicit confirmation, the browser is sent to
/// <c>http://127.0.0.1:{port}/callback</c> with a one-time code that only the holder of the verifier can redeem at
/// <c>/api/cli/exchange</c>. The redirect target is always the loopback address, never a caller-supplied URL.
/// </summary>
[Authorize]
public sealed class CliLoginModel(
    IUserRepository users,
    ICliLoginCodeDao loginCodes,
    IOptions<CliOptions> cliOptions,
    SecurityAudit audit) : PageModel
{
    [BindProperty(SupportsGet = true, Name = "port")]
    public int Port { get; set; }

    [BindProperty(SupportsGet = true, Name = "state")]
    public string? State { get; set; }

    [BindProperty(SupportsGet = true, Name = "code_challenge")]
    public string? CodeChallenge { get; set; }

    public string Email { get; private set; } = "";
    public string? ErrorMessage { get; private set; }

    public void OnGet()
    {
        Email = User.FindFirstValue(ClaimTypes.Email) ?? "";
        ErrorMessage = Validate();
    }

    public async Task<IActionResult> OnPostAsync()
    {
        Email = User.FindFirstValue(ClaimTypes.Email) ?? "";
        ErrorMessage = Validate();
        var user = await users.FindByEmailAsync(Email);
        if (ErrorMessage is not null || user is null)
        {
            ErrorMessage ??= "Your account was not found. Sign in again.";
            return Page();
        }

        var now = DateTime.UtcNow;
        var code = OpaqueToken.Generate(OpaqueToken.LoginCodePrefix);
        await loginCodes.InsertAsync(new CliLoginCode
        {
            CodeHash = OpaqueToken.Hash(code),
            CodeChallenge = CodeChallenge!,
            UserId = user.Id,
            CreatedUtc = now,
            ExpiresUtc = now + cliOptions.Value.LoginCodeLifetime,
        });
        await audit.RecordAsync(new SecurityEvent
        {
            EventType = "cli.login",
            Outcome = SecurityEvent.Allowed,
            PrincipalType = PrincipalTypes.Human,
            Subject = user.Subject,
            Issuer = CliEndpoints.HumanIssuer,
            UserId = user.Id,
            ClientId = CliEndpoints.CliClientId,
            HttpStatus = 302,
        });
        return Redirect($"http://127.0.0.1:{Port}/callback?code={Uri.EscapeDataString(code)}&state={Uri.EscapeDataString(State!)}");
    }

    private string? Validate() =>
        Port is < 1024 or > 65535 || !Pkce.IsBase64Url(State, 16, 128) || !Pkce.IsChallenge(CodeChallenge)
            ? "This sign-in link is not valid. Run rabbit auth login again."
            : null;
}
