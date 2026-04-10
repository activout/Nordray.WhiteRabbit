using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Nordray.WhiteRabbit.Web.Pages;

[Authorize]
public sealed class IndexModel : PageModel
{
    public string Email { get; private set; } = "";

    public void OnGet()
    {
        Email = User.FindFirstValue(ClaimTypes.Email) ?? "";
    }
}
