using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleClient.Pages;

public sealed class IndexModel : PageModel
{
    public bool IsAuthenticated { get; private set; }
    public string? Email { get; private set; }

    public void OnGet()
    {
        IsAuthenticated = User.Identity?.IsAuthenticated == true;
        Email = User.FindFirstValue(ClaimTypes.Email)
             ?? User.FindFirstValue("email")
             ?? User.Identity?.Name;
    }
}
