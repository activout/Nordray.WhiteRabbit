using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleClient.Pages;

public sealed class IndexModel : PageModel
{
    public bool IsAuthenticated { get; private set; }
    public string? Email { get; private set; }

    public bool AccessDenied { get; private set; }
    public bool Error { get; private set; }

    public void OnGet(string? denied, string? error)
    {
        IsAuthenticated = User.Identity?.IsAuthenticated == true;
        Email = User.FindFirstValue(ClaimTypes.Email)
             ?? User.FindFirstValue("email")
             ?? User.Identity?.Name;
        AccessDenied = denied == "1";
        Error = error == "1";
    }
}
