using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace ExampleClient.Pages;

[Authorize]
public sealed class PullZonesModel(IHttpClientFactory httpClientFactory) : PageModel
{
    public IReadOnlyList<PullZoneDto>? PullZones { get; private set; }
    public ProxyError? Error { get; private set; }
    public string? AccessToken { get; private set; }

    public async Task OnGetAsync()
    {
        AccessToken = await HttpContext.GetTokenAsync("access_token");

        if (string.IsNullOrEmpty(AccessToken))
        {
            Error = new ProxyError(HttpStatusCode.Unauthorized, "No access token available. Try signing out and back in.");
            return;
        }

        var client = httpClientFactory.CreateClient("white-rabbit");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);

        var response = await client.GetAsync("proxy/api.bunny.net/pullzone");

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            Error = new ProxyError(response.StatusCode, body);
            return;
        }

        PullZones = await response.Content.ReadFromJsonAsync<List<PullZoneDto>>()
                 ?? [];
    }

    public sealed record ProxyError(HttpStatusCode StatusCode, string Message);
}

public sealed class PullZoneDto
{
    [JsonPropertyName("Id")]
    public long Id { get; init; }

    [JsonPropertyName("Name")]
    public string Name { get; init; } = "";

    [JsonPropertyName("EnabledHostnames")]
    public string[]? Hostnames { get; init; }
}
