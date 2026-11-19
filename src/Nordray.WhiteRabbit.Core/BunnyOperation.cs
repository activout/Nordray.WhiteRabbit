namespace Nordray.WhiteRabbit.Core;

public sealed record BunnyOperation(
    string OperationId,
    string IncomingMethod,
    string IncomingPathTemplate,
    string DestinationBaseUrl,
    string DestinationPathTemplate,
    BunnyCredentialKind CredentialKind,
    string? RequiredCapability,
    bool RequiresAuthenticationOnly,
    string ConsentTitle,
    string ConsentDescription,
    IReadOnlyList<string>? RedactJsonFields = null,
    string? RestoreRedactedEnvironmentFrom = null,
    IReadOnlyList<string>? AllowedBodyFields = null)
{
    /// <summary>
    /// JSON fields of a successful response that White Rabbit replaces before the caller sees them, because they hold
    /// secrets the capability does not cover (e.g. container environment variable values). Paths use <c>.</c> between
    /// properties and <c>[]</c> for "every element", e.g. <c>containerTemplates[].environmentVariables[].value</c>.
    /// </summary>
    public IReadOnlyList<string> RedactJsonFields { get; init; } = RedactJsonFields ?? [];

    /// <summary>
    /// For an operation that replaces a container's whole environment (a JSON object of name to value): the upstream
    /// path, with the same route values, of the container whose current <c>environmentVariables</c> fill in values the
    /// caller sends back as the redaction placeholder. Tools such as <c>bunny apps env set</c> read every variable and
    /// write them all back, so without this a redacted read would overwrite every other secret with the placeholder.
    /// </summary>
    public string? RestoreRedactedEnvironmentFrom { get; init; } = RestoreRedactedEnvironmentFrom;

    /// <summary>
    /// When set, the request body must be a JSON object with only these top-level properties; anything else is refused
    /// before forwarding. Used where Bunny's endpoint accepts more than the capability covers, e.g. a container PATCH
    /// that could also replace environment variables, endpoints or volumes.
    /// </summary>
    public IReadOnlyList<string>? AllowedBodyFields { get; init; } = AllowedBodyFields;
}

public enum BunnyCredentialKind
{
    None,
    AccountApiKey,
    StorageZonePassword,
    StreamApiKey
}

/// <summary>
/// What a capability allows, as shown on the consent page, by the CLI and in the capability table. One description
/// covers every operation of the capability, so approving it never grants more than the text says.
/// </summary>
public sealed record CapabilityDescription(string Name, string Title, string Description);
