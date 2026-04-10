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
    string ConsentDescription);

public enum BunnyCredentialKind
{
    None,
    AccountApiKey,
    StorageZonePassword,
    StreamApiKey
}
