namespace Nordray.WhiteRabbit.Core.Services;

public interface IAuditService
{
    Task RecordAsync(
        string operationId,
        string? email,
        string? clientId,
        string outcome,
        int httpStatusCode,
        CancellationToken ct = default);
}
