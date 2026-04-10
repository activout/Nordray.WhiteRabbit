namespace Nordray.WhiteRabbit.Core.Services;

public interface ILoginCodeService
{
    Task GenerateAndSendAsync(string email, string requestIp, CancellationToken ct = default);
    Task<bool> VerifyAsync(string email, string code, CancellationToken ct = default);
}
