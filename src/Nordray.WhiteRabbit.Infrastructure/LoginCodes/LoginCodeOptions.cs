namespace Nordray.WhiteRabbit.Infrastructure.LoginCodes;

public sealed class LoginCodeOptions
{
    public int ExpiryMinutes { get; set; } = 10;
    public int ResendCooldownSeconds { get; set; } = 60;
    public int MaxCodesPerEmailPerHour { get; set; } = 5;
}
