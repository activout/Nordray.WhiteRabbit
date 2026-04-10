namespace Nordray.WhiteRabbit.Infrastructure.LoginCodes;

public sealed class RateLimitExceededException(string message) : Exception(message);
