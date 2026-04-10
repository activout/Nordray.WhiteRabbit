namespace Nordray.WhiteRabbit.Infrastructure.Database;

public sealed class DatabaseOptions
{
    public string ConnectionString { get; set; } = "Data Source=./data/white-rabbit.db";
}
