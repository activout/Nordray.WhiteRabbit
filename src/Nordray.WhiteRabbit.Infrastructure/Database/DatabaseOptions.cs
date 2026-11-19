namespace Nordray.WhiteRabbit.Infrastructure.Database;

public sealed class DatabaseOptions
{
    /// <summary>
    /// A libSQL connection string. A local file (<c>Data Source=./data/white-rabbit.db</c>), an in-memory database
    /// (<c>Data Source=:memory:</c>, tests only) or Bunny Database
    /// (<c>Data Source=https://&lt;database&gt;.lite.bunnydb.net;Auth Token=&lt;token&gt;</c>).
    /// </summary>
    public string ConnectionString { get; set; } = "Data Source=./data/white-rabbit.db";
}
