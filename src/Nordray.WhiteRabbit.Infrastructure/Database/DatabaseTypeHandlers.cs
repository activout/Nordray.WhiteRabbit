using System.Data;
using System.Globalization;
using Dapper;

namespace Nordray.WhiteRabbit.Infrastructure.Database;

internal static class DatabaseTypeHandlers
{
    private static bool _registered;
    private static readonly Lock _lock = new();

    public static void Register()
    {
        lock (_lock)
        {
            if (_registered) return;
            SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
            SqlMapper.AddTypeHandler(new NullableDateTimeOffsetHandler());
            _registered = true;
        }
    }

    private sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
    {
        public override void SetValue(IDbDataParameter parameter, DateTimeOffset value)
        {
            parameter.Value = value.UtcDateTime.ToString("O");
            parameter.DbType = DbType.String;
        }

        public override DateTimeOffset Parse(object value) =>
            DateTimeOffset.Parse((string)value, null,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
    }

    private sealed class NullableDateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset?>
    {
        public override void SetValue(IDbDataParameter parameter, DateTimeOffset? value)
        {
            if (value.HasValue)
            {
                parameter.Value = value.Value.UtcDateTime.ToString("O");
                parameter.DbType = DbType.String;
            }
            else
            {
                parameter.Value = DBNull.Value;
            }
        }

        public override DateTimeOffset? Parse(object value)
        {
            if (value is null or DBNull) return null;
            return DateTimeOffset.Parse((string)value, null,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
        }
    }
}
