namespace Nordray.WhiteRabbit.Infrastructure.Database;

// PascalCase column names so Dapper maps them to C# properties without any custom conventions.
internal static class DatabaseSchema
{
    public static readonly string[] Statements =
    [
        """
        CREATE TABLE IF NOT EXISTS Users (
            Id           INTEGER PRIMARY KEY AUTOINCREMENT,
            Subject      TEXT NOT NULL UNIQUE,
            Email        TEXT NOT NULL UNIQUE,
            DisplayName  TEXT,
            CreatedUtc   TEXT NOT NULL,
            LastLoginUtc TEXT NOT NULL,
            BunnyApiKey  TEXT
        )
        """,
        "CREATE INDEX IF NOT EXISTS IX_Users_Email ON Users(Email)",

        """
        CREATE TABLE IF NOT EXISTS LoginCodes (
            Id          INTEGER PRIMARY KEY AUTOINCREMENT,
            Email       TEXT NOT NULL,
            CodeHash    TEXT NOT NULL,
            CreatedUtc  TEXT NOT NULL,
            ExpiresUtc  TEXT NOT NULL,
            ConsumedUtc TEXT,
            RequestIp   TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS IX_LoginCodes_Email ON LoginCodes(Email)",

        """
        CREATE TABLE IF NOT EXISTS OAuthClients (
            Id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ClientId    TEXT NOT NULL UNIQUE,
            ClientName  TEXT NOT NULL,
            IsActive    INTEGER NOT NULL DEFAULT 1,
            CreatedUtc  TEXT NOT NULL
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS Capabilities (
            Id          INTEGER PRIMARY KEY AUTOINCREMENT,
            Name        TEXT NOT NULL UNIQUE,
            DisplayName TEXT NOT NULL,
            Description TEXT NOT NULL,
            CreatedUtc  TEXT NOT NULL
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS Grants (
            Id         INTEGER PRIMARY KEY AUTOINCREMENT,
            UserId     INTEGER NOT NULL REFERENCES Users(Id),
            ClientId   INTEGER NOT NULL REFERENCES OAuthClients(Id),
            CreatedUtc TEXT NOT NULL,
            RevokedUtc TEXT
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS GrantCapabilities (
            GrantId      INTEGER NOT NULL REFERENCES Grants(Id),
            CapabilityId INTEGER NOT NULL REFERENCES Capabilities(Id),
            PRIMARY KEY (GrantId, CapabilityId)
        )
        """,

        """
        CREATE TABLE IF NOT EXISTS AuditEvents (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            OccurredUtc     TEXT NOT NULL,
            UserId          INTEGER,
            ClientId        TEXT,
            OperationId     TEXT,
            RequestMethod   TEXT,
            RequestPath     TEXT,
            DestinationHost TEXT,
            DestinationPath TEXT,
            Outcome         TEXT,
            HttpStatusCode  INTEGER,
            ErrorCode       TEXT
        )
        """,
    ];

    // Applied after the main schema. Each entry is tried once; errors are silently
    // ignored (SQLite has no IF NOT EXISTS for ALTER TABLE ADD COLUMN).
    public static readonly string[] Migrations =
    [
        "ALTER TABLE Users ADD COLUMN BunnyApiKey TEXT",
    ];
}
