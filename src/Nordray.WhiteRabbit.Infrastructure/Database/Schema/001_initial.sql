-- Initial schema. Consolidates the tables and columns that main created with
-- CREATE TABLE IF NOT EXISTS plus ignored ALTER TABLE statements before
-- numbered migrations existed. PascalCase column names map to C# properties.
-- Never edit an applied migration: add a new numbered file instead.

CREATE TABLE Users (
    Id           INTEGER PRIMARY KEY AUTOINCREMENT,
    Subject      TEXT NOT NULL UNIQUE,
    Email        TEXT NOT NULL UNIQUE,
    DisplayName  TEXT,
    CreatedUtc   TEXT NOT NULL,
    LastLoginUtc TEXT NOT NULL,
    BunnyApiKey  TEXT
);

CREATE TABLE LoginCodes (
    Id             INTEGER PRIMARY KEY AUTOINCREMENT,
    Email          TEXT NOT NULL,
    CodeHash       TEXT NOT NULL,
    CodeSalt       TEXT NOT NULL DEFAULT '',
    CreatedUtc     TEXT NOT NULL,
    ExpiresUtc     TEXT NOT NULL,
    ConsumedUtc    TEXT,
    RequestIp      TEXT NOT NULL,
    FailedAttempts INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IX_LoginCodes_Email ON LoginCodes(Email);

CREATE TABLE OAuthClients (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ClientId    TEXT NOT NULL UNIQUE,
    ClientName  TEXT NOT NULL,
    IsActive    INTEGER NOT NULL DEFAULT 1,
    CreatedUtc  TEXT NOT NULL
);

CREATE TABLE Capabilities (
    Id          INTEGER PRIMARY KEY AUTOINCREMENT,
    Name        TEXT NOT NULL UNIQUE,
    DisplayName TEXT NOT NULL,
    Description TEXT NOT NULL,
    CreatedUtc  TEXT NOT NULL
);

CREATE TABLE Grants (
    Id         INTEGER PRIMARY KEY AUTOINCREMENT,
    UserId     INTEGER NOT NULL REFERENCES Users(Id),
    ClientId   INTEGER NOT NULL REFERENCES OAuthClients(Id),
    CreatedUtc TEXT NOT NULL,
    RevokedUtc TEXT
);

CREATE INDEX IX_Grants_UserId_ClientId ON Grants(UserId, ClientId);

CREATE TABLE GrantCapabilities (
    GrantId      INTEGER NOT NULL REFERENCES Grants(Id),
    CapabilityId INTEGER NOT NULL REFERENCES Capabilities(Id),
    PRIMARY KEY (GrantId, CapabilityId)
);

CREATE TABLE AuditEvents (
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
);

-- ASP.NET Core Data Protection key ring. It protects the stored Bunny API keys,
-- so it must survive container replacement. Each row's XML is encrypted with
-- DataProtection:EncryptionKey (AES-256-GCM) before it is written.
CREATE TABLE DataProtectionKeys (
    FriendlyName TEXT NOT NULL PRIMARY KEY,
    Xml          TEXT NOT NULL,
    CreatedUtc   TEXT NOT NULL
);
