-- The rabbit CLI signs in through White Rabbit itself instead of Dex: /cli/login hands the CLI's loopback
-- listener a one-time code, bound to the CLI's PKCE challenge, that /api/cli/exchange redeems for a session.
-- Only the code's SHA-256 hash is stored.
CREATE TABLE CliLoginCodes (
    Id            INTEGER PRIMARY KEY AUTOINCREMENT,
    CodeHash      TEXT NOT NULL UNIQUE,
    CodeChallenge TEXT NOT NULL,          -- base64url SHA-256 of the CLI's code_verifier (S256)
    UserId        INTEGER NOT NULL REFERENCES Users(Id),
    CreatedUtc    TEXT NOT NULL,
    ExpiresUtc    TEXT NOT NULL,
    ConsumedUtc   TEXT
);

-- OIDC clients, consent and grants went with Dex. A human session may use every capability; a binding or a
-- virtual credential narrows it.
DROP TABLE GrantCapabilities;
DROP TABLE Grants;
DROP TABLE Capabilities;
DROP TABLE OAuthClients;
