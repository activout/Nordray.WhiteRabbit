-- CLI sessions, CI workload bindings, short-lived virtual Bunny credentials and the security audit trail.

-- Which CI workload may act for which tenant (user), with which capabilities. Created only through the
-- admin API by an interactive human session; repository content can never create or widen one.
CREATE TABLE WorkloadBindings (
    Id                INTEGER PRIMARY KEY AUTOINCREMENT,
    OwnerUserId       INTEGER NOT NULL REFERENCES Users(Id),
    Issuer            TEXT NOT NULL,     -- configured issuer name, e.g. "github" or "codebahn"
    Repository        TEXT NOT NULL,     -- owner/name
    RepositoryId      TEXT,              -- GitHub: required, immutable. Forgejo: not available
    RepositoryOwnerId TEXT,              -- GitHub: optional, immutable
    Ref               TEXT NOT NULL,     -- exact, refs/heads/... or refs/tags/...
    WorkflowRef       TEXT NOT NULL,     -- exact, <repo>/<path>@<ref>
    JobWorkflowRef    TEXT,              -- GitHub reusable workflows: exact job_workflow_ref
    Environment       TEXT,              -- GitHub: exact environment name when set
    EventNames        TEXT NOT NULL,     -- space-separated allow-list; pull_request events are never allowed
    Capabilities      TEXT NOT NULL,     -- space-separated capability names
    Description       TEXT,
    CreatedUtc        TEXT NOT NULL,
    RevokedUtc        TEXT
);

CREATE INDEX IX_WorkloadBindings_Issuer ON WorkloadBindings(Issuer, RevokedUtc);

-- White Rabbit sessions issued by /api/cli/exchange. Only a SHA-256 hash of the bearer token is stored.
CREATE TABLE CliSessions (
    Id            TEXT PRIMARY KEY,
    TokenHash     TEXT NOT NULL UNIQUE,
    PrincipalType TEXT NOT NULL,         -- human, github_workload, forgejo_workload
    UserId        INTEGER NOT NULL REFERENCES Users(Id),  -- the human, or the binding's owner
    Subject       TEXT NOT NULL,         -- human: user subject. Workload: the CI token's sub
    Issuer        TEXT NOT NULL,         -- issuer URL of the exchanged token
    ClientId      TEXT,                  -- human: the OIDC client (rabbit-cli)
    BindingId     INTEGER REFERENCES WorkloadBindings(Id),
    Repository    TEXT,
    RepositoryId  TEXT,
    WorkflowRef   TEXT,
    Ref           TEXT,
    RunId         TEXT,
    CreatedUtc    TEXT NOT NULL,
    ExpiresUtc    TEXT NOT NULL,
    RevokedUtc    TEXT
);

-- Virtual Bunny credentials: opaque, short-lived, accepted only by White Rabbit's proxy.
-- Only a SHA-256 hash is stored; Id is the public fingerprint used in audit records.
CREATE TABLE VirtualCredentials (
    Id           TEXT PRIMARY KEY,
    KeyHash      TEXT NOT NULL UNIQUE,
    SessionId    TEXT NOT NULL REFERENCES CliSessions(Id),
    Capabilities TEXT NOT NULL,          -- space-separated, never broader than the session
    CreatedUtc   TEXT NOT NULL,
    ExpiresUtc   TEXT NOT NULL,
    RevokedUtc   TEXT
);

CREATE INDEX IX_VirtualCredentials_SessionId ON VirtualCredentials(SessionId);

-- Append-only security audit trail. Never holds tokens, keys, codes, query strings or request bodies.
CREATE TABLE SecurityEvents (
    Id             INTEGER PRIMARY KEY AUTOINCREMENT,
    OccurredUtc    TEXT NOT NULL,
    EventType      TEXT NOT NULL,        -- e.g. cli.exchange, cli.credential, cli.revoke, proxy.request, admin.binding.create
    Outcome        TEXT NOT NULL,        -- allowed / denied
    Reason         TEXT,                 -- denial reason code
    PrincipalType  TEXT,
    Subject        TEXT,
    Issuer         TEXT,
    UserId         INTEGER,
    ClientId       TEXT,
    BindingId      INTEGER,
    SessionId      TEXT,
    CredentialId   TEXT,
    Repository     TEXT,
    RepositoryId   TEXT,
    WorkflowRef    TEXT,
    Ref            TEXT,
    RunId          TEXT,
    OperationId    TEXT,
    HttpMethod     TEXT,
    Path           TEXT,                 -- path only, never the query string
    HttpStatus     INTEGER,
    UpstreamStatus INTEGER,
    CorrelationId  TEXT,
    Detail         TEXT                  -- JSON, e.g. a binding before/after an admin change
);

CREATE INDEX IX_SecurityEvents_OccurredUtc ON SecurityEvents(OccurredUtc);

-- Superseded by SecurityEvents; it never held more than proxy outcomes and nothing is deployed yet.
DROP TABLE AuditEvents;
