# Nordray White Rabbit — Agent & Developer Instructions

## Project overview

**Nordray White Rabbit** is an open source broker that keeps the bunny.net API key out of CI/CD. bunny.net has a single
all-powerful account key and no OIDC or scoped keys; White Rabbit holds the key server side and gives GitHub Actions and
Forgejo Actions jobs short-lived, capability-limited virtual credentials based on their own OIDC tokens.

Root .NET namespace: `Nordray.WhiteRabbit`

White Rabbit:
- exchanges a CI job's OIDC token (or a `rabbit` CLI login code) for a short-lived session
- matches CI identities against owner-created workload bindings (repository, ref, workflow, event → capabilities)
- maps each supported bunny.net endpoint to an internal capability
- proxies allowed requests to bunny.net from the server side with the owner's own key
- keeps bunny credentials on the server side only
- denies everything not explicitly supported

It is not a general OIDC provider: there are no third-party OIDC clients, no consent screen and no Dex.

---

## Repository layout

```
/src
  Nordray.WhiteRabbit.Web            ASP.NET Core host — CLI API, sign-in pages, proxy pipeline
  Nordray.WhiteRabbit.Core           Domain types — BunnyOperation, capabilities, bindings, login codes
  Nordray.WhiteRabbit.Infrastructure Email (Mailjet), libSQL (Activout.DatabaseClient), DAOs, migrations
  Nordray.WhiteRabbit.Proxy          YARP configuration, credential injection, audit middleware
  Nordray.WhiteRabbit.Bunny          BunnyOperationRegistry, BunnyCredentialKind
/tests
  Nordray.WhiteRabbit.Tests.Unit
  Nordray.WhiteRabbit.Tests.Integration
/cli                                 rabbit, the Go command-line client
/examples/ci                         GitHub Actions and Forgejo Actions workflows
```

---

## Technology stack

| Concern | Library / Tool |
|---|---|
| Web host | ASP.NET Core |
| Request forwarding | YARP (`Microsoft.ReverseProxy`) |
| Database access | Activout.DatabaseClient + `LibSqlGateway` (`Activout.DatabaseClient.LibSql`) on `Nelknet.LibSQL.Data`. Never EF Core |
| Email | Mailjet (`Mailjet.Api`) |
| CI token validation | `Microsoft.IdentityModel` (`JsonWebTokenHandler`, OIDC discovery for JWKS) |
| Unit tests | xUnit |
| HTTP mocking in tests | `RichardSzalay.MockHttp` (preferred for all HTTP client mocking) |
| Other mocking | Moq (use only when mockhttp is insufficient) |

---

## Architecture

White Rabbit is a single container. It handles:
- one-time email code login for the owner, and the `rabbit` CLI's loopback login (`/cli/login`, PKCE S256)
- validation of GitHub/Forgejo Actions OIDC tokens and workload binding matching
- opaque sessions (`wrs_…`) and virtual credentials (`wrk_…`), stored as hashes only
- operation registry and capability checks
- YARP-based request forwarding with the owner's bunny.net key injected server side
- audit logging

```
CI job (OIDC token)        rabbit CLI (browser + emailed code)
        |                          |
        +------------+-------------+
                     v
  Nordray.WhiteRabbit (container, port 8080)
        |
        +-----> bunny.net APIs (https://api.bunny.net)
        |
        +-----> libSQL (local file / Bunny Database)
```

---

## Bunny integration rules

- **Base URL:** `https://api.bunny.net` only. Do not add `video.bunnycdn.com` or `storage.bunnycdn.com` in v1.
- **API families:** Core Platform (pull zones, DNS, statistics, regions), Shield, and the reviewed subset of Magic Containers (`/mc/…`) and Bunny Database (`/database/…`). Fields that hold secrets the capability does not cover (e.g. environment variable values) are listed in `RedactJsonFields` and redacted in the response.
- **Every proxied route must be listed in `BunnyOperationRegistry`.** An operation not in the registry is rejected with 404.
- **Never auto-proxy based on OpenAPI alone.** OpenAPI specs may be used as a developer productivity aid (generating candidate lists, DTOs), but the registry is the sole runtime authority.
- Bunny credentials are injected server side. They must never be returned to the client or logged.

### Operation registry types

```csharp
// src/Nordray.WhiteRabbit.Core/BunnyOperation.cs

public sealed record BunnyOperation(
    string OperationId,
    string IncomingMethod,
    string IncomingPathTemplate,
    string DestinationBaseUrl,
    string DestinationPathTemplate,
    BunnyCredentialKind CredentialKind,
    string? RequiredCapability,
    bool RequiresAuthenticationOnly,
    string ConsentTitle,
    string ConsentDescription);

public enum BunnyCredentialKind
{
    None,
    AccountApiKey,
    StorageZonePassword,
    StreamApiKey
}
```

Rules:
- `RequiredCapability` and `RequiresAuthenticationOnly` must not both be empty/false.
- `OperationId` values must be stable (they appear in audit events).
- Incoming path templates are White Rabbit's own — they are not copied blindly from bunny.
- If `CredentialKind` is not `None`, the proxy injects the correct credential before forwarding.

### Starter capability list

```
pullzone.read
pullzone.write
dns.read
dns.write
statistics.read
shield.read
shield.write
mc.read
mc.deploy
mc.env
mc.manage
db.read
db.manage
db.token
```

### Example registry entries

```
GET  /proxy/core/pullzone              -> capability: pullzone.read
POST /proxy/core/pullzone              -> capability: pullzone.write
GET  /proxy/core/statistics            -> capability: statistics.read
GET  /proxy/core/region                -> RequiresAuthenticationOnly = true
GET  /proxy/core/user                  -> account.read
GET  /proxy/core/dns                   -> capability: dns.read
POST /proxy/core/dns                   -> capability: dns.write
GET  /proxy/shield                     -> capability: shield.read
POST /proxy/shield                     -> capability: shield.write
```

---

## Authorisation model

White Rabbit uses capability-based authorisation. There is no resource-level scoping, no per-zone grant, and no policy engine in v1.

**Deny by default.** If a route is not in the registry, return `404 Not Found`. If a route is in the registry but the client lacks the required capability, return `403 Forbidden`.

**RequiresAuthenticationOnly:** Some endpoints require only a valid virtual credential, not a specific capability. They still pass through White Rabbit and still return 401 without a credential.

**Who has which capabilities:** a human session has every capability (it is the owner's own key); a workload session has exactly its binding's; a virtual credential has the subset it was issued for (`RABBIT_CAPABILITIES` in the CLI).

Per-request decision flow:
1. Authenticate request (virtual credential in `AccessKey`; nothing else is accepted)
2. Resolve operation from registry by method + path
3. Return 404 if not found
4. Check auth-only or capability requirement; return 403 if not met
5. Construct target URI
6. Apply header rules (see below)
7. Inject bunny credential
8. Forward via YARP
9. Write audit event

---

## Header rules

On every request forwarded to bunny.net:
- **Strip** incoming `AccessKey` header (then inject the owner's key)
- **Strip** incoming `Authorization` header
- **Strip** any `X-Remote-*` headers
- Use an allowlist for forwarded headers where practical

---

## Authentication flow (email one-time code)

Owner sign-in (cookie, used only to authorise `/cli/login`):
1. User enters email address at `/login`
2. White Rabbit generates a one-time code, stores a hash, sends the code via Mailjet
3. User enters the code at `/login/verify`
4. White Rabbit verifies the code (checks hash, expiry, not consumed) and signs the user in

CLI sign-in (`rabbit auth login`):
1. The CLI listens on `127.0.0.1:<port>` and opens `/cli/login?port=&state=&code_challenge=` (S256)
2. After the sign-in above and an explicit confirmation (POST, antiforgery), White Rabbit stores a hashed one-time
   code `wrc_…` (2 minutes) with the challenge and redirects to `http://127.0.0.1:<port>/callback?code=&state=`
3. The CLI posts `code` + `code_verifier` to `/api/cli/exchange`; the code is consumed first, then the verifier checked
4. The redirect target is always the loopback address, never a caller-supplied URL

Requirements:
- Store only hashed codes
- Expire email codes after 10 minutes
- Enforce resend cooldown
- Enforce rate limits per email and per IP
- Invalidate after successful use

---

## Data model (libSQL; see `Database/Schema/*.sql` for the authoritative schema)

### users
`Id`, `Subject`, `Email`, `DisplayName`, `CreatedUtc`, `LastLoginUtc`

### login_codes
`Id`, `Email`, `CodeHash`, `CreatedUtc`, `ExpiresUtc`, `ConsumedUtc`, `RequestIp`

### DataProtectionKeys
`FriendlyName`, `Xml` (AES-256-GCM encrypted with `DataProtection:EncryptionKey`), `CreatedUtc`

### WorkloadBindings
`Id`, `OwnerUserId`, `Issuer`, `Repository`, `RepositoryId`, `RepositoryOwnerId`, `Ref`, `WorkflowRef`, `JobWorkflowRef`, `Environment`, `EventNames`, `Capabilities`, `Description`, `CreatedUtc`, `RevokedUtc`

### CliLoginCodes
`Id`, `CodeHash`, `CodeChallenge`, `UserId`, `CreatedUtc`, `ExpiresUtc`, `ConsumedUtc`

### CliSessions / VirtualCredentials
Opaque tokens stored as SHA-256 hashes only (`TokenHash`, `KeyHash`), with principal, owner, binding, lifetime and revocation.

### SecurityEvents
Append-only audit trail; never holds tokens, keys, codes, query strings or bodies. Replaces the earlier `AuditEvents` table.

### SchemaMigrations
`Version`, `Name`, `AppliedUtc`

---

## Database access conventions (Activout.DatabaseClient)

- All database access goes through Activout.DatabaseClient DAO interfaces over `LibSqlGateway` (package `Activout.DatabaseClient.LibSql`). Never use EF Core, and never call Dapper directly on a connection: Dapper strips the `@` from parameter names and the libSQL provider rejects them. That is also why `DapperGateway` is not used.
- One provider everywhere: `LibSQLConnection` for a local file, `Data Source=:memory:` in tests (one database per connection) and Bunny Database when deployed. `DatabaseConnectionFactory` creates connections; each request shares one scoped `DbConnection`.
- Attributes live in `Activout.DatabaseClient.Attributes`: `[SqlQuery]`, `[SqlUpdate]`, `[Bind]`, `[BindProperties]`. `DatabaseClientBuilder` is in `Activout.DatabaseClient.Implementation`.
- Transactions: the DAO extends `IWithTransactions` and each method that takes part has an `IDbTransaction?` parameter; pass the transaction to every statement in it (no DAO needs one today; `ICliLoginCodeDao.ConsumeAsync` shows a single atomic statement instead).
- Use `INSERT ... RETURNING Id` with `[SqlQuery]` to get a new row's ID.
- **`SELECT COUNT(*)` must return `Task<long>`, not `Task<int>`.** SQLite returns 64-bit integers for aggregate functions.
- All column names are PascalCase so Dapper maps them to C# properties without custom conventions.
- **Timestamps are UTC `DateTime`**, stored as `yyyy-MM-dd HH:mm:ss.fff` text, so text comparison follows time order. Do not use `DateTimeOffset`: the gateway stores it with its original offset (breaking comparisons) and cannot read it back. `SqliteTypeHandlers.Register()` runs once in `AddInfrastructure`.
- Schema changes are new numbered files in `Database/Schema/` (embedded resources), applied by `DatabaseMigrator` at start-up. Never edit an applied migration; a failed one is fixed forward.

---

## UI pages

| Route | Purpose |
|---|---|
| `/login` | Email entry form |
| `/login/verify` | Code entry form |
| `/cli/login` | Confirm a `rabbit auth login`, then redirect to the CLI's loopback listener |
| `/` | Signed-in landing page pointing at the CLI |

Everything else is done with the `rabbit` CLI. Do not add a web admin UI.

## Backend endpoints

```
ANY  /proxy/api.bunny.net/{**path}  virtual credential (AccessKey: wrk_…) only
GET  /api/cli/config            federation audience and capabilities (no secrets)
POST /api/cli/exchange          login code + verifier, or GitHub/Forgejo identity token -> session (wrs_…)
POST /api/cli/credentials       session -> virtual Bunny credential (wrk_…), proxy only
GET  /api/cli/whoami            session -> principal, current capabilities, has_bunny_key
POST /api/cli/revoke            revoke a credential, or the session and its credentials
GET|POST /api/admin/bindings    human session only: list/create own workload bindings
DELETE /api/admin/bindings/{id} human session only: revoke own binding
PUT|DELETE /api/admin/bunny-key human session only: store/remove own bunny.net API key (never returned)
GET  /health   process liveness
GET  /ready    database reachable and all migrations applied (503 otherwise)
```

---

## Configuration

### Secret handling rules

**Secrets are never stored in `appsettings*.json` files.** All sensitive values must be
supplied as environment variables with the `WhiteRabbit_` prefix. The prefix is stripped
and `__` maps to `:` in the config hierarchy:

```
WhiteRabbit_Mailjet__ApiKey=xxx   →   Mailjet:ApiKey
WhiteRabbit_Database__ConnectionString=xxx → Database:ConnectionString
```

`Program.cs` calls `builder.Configuration.AddEnvironmentVariables(prefix: "WhiteRabbit_")`
which loads these after `appsettings.json`, so they always win. Standard ASP.NET Core
variables (`ASPNETCORE_ENVIRONMENT`, `ASPNETCORE_URLS`) keep their normal unprefixed names.

For local development copy `.env.example` → `.env` (git-ignored) and fill in values.
Docker Compose reads `.env` automatically. When running with `dotnet watch` outside Docker,
export the variables in your shell or use a tool like `dotenv`.

### Secret environment variables

| Variable | Config key | Purpose |
|---|---|---|
| `WhiteRabbit_DataProtection__EncryptionKey` | `DataProtection:EncryptionKey` | Required. Base64 of 32 random bytes; encrypts the Data Protection key ring stored in the database |
| `WhiteRabbit_Database__ConnectionString` | `Database:ConnectionString` | Secret when it carries a Bunny Database auth token |
| `WhiteRabbit_Mailjet__ApiKey` | `Mailjet:ApiKey` | Mailjet API key (omit to fall back to SMTP) |
| `WhiteRabbit_Mailjet__SecretKey` | `Mailjet:SecretKey` | Mailjet secret key |
| `WhiteRabbit_Mailjet__FromEmail` | `Mailjet:FromEmail` | Sender address |

### Non-secret appsettings (safe to commit)

```json
{
  "Mailjet": { "FromName": "White Rabbit", "SmtpHost": "", "SmtpPort": 1025 },
  "Database": { "ConnectionString": "Data Source=./data/white-rabbit.db" },
  "Access": { "AllowedEmails": [], "AllowedDomains": [] },
  "Cli": { "LoginCodeLifetime": "00:02:00", "HumanSessionLifetime": "08:00:00", "WorkloadSessionLifetime": "01:00:00", "CredentialLifetime": "00:05:00" },
  "Federation": { "Audience": "", "MaxTokenLifetime": "02:00:00", "Issuers": [] },
  "LoginCode": { "ExpiryMinutes": 10, "ResendCooldownSeconds": 60 },
  "RateLimit": { "RequestsPerEmailPerHour": 5, "RequestsPerIpPerHour": 20 }
}
```

---

## Testing conventions

- **Framework:** xUnit for all test projects.
- **HTTP mocking:** Use `RichardSzalay.MockHttp` (`MockHttpMessageHandler`) for any HTTP client interactions in tests. This is the preferred approach for faking bunny.net or Mailjet HTTP calls.
- **Other mocking:** Use Moq only when mockhttp is insufficient (e.g., non-HTTP dependencies like database repositories or clock abstractions).
- Do not use `[Fact]` + `Assert.True(false)` placeholder tests — write real assertions.

### Unit test targets (Nordray.WhiteRabbit.Tests.Unit)
- `BunnyOperationRegistry` — lookup by method + path, missing route returns null
- Capability check logic — has capability, missing capability, auth-only passthrough
- Login code generation and validation — expiry, already consumed, hash mismatch
- Credential selection logic — correct credential type per `BunnyCredentialKind`
- Binding rules — exact matching, forbidden events, GitHub-only claims

### Integration test targets (Nordray.WhiteRabbit.Tests.Integration)
- `POST /auth/email/request-code` — creates login_codes row, sends email
- `/login` + `/login/verify` — codes sent only to allowed addresses
- `/cli/login` → loopback redirect → `/api/cli/exchange` with the verifier; reused, expired or wrong-verifier codes denied
- CI token exchange — matching binding gets a session; forged or overbroad claims denied and audited
- Allowed proxy request — forwarded to bunny.net with credential injected
- Denied proxy request (no capability) — 403 returned
- Unsupported route — 404 returned
- Request without a virtual credential — 401 returned
- Audit event creation — SecurityEvents row written for every proxy decision, exchange, credential and admin change

---

## Security rules

These are mandatory and must not be weakened:

1. Deny by default — reject any route not in the registry
2. Never expose bunny credentials to clients (never log, never return in response)
3. Rate limit login code requests (per email and per IP)
4. Rate limit code verification attempts
5. Expire login codes after 10 minutes
6. Store only hashed login codes
7. Strip dangerous headers (`AccessKey`, `Authorization`, `X-Remote-*`)
8. Validate redirect and callback URIs carefully
9. Log all security-relevant events in SecurityEvents
10. Never auto-proxy a newly discovered bunny endpoint

Additional protections:
- CSRF protection on all web forms
- Secure, HttpOnly, SameSite=Strict cookies
- Strict HTTPS in production
- Input validation on all route parameters

---

## Bunny credential injection

Credentials are read from environment variables at startup and held in memory. They must:
- never be written to logs
- never be returned in any HTTP response body or header
- be selected based on `BunnyOperation.CredentialKind`

| CredentialKind | Env var | Bunny header |
|---|---|---|
| `AccountApiKey` | `WHITE_RABBIT_BUNNY_ACCOUNT_API_KEY` | `AccessKey` |
| `StorageZonePassword` | `WHITE_RABBIT_BUNNY_STORAGE_PASSWORD` | `AccessKey` |
| `StreamApiKey` | `WHITE_RABBIT_BUNNY_STREAM_API_KEY` | `AccessKey` |
| `None` | — | — |

---

## Build order

v1 is built. New work follows the rules above; new bunny endpoints need a reviewed registry entry and tests.


## Do not build first

- Automatic OpenAPI-driven proxy generation
- Generic proxy configuration outside the registry
- OpenFGA or resource-level scoping
- Complex admin UI
- Third-party OIDC clients, a consent screen, or an OIDC provider (Dex was removed on purpose)
- A web admin UI (the `rabbit` CLI is the admin interface)
- Password login or social login
- Support for `video.bunnycdn.com` or `storage.bunnycdn.com` (v1 scope is `api.bunny.net` only)

---

## Local development (Docker Compose)

Services:
- `white-rabbit` — the ASP.NET Core app on port 8080
- `mailpit` — local SMTP/web UI for email testing

Persistent volumes:
- `./data/white-rabbit/white-rabbit.db` — local libSQL database file

---

## Definition of done for v1

- A user can sign in via emailed code, and the `rabbit` CLI through `/cli/login`
- The owner can store their bunny.net key and manage workload bindings from the CLI
- GitHub Actions and Forgejo Actions jobs matching a binding get virtual credentials
- At least Core Platform + Shield bunny endpoints can be proxied successfully
- Unsupported routes are denied (404)
- Capability-protected routes are enforced (403)
- Requests without a virtual credential are refused (401)
- Audit events are written for every proxy decision
- The app runs locally with Docker Compose
- The app can be deployed as a single bunny.net Magic Containers container
