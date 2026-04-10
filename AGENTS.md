# Nordray White Rabbit — Agent & Developer Instructions

## Project overview

**Nordray White Rabbit** is an open source OIDC facade that places selected bunny.net APIs behind modern user login and delegated client access. bunny.net does not provide native OIDC login; White Rabbit adds it.

Root .NET namespace: `Nordray.WhiteRabbit`

White Rabbit:
- requires OIDC authentication for all proxied requests
- maps each supported bunny.net endpoint to an internal capability
- allows a signed-in user to grant a client access to a selected set of capabilities
- proxies allowed requests to bunny.net from the server side
- keeps bunny credentials on the server side only
- denies everything not explicitly supported

---

## Repository layout

```
/src
  Nordray.WhiteRabbit.Web            ASP.NET Core host — routes, Razor pages, middleware pipeline
  Nordray.WhiteRabbit.Core           Domain types — BunnyOperation, capabilities, grants, login codes
  Nordray.WhiteRabbit.Infrastructure Email (Mailjet), SQLite (Activout.DatabaseClient), repositories
  Nordray.WhiteRabbit.Proxy          YARP configuration, credential injection, audit middleware
  Nordray.WhiteRabbit.Bunny          BunnyOperationRegistry, BunnyCredentialKind
  Nordray.WhiteRabbit.AuthProxy      Dex authproxy integration, X-Remote-User header logic
/tests
  Nordray.WhiteRabbit.Tests.Unit
  Nordray.WhiteRabbit.Tests.Integration
/deploy
/docs
```

---

## Technology stack

| Concern | Library / Tool |
|---|---|
| Web host | ASP.NET Core |
| Request forwarding | YARP (`Microsoft.ReverseProxy`) |
| OIDC provider | Dex (separate container, authproxy connector) |
| SQLite access | Activout.DatabaseClient + `Microsoft.Data.Sqlite` |
| Email | Mailjet (`Mailjet.Api`) |
| OIDC token validation | `Microsoft.AspNetCore.Authentication.OpenIdConnect` |
| Unit tests | xUnit |
| HTTP mocking in tests | `RichardSzalay.MockHttp` (preferred for all HTTP client mocking) |
| Other mocking | Moq (use only when mockhttp is insufficient) |

---

## Architecture

Dex handles identity protocols (OIDC token issuance, client registration).

White Rabbit handles product logic:
- one-time email code login (in front of Dex authproxy)
- grant storage and consent UI
- operation registry and capability checks
- YARP-based request forwarding
- bunny credential injection (server side only)
- audit logging

```
browser / CLI / app
        |
        | OIDC
        v
      Dex (container, port 5556)
        ^
        | authenticated callback via authproxy
        |
  Nordray.WhiteRabbit (container, port 8080)
        |
        +-----> bunny.net APIs (https://api.bunny.net)
        |
        +-----> SQLite
```

---

## Bunny integration rules

- **Base URL:** `https://api.bunny.net` only. Do not add `video.bunnycdn.com` or `storage.bunnycdn.com` in v1.
- **API families in v1:** Core Platform (pull zones, DNS, statistics, regions) and Shield.
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
```

### Example registry entries

```
GET  /proxy/core/pullzone              -> capability: pullzone.read
POST /proxy/core/pullzone              -> capability: pullzone.write
GET  /proxy/core/statistics            -> capability: statistics.read
GET  /proxy/core/region                -> RequiresAuthenticationOnly = true
GET  /proxy/core/dns                   -> capability: dns.read
POST /proxy/core/dns                   -> capability: dns.write
GET  /proxy/shield                     -> capability: shield.read
POST /proxy/shield                     -> capability: shield.write
```

---

## Authorisation model

White Rabbit uses capability-based authorisation. There is no resource-level scoping, no per-zone grant, and no policy engine in v1.

**Deny by default.** If a route is not in the registry, return `404 Not Found`. If a route is in the registry but the client lacks the required capability, return `403 Forbidden`.

**RequiresAuthenticationOnly:** Some endpoints require only a valid authenticated session, not an explicit capability grant. These still pass through White Rabbit and still require OIDC. They do not require a capability grant.

Per-request decision flow:
1. Authenticate request (validate Dex-issued JWT)
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
- **Strip** incoming `AccessKey` header
- **Strip** incoming `Authorization` header before the outgoing bunny call
- **Strip** any `X-Remote-*` headers on routes related to Dex authproxy
- Use an allowlist for forwarded headers where practical

On Dex authproxy routes:
- Strip any client-supplied `X-Remote-*` headers
- Set `X-Remote-User` (or the configured header name) only after successful email-code verification

---

## Authentication flow (email one-time code)

1. User enters email address at `/login`
2. White Rabbit generates a one-time code, stores a hash, sends the code via Mailjet
3. User enters the code at `/login/verify`
4. White Rabbit verifies the code (checks hash, expiry, not consumed)
5. White Rabbit invalidates the code and forwards the authenticated user to Dex authproxy callback
6. Dex issues OIDC tokens to the client

Requirements:
- Store only hashed codes
- Expire codes after 10 minutes
- Enforce resend cooldown
- Enforce rate limits per email and per IP
- Invalidate after successful use

---

## Data model (SQLite)

### users
`Id`, `Subject`, `Email`, `DisplayName`, `CreatedUtc`, `LastLoginUtc`

### oauth_clients
`Id`, `ClientId`, `ClientName`, `IsActive`, `CreatedUtc`

### capabilities
`Id`, `Name`, `DisplayName`, `Description`, `CreatedUtc`

### grants
`Id`, `UserId`, `ClientId`, `CreatedUtc`, `RevokedUtc`

### grant_capabilities
`GrantId`, `CapabilityId`

### login_codes
`Id`, `Email`, `CodeHash`, `CreatedUtc`, `ExpiresUtc`, `ConsumedUtc`, `RequestIp`

### audit_events
`Id`, `OccurredUtc`, `UserId`, `ClientId`, `OperationId`, `RequestMethod`, `RequestPath`, `DestinationHost`, `DestinationPath`, `Outcome`, `HttpStatusCode`, `ErrorCode`

### settings
Optional key/value table for simple app settings.

---

## Database access conventions (Activout.DatabaseClient)

- Install **both** `Activout.DatabaseClient` and `Activout.DatabaseClient.Dapper` — the Dapper gateway is a separate package.
- Attributes live in `Activout.DatabaseClient.Attributes`: `[SqlQuery]`, `[SqlUpdate]`, `[Bind]`, `[BindProperties]`.
- `DapperGateway` is in `Activout.DatabaseClient.Dapper`; `DatabaseClientBuilder` is in `Activout.DatabaseClient.Implementation`.
- **`SELECT COUNT(*)` must return `Task<long>`, not `Task<int>`.** SQLite returns 64-bit integers for aggregate functions; using `int` causes a silent runtime mapping failure.
- All column names are PascalCase so Dapper maps them to C# properties without custom conventions.
- `DateTimeOffset` values are stored as ISO 8601 UTC strings via custom Dapper type handlers registered in `DatabaseTypeHandlers`.

---

## UI pages

| Route | Purpose |
|---|---|
| `/login` | Email entry form |
| `/login/verify` | Code entry form |
| `/consent` | Capability approval screen |
| `/grants` | User's active grants (with revocation) |
| `/grants/{id}` | Grant detail |
| `/error` | Error display |
| `/admin/clients` | (optional) Client management |
| `/admin/capabilities` | (optional) Capability management |

## Backend endpoints

```
POST /auth/email/request-code
POST /auth/email/verify-code
GET  /consent
POST /consent/approve
POST /consent/deny
ANY  /proxy/{apiFamily}/{**path}
GET  /.well-known/health
GET  /.well-known/ready
```

---

## Configuration

### Secret handling rules

**Secrets are never stored in `appsettings*.json` files.** All sensitive values must be
supplied as environment variables with the `WhiteRabbit_` prefix. The prefix is stripped
and `__` maps to `:` in the config hierarchy:

```
WhiteRabbit_Mailjet__ApiKey=xxx   →   Mailjet:ApiKey
WhiteRabbit_Dex__ClientSecret=xxx →   Dex:ClientSecret
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
| `WhiteRabbit_Dex__ClientSecret` | `Dex:ClientSecret` | Shared secret between White Rabbit and Dex |
| `WhiteRabbit_Mailjet__ApiKey` | `Mailjet:ApiKey` | Mailjet API key (omit to fall back to SMTP) |
| `WhiteRabbit_Mailjet__SecretKey` | `Mailjet:SecretKey` | Mailjet secret key |
| `WhiteRabbit_Mailjet__FromEmail` | `Mailjet:FromEmail` | Sender address |

### Non-secret appsettings (safe to commit)

```json
{
  "Dex": { "InternalAddress": "http://dex:5556", "IssuerUrl": "", "ClientId": "white-rabbit" },
  "Mailjet": { "FromName": "White Rabbit", "SmtpHost": "", "SmtpPort": 1025 },
  "Database": { "ConnectionString": "Data Source=./data/white-rabbit.db" },
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
- Consent decision logic — approve stores grant, deny does not

### Integration test targets (Nordray.WhiteRabbit.Tests.Integration)
- `POST /auth/email/request-code` — creates login_codes row, sends email
- `POST /auth/email/verify-code` — valid code transitions to Dex callback
- Consent approval flow — grant row created with correct capabilities
- Allowed proxy request — forwarded to bunny.net with credential injected
- Denied proxy request (no capability) — 403 returned
- Unsupported route — 404 returned
- Unauthenticated request — 401 returned
- Audit event creation — audit_events row written for every proxy decision

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
9. Log all security-relevant events in audit_events
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

Implement in this sequence:

1. Create solution and projects
2. Add SQLite access through Activout.DatabaseClient
3. Implement login code flow (generate, hash, store, verify)
4. Integrate Dex authproxy (X-Remote-User callback)
5. Implement consent UI (GET/POST /consent)
6. Add grant persistence (approve → store, /grants revocation page)
7. Create `BunnyOperationRegistry` with Core Platform + Shield entries
8. Add capability check middleware or service
9. Add YARP forwarding with credential injection
10. Add audit logging
11. Add Docker Compose (white-rabbit + dex + mailpit for dev)
12. Add container images for Magic Containers deployment

## Do not build first

- Automatic OpenAPI-driven proxy generation
- Generic proxy configuration outside the registry
- OpenFGA or resource-level scoping
- Complex admin UI
- Public (non-confidential) OIDC clients
- Password login or social login
- Support for `video.bunnycdn.com` or `storage.bunnycdn.com` (v1 scope is `api.bunny.net` only)

---

## Local development (Docker Compose)

Services:
- `white-rabbit` — the ASP.NET Core app on port 8080
- `dex` — OIDC provider on port 5556
- `mailpit` — local SMTP/web UI for email testing

Persistent volumes:
- `./data/white-rabbit/white-rabbit.db` — SQLite database
- `./data/dex/` — Dex storage

---

## Definition of done for v1

- A user can sign in via emailed code
- Dex issues OIDC tokens through the authproxy-based login flow
- A client can request capabilities via consent screen
- White Rabbit stores grants in SQLite
- At least Core Platform + Shield bunny endpoints can be proxied successfully
- Unsupported routes are denied (404)
- Capability-protected routes are enforced (403)
- Auth-only routes still require OIDC (401 if not authenticated)
- Audit events are written for every proxy decision
- The app runs locally with Docker Compose
- The app can be deployed as a multi-container bunny.net Magic Containers application
