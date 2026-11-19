# Nordray White Rabbit

An open source **OIDC facade** in front of selected [bunny.net](https://bunny.net) APIs.

White Rabbit makes bunny.net APIs available through modern user login and delegated client access — without exposing your bunny.net credentials to API consumers. It sits between your OIDC clients and bunny.net, enforcing capability-based access control and injecting credentials server-side.

## Why

bunny.net does not provide native OIDC login for its APIs. If you want to give an application access to your pull zones, DNS zones, or Shield configuration without handing over your account API key, you need a layer in front. White Rabbit is that layer.

## How it works

```
OIDC client (app, CLI, ...)
        │
        │  OIDC authorization flow
        ▼
┌───────────────────────────┐
│        Dex (OIDC)         │  Issues tokens, manages clients
└────────────┬──────────────┘
             │  authproxy connector
             ▼
┌───────────────────────────┐
│    Nordray White Rabbit   │
│                           │
│  • Email one-time code    │  User authentication
│  • Consent screen         │  User approves client access
│  • Capability checks      │  Deny by default
│  • Credential injection   │  Your key, never exposed
│  • YARP forwarding        │  Proxies to bunny.net
│  • Audit logging          │
└────────────┬──────────────┘
             │
             ▼
        bunny.net APIs
```

1. A user signs in with their email address — White Rabbit sends a 6-digit one-time code.
2. On first access from a client application, the user sees a consent screen listing the capabilities the client is requesting.
3. Approved grants are stored in the database. Subsequent requests from the same client skip the consent step.
4. White Rabbit looks up every incoming proxy request in a hard-coded operation registry. Anything not in the registry is rejected with `404`. Anything the client hasn't been granted is rejected with `403`.
5. Approved requests have the user's bunny.net API key injected server-side and are forwarded to `https://api.bunny.net` via YARP.

## Supported bunny.net APIs (v1)

| Area | Operations |
|---|---|
| Regions | List regions |
| Statistics | Read account statistics |
| Pull Zones | List, get, create, update, delete |
| DNS Zones | List, get, create, update, delete |
| Shield | List zones, get zone, update zone |

New endpoints require a code review and an explicit entry in `BunnyOperationRegistry`. Bunny's OpenAPI specs are used for reference only — presence in the spec does not make an endpoint automatically available.

## Security model

- **Deny by default.** Every proxied operation is explicitly registered.
- **Capability-based grants.** Clients request capabilities (`pullzone.read`, `dns.write`, …); users approve or deny.
- **Credentials never leave the server.** The user's bunny.net API key is stored in the database and injected into outgoing requests. Clients never see it.
- **Email one-time codes.** No passwords. Codes are SHA-256 hashed, expire in 10 minutes, and are invalidated after first use.
- **Rate limiting.** Per-email and per-IP limits on code requests and verification attempts.
- **Header stripping.** `AccessKey`, `Authorization`, and `X-Remote-*` headers are stripped from all inbound requests before forwarding.

## Technology stack

| Concern | Choice |
|---|---|
| Web host | ASP.NET Core 10 |
| OIDC provider | [Dex](https://dexidp.io) (authproxy connector) |
| Proxy forwarding | YARP (reverse proxy pipeline) |
| Database | libSQL (a local file, or [Bunny Database](https://bunny.net/database/) when deployed) via [Activout.DatabaseClient](https://github.com/twogood/Activout.DatabaseClient) and its `LibSqlGateway` |
| Email | Mailjet (SMTP/Mailpit fallback for local dev) |
| Tests | xUnit, RichardSzalay.MockHttp |

## Running locally

Prerequisites: Docker, .NET 10 SDK.

```bash
# Start Dex and Mailpit
docker compose up dex mailpit

# Set the one required dev secret
export WhiteRabbit_Dex__ClientSecret=change-me-in-production

# Run White Rabbit with hot reload
dotnet watch --project src/Nordray.WhiteRabbit.Web
```

Open [http://localhost:8080](http://localhost:8080) and sign in with your email. Check [http://localhost:8025](http://localhost:8025) (Mailpit) for the login code.

To run everything in Docker:

```bash
cp .env.example .env   # fill in secrets if needed
docker compose up
```

## Configuration

Secrets are **never** stored in `appsettings` files. All sensitive values are supplied as `WhiteRabbit_`-prefixed environment variables (`__` maps to `:` in the config hierarchy):

| Variable | Purpose |
|---|---|
| `WhiteRabbit_DataProtection__EncryptionKey` | **Required.** Base64 of 32 random bytes (`openssl rand -base64 32`). Encrypts the Data Protection key ring stored in the database, which in turn protects every stored bunny.net API key. Keep it with the database backup, separately protected: without it the stored keys cannot be read. White Rabbit refuses to start without it |
| `WhiteRabbit_Database__ConnectionString` | `Data Source=<file>` locally, or `Data Source=https://<database>.lite.bunnydb.net;Auth Token=<token>` for Bunny Database |
| `WhiteRabbit_Dex__ClientSecret` | Shared secret between White Rabbit and Dex |
| `WhiteRabbit_Mailjet__ApiKey` | Mailjet API key (omit to use SMTP fallback) |
| `WhiteRabbit_Mailjet__SecretKey` | Mailjet secret key |
| `WhiteRabbit_Mailjet__FromEmail` | Sender address |

Non-secret settings that every instance must choose:

| Setting | Purpose |
|---|---|
| `Access:AllowedEmails`, `Access:AllowedDomains` | Who may sign in (e.g. `WhiteRabbit_Access__AllowedEmails__0=you@example.com`). **Empty means nobody**, so an instance never collects strangers' bunny.net keys by accident. Removing an address ends its sessions and proxy access |
| `Proxy:AllowedClientIds` | OIDC client IDs whose tokens the Bunny proxy accepts (e.g. `WhiteRabbit_Proxy__AllowedClientIds__0=example-client`). Tokens for any other audience are rejected. Empty means none |

See [`.env.example`](.env.example) for a full template.

### Health

- `GET /health`: the process is running.
- `GET /ready`: the database answers and every migration shipped with this build has been applied. Returns 503 otherwise, without connection details.

### Database

The same libSQL provider serves a local file, an in-memory database in tests and Bunny Database in production. The schema lives in numbered migrations (`src/Nordray.WhiteRabbit.Infrastructure/Database/Schema/NNN_name.sql`), applied once each at start-up and recorded in `SchemaMigrations`. Never edit an applied migration; add a new numbered file. The native libSQL library ships for linux-x64, linux-arm64, macOS arm64 and Windows x64; Intel Macs are not supported for local development.

## Deployment

White Rabbit is designed to run as a two-container application on [bunny.net Magic Containers](https://bunny.net/magic-containers/):

- `white-rabbit` on port `8080`
- `dex` on port `5556`

Both containers communicate over `localhost`. White Rabbit's data, including the encrypted Data Protection key ring, lives in its database (Bunny Database when deployed); Dex keeps its own SQLite file on a persistent volume.

## Project layout

```
src/
  Nordray.WhiteRabbit.Web            ASP.NET Core host, Razor pages, middleware pipeline
  Nordray.WhiteRabbit.Core           Domain types — BunnyOperation, capabilities, models
  Nordray.WhiteRabbit.Infrastructure libSQL DAOs and migrations, Mailjet/SMTP email service
  Nordray.WhiteRabbit.Proxy          BunnyHttpClientFactory, ISRG Root X1 certificate pinning
  Nordray.WhiteRabbit.Bunny          BunnyOperationRegistry (the hard-coded allow-list)
  Nordray.WhiteRabbit.AuthProxy      DexAuthProxyMiddleware, X-Remote-User injection
tests/
  Nordray.WhiteRabbit.Tests.Unit
  Nordray.WhiteRabbit.Tests.Integration
deploy/
  dex/config.yaml                    Dex configuration (authproxy connector)
examples/
  ExampleClient                      Sample OIDC client demonstrating the full login + proxy flow
```

## What v1 deliberately does not include

- OpenFGA or attribute-based policies
- Resource-level scoping (per pull zone, per DNS zone)
- Refresh tokens (Dex authproxy connector does not support them)
- Automatic endpoint discovery from bunny's OpenAPI specs
- Multi-tenant isolation
- Passwords or social login

## License

MIT
