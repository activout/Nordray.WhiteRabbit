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

## Supported bunny.net APIs

| Area | Operations | Capabilities |
|---|---|---|
| Regions | List regions | (sign-in only) |
| Statistics | Read account statistics | `statistics.read` |
| Pull Zones | List, get, create, update, delete | `pullzone.read`, `pullzone.write` |
| DNS Zones | List, get, create, update, delete | `dns.read`, `dns.write` |
| Shield | List zones, get zone, update zone | `shield.read`, `shield.write` |
| Magic Containers | List and get apps, app overview, get container, regions, list registries | `mc.read` |
| Magic Containers | Change a container's image, deploy, restart | `mc.deploy` |
| Magic Containers | Set a container's environment variables | `mc.env` |
| Magic Containers | Create and delete apps, e.g. preview deployments | `mc.manage` |
| Bunny Database | Configuration, limits, optimal regions, list and get databases | `db.read` |
| Bunny Database | Create and delete databases | `db.manage` |
| Bunny Database | Create a database access token (the token itself gives direct access to that database) | `db.token` |

**Redaction.** Some responses hold secrets the capability does not cover. White Rabbit replaces those fields with `[redacted by White Rabbit]` before the caller sees them:
- container environment variable values, in the app, app-create, container, container-update and set-environment responses;
- registry password fragments, in the registry list.

Everything else, such as IDs and names, is returned unchanged. A successful response that cannot be parsed for redaction is refused (502), not passed through.

**Setting environment variables keeps redacted values.** Setting a container's environment replaces all of its variables, and tools such as `bunny apps env set` send back every variable they read. White Rabbit gave them the placeholder, so before forwarding, each value equal to `[redacted by White Rabbit]` is replaced with that variable's current value, read with the owner's key. A placeholder for a variable the container does not have is refused (400). If the current values cannot be read, nothing is written (502). So `mc.env` can add, change and remove variables without ever reading one.

**`mc.deploy` changes only the image.** Bunny's container update also accepts environment variables, endpoints, volumes, probes and the entry point. White Rabbit forwards only the image fields and refuses any other field (400), even when it is null or empty.

**Each capability has one description**, in `BunnyOperationRegistry`, covering every operation it allows. The consent page, `rabbit` and the capability table all show that text.

**Deletes are explicit.** `mc.manage` and `db.manage` can delete any app or database on the account, not just ones they created. Grant them only to bindings that need them, e.g. a workflow that cleans up preview deployments.

**Left out on purpose:** log forwarding (its responses carry tokens), registry changes and single-registry reads, volume and endpoint changes, and database groups and their tokens.

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

### rabbit CLI and CI federation

The Go command-line client is in [`cli/`](cli/README.md) (install, usage, CI examples in [`examples/ci`](examples/ci)). The server side:

The `rabbit` CLI never holds a real bunny.net key. It exchanges an identity token for a White Rabbit session, then
asks for short-lived **virtual credentials** that only White Rabbit's proxy accepts.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /api/cli/exchange` `{"subject_token": "…"}` | none (rate limited) | Exchanges a Dex ID token (client `rabbit-cli`, at most 10 minutes old), a GitHub Actions token or a Forgejo Actions token for a session token `wrs_…`. Humans get 8 hours, CI workloads 60 minutes |
| `POST /api/cli/credentials` `{"capabilities": […]}` | `Authorization: Bearer wrs_…` | Issues a virtual credential `wrk_…` (5 minutes), never broader than the session. Send it as `AccessKey` to `/proxy/api.bunny.net/…` |
| `GET /api/cli/whoami` | session | The authenticated human or workload and its current capabilities |
| `POST /api/cli/revoke` `{"credential_id": "…"?}` | session | Revokes one credential, or the session and all its credentials |
| `GET/POST /api/admin/bindings`, `DELETE /api/admin/bindings/{id}` | human session only | Lists, creates and revokes the caller's own CI workload bindings |

- **Sessions and virtual credentials** are opaque random tokens; only their SHA-256 hashes are stored. They are checked on every use against the sign-in allow-list, the human's current grants for `rabbit-cli`, or the workload binding, so revoking any of those takes effect immediately.
- **The proxy** accepts a virtual credential in `AccessKey`, or a Dex token issued to a client in `Proxy:AllowedClientIds`. Anything else in `AccessKey`, including a real bunny.net key, is refused and never forwarded. The owner's own stored key is injected server side.
- **CI tokens** are validated per configured issuer: exact `iss`, audience `Federation:Audience`, RS256 only (checked before any key lookup), expiry and not-before, and a lifetime of at most `Federation:MaxTokenLifetime`. Signing keys come from the issuer's discovery document; only configured issuers are ever fetched.
- **Workload bindings** decide what a CI identity may do. They are created only through the admin API by a human, never from repository content.
  - Every field is matched exactly: issuer, repository, ref (`refs/heads/…` or `refs/tags/…` only) and `workflow_ref`, whose `@ref` must equal the ref.
  - The event must be on the binding's allow-list. `pull_request`, `pull_request_target`, `workflow_run` and similar events are never allowed.
  - **GitHub** bindings also require the immutable `repository_id`, and optionally `repository_owner_id`, `environment` and `job_workflow_ref`.
  - **Forgejo** (tested on 15.0.12) does not issue IDs or environments. Its bindings match on names, so renaming or transferring a repository is a known risk. Forgejo's `ref_protected` claim is always `"false"` and is not used. Forgejo jobs must set `enable-openid-connect: true`.
  - Two matching bindings are refused as ambiguous.
- **Dex**: `rabbit-cli` is a public client (no secret in the binary). White Rabbit rejects its authorization requests unless they use `response_type=code` with PKCE `S256`, because Dex itself accepts public-client logins without PKCE.

Settings: `Cli:DexClientId`, `Cli:*Lifetime`, `Cli:MaxDexTokenAge`, `Federation:Audience` (distinct per environment, e.g. `whiterabbit:test`), `Federation:MaxTokenLifetime`, and `Federation:Issuers` (each `Name`, `Kind` = `GitHub` or `Forgejo`, and the exact `Url`). An empty audience or issuer list disables CI federation.

### Audit

Security events (`SecurityEvents` table and the structured log) record token exchanges, credential issuance, revocations, binding changes and every proxy decision. Each event records:
- principal type, subject and issuer;
- binding and session;
- repository, workflow, ref and run;
- credential ID;
- operation, method and path (never the query string);
- status, upstream status and correlation ID.

Tokens, keys, codes and request bodies are never recorded. Send `X-Correlation-ID` to correlate a request; it is echoed in the response.

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

**Image.** `.github/workflows/image.yml` publishes the server image to `ghcr.io/activout/nordray-whiterabbit`:
- every push to `main` gets `:sha-<commit>` and `:main`;
- every `v*` tag gets `:<tag>` and `:latest`.

The run summary shows the digest. Deploy a pinned digest, not a moving tag. The image is generic: it holds no configuration, hostnames or secrets. Supply those as environment variables (see Configuration), for example from a secrets loader that you add as the entrypoint in your own image layer.

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
