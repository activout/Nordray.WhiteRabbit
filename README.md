# Nordray White Rabbit

Keeps your **bunny.net API key out of CI/CD**. White Rabbit holds the key server side. GitHub Actions and Forgejo
Actions jobs prove who they are with their own OIDC token, and get short-lived virtual credentials that can do only
what you allowed that workflow.

## Why

bunny.net has one all-powerful account API key and no native OIDC or scoped keys. Putting that key in a CI secret
means every workflow, and anyone who can change one, holds full control of the account. White Rabbit is the layer in
between: a deploy job gets `mc.read` + `mc.deploy` for five minutes, and nothing else.

## How it works

```
GitHub / Forgejo Actions job            you, at a terminal
   │ job OIDC token                       │ rabbit auth login (browser + emailed code)
   ▼                                      ▼
┌──────────────────────────────────────────────────┐
│              Nordray White Rabbit                │
│  • token exchange      CI token / login code → session (wrs_…)
│  • workload bindings   repository + ref + workflow → capabilities
│  • virtual credentials wrk_…, 5 minutes          │
│  • operation registry  deny by default (404/403) │
│  • key injection       your bunny.net key, never returned
│  • audit log           every decision            │
└─────────────────────────┬────────────────────────┘
                          ▼
                   https://api.bunny.net
```

1. **Once, as the owner:** `rabbit auth login` signs you in with a 6-digit code sent by email. `rabbit admin key set`
   stores your bunny.net API key, encrypted. `rabbit admin bindings add …` allows one workflow of one repository a set
   of capabilities.
2. **In CI:** `rabbit -- <bunny arguments>` exchanges the job's OIDC token. Only a job that matches a binding
   exactly gets a session.
3. Each BunnyCLI call goes through White Rabbit's proxy with a virtual credential. The operation must be in the
   hard-coded registry (`404` otherwise) and its capability must be in the binding (`403` otherwise). Then the owner's
   key is injected and the request is forwarded to `https://api.bunny.net`.

The same `rabbit -- …` works at your own terminal, so an AI agent can run BunnyCLI without ever seeing the key
(`rabbit --capabilities a,b -- …` limits what it may do).

## Supported bunny.net APIs

| Area | Operations | Capabilities |
|---|---|---|
| Regions | List regions | (sign-in only) |
| Account | Account details (`bunny whoami`, the account ID for `bunny apps deploy`) | `account.read` |
| Statistics | Read account statistics | `statistics.read` |
| Pull Zones | List, get, create, update, delete | `pullzone.read`, `pullzone.write` |
| DNS Zones | List, get, create, update, delete | `dns.read`, `dns.write` |
| Shield | List zones, get zone, update zone | `shield.read`, `shield.write` |
| Magic Containers | List and get apps, app overview, get container, regions, list registries | `mc.read` |
| Magic Containers | Change a container's image, deploy, restart | `mc.deploy` |
| Magic Containers | Set a container's environment variables | `mc.env` |
| Magic Containers | Create and delete apps, e.g. preview deployments | `mc.manage` |
| Bunny Database | Configuration, limits, optimal regions, list and get databases, database status | `db.read` |
| Bunny Database | Create and delete databases | `db.manage` |
| Bunny Database | Create a database access token (the token itself gives direct access to that database) | `db.token` |

**Redaction.** Some responses hold secrets the capability does not cover. White Rabbit replaces those fields with `[redacted by White Rabbit]` before the caller sees them:
- container environment variable values, in the app, app-create, container, container-update and set-environment responses;
- registry password fragments, in the registry list.

Everything else, such as IDs and names, is returned unchanged. A successful response that cannot be parsed for redaction is refused (502), not passed through.

**Setting environment variables keeps redacted values.** Setting a container's environment replaces all of its variables, and tools such as `bunny apps env set` send back every variable they read. White Rabbit gave them the placeholder, so before forwarding, each value equal to `[redacted by White Rabbit]` is replaced with that variable's current value, read with the owner's key. A placeholder for a variable the container does not have is refused (400). If the current values cannot be read, nothing is written (502). So `mc.env` can add, change and remove variables without ever reading one.

**`mc.deploy` changes only the image.** Bunny's container update also accepts environment variables, endpoints, volumes, probes and the entry point. White Rabbit forwards only the image fields and refuses any other field (400), even when it is null or empty.

**Each capability has one description**, in `BunnyOperationRegistry`, covering every operation it allows. `rabbit` and the capability table both show that text.

**Deletes are explicit.** `mc.manage` and `db.manage` can delete any app or database on the account, not just ones they created. Grant them only to bindings that need them, e.g. a workflow that cleans up preview deployments.

**Left out on purpose:** log forwarding (its responses carry tokens), registry changes and single-registry reads, volume and endpoint changes, and database groups and their tokens.

New endpoints require a code review and an explicit entry in `BunnyOperationRegistry`. Bunny's OpenAPI specs are used for reference only — presence in the spec does not make an endpoint automatically available.

## Security model

- **Deny by default.** Every proxied operation is explicitly registered.
- **Capability-based access.** Each workload binding lists the capabilities (`pullzone.read`, `mc.deploy`, …) its workflow may use; each virtual credential can be narrowed further.
- **Credentials never leave the server.** The owner's bunny.net API key is stored encrypted in the database and injected into outgoing requests. CI jobs and the CLI never see it.
- **Email one-time codes.** No passwords. Codes are SHA-256 hashed, expire in 10 minutes, and are invalidated after first use.
- **Rate limiting.** Per-email and per-IP limits on code requests and verification attempts.
- **Header stripping.** Inbound `AccessKey`, `Authorization` and `X-Remote-*` headers are never forwarded to bunny.net.

## Technology stack

| Concern | Choice |
|---|---|
| Web host | ASP.NET Core 10 |
| Token validation | `Microsoft.IdentityModel` (GitHub and Forgejo Actions OIDC tokens) |
| Proxy forwarding | YARP (reverse proxy pipeline) |
| Database | libSQL (a local file, or [Bunny Database](https://bunny.net/database/) when deployed) via [Activout.DatabaseClient](https://github.com/twogood/Activout.DatabaseClient) and its `LibSqlGateway` |
| Email | Mailjet (SMTP/Mailpit fallback for local dev) |
| Tests | xUnit, RichardSzalay.MockHttp |

## Running locally

Prerequisites: Docker, .NET 11 SDK.

```bash
# Start Mailpit (catches the login emails)
docker compose up mailpit

# The two required settings
export WhiteRabbit_DataProtection__EncryptionKey=$(openssl rand -base64 32)
export WhiteRabbit_Access__AllowedEmails__0=you@example.com

# Run White Rabbit with hot reload
dotnet watch --project src/Nordray.WhiteRabbit.Web
```

Then `rabbit --server http://localhost:8080 auth login`, and look in [http://localhost:8025](http://localhost:8025) (Mailpit) for the code.

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
| `WhiteRabbit_Mailjet__ApiKey` | Mailjet API key (omit to use SMTP fallback) |
| `WhiteRabbit_Mailjet__SecretKey` | Mailjet secret key |
| `WhiteRabbit_Mailjet__FromEmail` | Sender address |

Non-secret settings that every instance must choose:

| Setting | Purpose |
|---|---|
| `Access:AllowedEmails`, `Access:AllowedDomains` | Who may sign in (e.g. `WhiteRabbit_Access__AllowedEmails__0=you@example.com`). **Empty means nobody**, so an instance never collects strangers' bunny.net keys by accident. Removing an address ends its sessions and proxy access |

See [`.env.example`](.env.example) for a full template.

### rabbit CLI and CI federation

The Go command-line client is in [`cli/`](cli/README.md) (install, usage, CI examples in [`examples/ci`](examples/ci)). The server side:

The `rabbit` CLI never holds a real bunny.net key. It exchanges a login code or a CI identity token for a White Rabbit
session, then asks for short-lived **virtual credentials** that only White Rabbit's proxy accepts.

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /cli/login?port=&state=&code_challenge=` | browser sign-in (email code) | After an explicit confirmation, redirects to `http://127.0.0.1:{port}/callback` with a one-time code `wrc_…` (2 minutes) bound to the PKCE S256 challenge |
| `POST /api/cli/exchange` `{"code": "…", "code_verifier": "…"}` or `{"subject_token": "…"}` | none (rate limited) | Exchanges a login code with its verifier, or a GitHub Actions or Forgejo Actions token, for a session token `wrs_…`. Humans get 8 hours with every capability, CI workloads 60 minutes with their binding's |
| `POST /api/cli/credentials` `{"capabilities": […]}` | `Authorization: Bearer wrs_…` | Issues a virtual credential `wrk_…` (5 minutes), never broader than the session. Send it as `AccessKey` to `/proxy/api.bunny.net/…` |
| `GET /api/cli/whoami` | session | The authenticated human or workload and its current capabilities |
| `POST /api/cli/revoke` `{"credential_id": "…"?}` | session | Revokes one credential, or the session and all its credentials |
| `GET/POST /api/admin/bindings`, `DELETE /api/admin/bindings/{id}` | human session only | Lists, creates and revokes the caller's own CI workload bindings |
| `GET /api/admin/audit?since=&binding_id=&limit=` | human session only | The caller's own security events, newest first (default: last 24 hours, 50 events, at most 500) |
| `PUT /api/admin/bunny-key` `{"api_key": "…"}`, `DELETE /api/admin/bunny-key` | human session only | Stores (encrypted) or removes the caller's bunny.net API key. Never returned; `whoami` only says `has_bunny_key` |

- **Sessions and virtual credentials** are opaque random tokens; only their SHA-256 hashes are stored. They are checked on every use against the sign-in allow-list and, for CI, the workload binding, so revoking either takes effect immediately.
- **Login codes** are opaque, stored as SHA-256 hashes, valid for 2 minutes and consumed on first use, even when the verifier is wrong. The redirect always goes to `127.0.0.1`, never to a caller-supplied URL.
- **The proxy** accepts only a virtual credential in `AccessKey`. Anything else, including a real bunny.net key, is refused and never forwarded. The owner's own stored key is injected server side.
- **CI tokens** are validated per configured issuer: exact `iss`, audience `Federation:Audience`, RS256 only (checked before any key lookup), expiry and not-before, and a lifetime of at most `Federation:MaxTokenLifetime`. Signing keys come from the issuer's discovery document; only configured issuers are ever fetched.
- **Workload bindings** decide what a CI identity may do. They are created only through the admin API by a human, never from repository content.
  - Every field is matched exactly: issuer, repository, ref (`refs/heads/…` or `refs/tags/…` only) and `workflow_ref`, whose `@ref` must equal the ref.
  - The ref is optional. A binding without one accepts the workflow from any branch or tag, so the repository's own protections decide which refs are trusted: who may push which branches and tags, rulesets, and on GitHub a protected `environment` on the binding. The workflow must still come from the ref being built.
  - The event must be on the binding's allow-list. `pull_request`, `pull_request_target`, `workflow_run` and similar events are never allowed.
  - **GitHub** bindings also require the immutable `repository_id`, and optionally `repository_owner_id`, `environment` and `job_workflow_ref`.
  - **Forgejo** (tested on 15.0.12) does not issue IDs or environments. Its bindings match on names, so renaming or transferring a repository is a known risk. Forgejo's `ref_protected` claim is always `"false"` and is not used. Forgejo jobs must set `enable-openid-connect: true`.
  - Two matching bindings are refused as ambiguous.
Settings: `Cli:*Lifetime`, `Federation:Audience` (distinct per environment, e.g. `whiterabbit:test`), `Federation:MaxTokenLifetime`, and `Federation:Issuers` (each `Name`, `Kind` = `GitHub` or `Forgejo`, and the exact `Url`). An empty audience or issuer list disables CI federation.

### Audit

Security events (`SecurityEvents` table and the structured log) record CLI sign-ins, token exchanges, credential issuance, bunny.net key changes, revocations, binding changes and every proxy decision. Each event records:
- principal type, subject and issuer;
- binding and session;
- repository, workflow, ref and run;
- credential ID;
- operation, method and path (never the query string);
- status, upstream status and correlation ID.

Tokens, keys, codes and request bodies are never recorded. Send `X-Correlation-ID` to correlate a request; it is echoed in the response.

Read your own events with `rabbit admin audit` (`--since 7d`, `--binding ID`, `--limit N`, `--json`). It shows everything recorded with you as the owner, including your CI workloads' exchanges and proxy calls. Denials where no owner is known yet, such as a token from an untrusted issuer or for a repository without a binding, are only in the table and the log.

### Health

- `GET /health`: the process is running.
- `GET /ready`: the database answers and every migration shipped with this build has been applied. Returns 503 otherwise, without connection details.

### Database

The same libSQL provider serves a local file, an in-memory database in tests and Bunny Database in production. The schema lives in numbered migrations (`src/Nordray.WhiteRabbit.Infrastructure/Database/Schema/NNN_name.sql`), applied once each at start-up and recorded in `SchemaMigrations`. Never edit an applied migration; add a new numbered file. The native libSQL library ships for linux-x64, linux-arm64, macOS arm64 and Windows x64; Intel Macs are not supported for local development.

## Deployment

White Rabbit runs as a single container (`white-rabbit` on port `8080`) on [bunny.net Magic Containers](https://bunny.net/magic-containers/). All its data, including the encrypted Data Protection key ring, lives in its database (Bunny Database when deployed), so the container needs no volume.

**Image.** `.github/workflows/image.yml` publishes the server image to `ghcr.io/activout/nordray-whiterabbit`:
- every push to `main` gets `:sha-<commit>` and `:main`;
- every `v*` tag gets `:<tag>` and `:latest`.

The run summary shows the digest. Deploy a pinned digest, not a moving tag. The image is generic: it holds no configuration, hostnames or secrets. Supply those as environment variables (see Configuration), for example from a secrets loader that you add as the entrypoint in your own image layer.

## Project layout

```
src/
  Nordray.WhiteRabbit.Web            ASP.NET Core host, CLI API, sign-in pages, proxy pipeline
  Nordray.WhiteRabbit.Core           Domain types — BunnyOperation, capabilities, models
  Nordray.WhiteRabbit.Infrastructure libSQL DAOs and migrations, Mailjet/SMTP email service
  Nordray.WhiteRabbit.Proxy          BunnyHttpClientFactory, ISRG Root X1 certificate pinning
  Nordray.WhiteRabbit.Bunny          BunnyOperationRegistry (the hard-coded allow-list)
tests/
  Nordray.WhiteRabbit.Tests.Unit
  Nordray.WhiteRabbit.Tests.Integration
cli/                                 rabbit, the Go command-line client
examples/ci/                         GitHub Actions and Forgejo Actions workflows
```

## What v1 deliberately does not include

- OpenFGA or attribute-based policies
- Resource-level scoping (per pull zone, per DNS zone)
- Refresh tokens: sign in again when the session ends
- Third-party OIDC clients: White Rabbit is for CI/CD and the `rabbit` CLI only
- Automatic endpoint discovery from bunny's OpenAPI specs
- Multi-tenant isolation
- Passwords or social login

## License

MIT
