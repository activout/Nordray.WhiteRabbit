# Nordray White Rabbit, requirements specification v1

## document status

This is a handover-oriented requirements specification for version 1 of **Nordray White Rabbit**.

The intended .NET root namespace is:

- `Nordray.WhiteRabbit`

This document is written for a less experienced developer who should be able to start implementation from it.

---

## 1. purpose

Nordray White Rabbit is an open source **OIDC facade** in front of selected bunny.net APIs.

Its purpose is to make bunny.net APIs available through modern user login and delegated client access, even when bunny.net itself does not provide native OIDC login for these APIs.

White Rabbit will:

- require OIDC authentication for all proxied requests
- map each supported bunny.net endpoint to an internal capability
- allow a signed-in user to grant a client access to a selected set of capabilities
- proxy allowed requests to bunny.net from the server side
- keep bunny credentials on the server side only
- deny everything that is not explicitly supported

Version 1 is intentionally simple:

- capability-based access only
- no resource-level scoping
- no time-based constraints
- no OpenFGA
- no edge scripting
- no generic reverse proxy behaviour

---

## 2. naming

Product name:

- **Nordray White Rabbit**

.NET namespace root:

- `Nordray.WhiteRabbit`

Suggested repository layout:

```text
/src
  Nordray.WhiteRabbit.Web
  Nordray.WhiteRabbit.Core
  Nordray.WhiteRabbit.Infrastructure
  Nordray.WhiteRabbit.Database
  Nordray.WhiteRabbit.Proxy
  Nordray.WhiteRabbit.Bunny
  Nordray.WhiteRabbit.AuthProxy
/tests
  Nordray.WhiteRabbit.Tests.Unit
  Nordray.WhiteRabbit.Tests.Integration
/deploy
/docs
```

---

## 3. primary goals

### 3.1 functional goals

The system must:

1. allow a human user to sign in with email-based one-time code authentication
2. expose OIDC to clients through Dex
3. show a consent screen where a signed-in user approves requested capabilities
4. store grants in SQLite
5. accept requests only for supported bunny endpoints
6. check whether the authenticated client has the required capability
7. forward allowed requests to bunny.net
8. inject bunny credentials server side
9. log audit events for security and debugging

### 3.2 non-functional goals

The system should:

- be easy to run locally with Docker Compose
- be easy to deploy to bunny.net Magic Containers as one application with multiple containers
- use SQLite for White Rabbit data
- be understandable without requiring Kubernetes or cloud-native tooling
- be conservative and secure by default

---

## 4. scope of version 1

### included in v1

- ASP.NET Core application
- YARP-based proxy forwarding
- Dex as separate OIDC service
- custom email code login in front of Dex
- capability-based grants
- SQLite persistence
- consent screen
- admin/configuration through files or a minimal admin UI
- audit logging
- Docker Compose for local development
- container images suitable for bunny.net Magic Containers

### not included in v1

- OpenFGA
- resource-level permissions
- attribute-based conditions
- refresh-token-heavy advanced flows
- Bunny Edge Scripting
- dynamic endpoint discovery at runtime
- support for every bunny.net API endpoint on day one
- multi-tenant isolation inside White Rabbit
- passwords
- social login
- SAML
- fine-grained secrets manager integration

---

## 5. external systems

## 5.1 bunny.net

White Rabbit proxies selected bunny.net APIs.

Relevant facts:

- bunny.net publishes OpenAPI specification files for several API families
- the documented API families include Core Platform API, Origin Errors API, Storage API, Stream API, Shield API and Edge Scripting API
- bunny.net documents `AccessKey` header authentication for account-specific actions
- Stream and Storage use the same header name but different credentials
- Magic Containers supports multiple containers in the same application, running in one pod sandbox and communicating over `localhost`
- Magic Containers requires images from a private container registry

These facts are useful for design and deployment.

## 5.2 Dex

Dex is used as the OIDC provider exposed to White Rabbit clients.

Important constraints:

- Dex `authproxy` is suitable for login methods not natively handled by Dex
- Dex expects the authenticating proxy to set a user identity header such as `X-Remote-User`
- the proxy must strip any client-supplied `X-Remote-*` headers before forwarding to Dex
- the Dex authproxy connector does not support refresh tokens

This is acceptable for v1.

---

## 6. high-level architecture

```text
+---------------------------+
| browser / cli / app       |
+-------------+-------------+
              |
              | OIDC
              v
+---------------------------+
| Dex                       |
| separate container        |
+-------------+-------------+
              ^
              | authenticated callback via authproxy
              |
+-------------+-------------+
| Nordray.WhiteRabbit       |
| ASP.NET Core              |
|                           |
| - email code login        |
| - consent UI              |
| - grants                  |
| - capability checks       |
| - YARP forwarding         |
| - audit                   |
| - Bunny credential use    |
+------+------+-------------+
       |      |
       |      +-------------------------> bunny.net APIs
       |
       +-------------------------------> SQLite
```

### design principle

Dex handles identity protocols.

White Rabbit handles product logic:

- one-time code login
- grant storage
- capability checks
- proxy decisions
- bunny credential injection
- audit logging

---

## 7. deployment model

## 7.1 local development

Everything must run locally using Docker Compose.

Required services:

- `white-rabbit`
- `dex`

Optional local helper services:

- `mailpit` or equivalent for local email testing
- a small reverse proxy only if needed for local HTTPS, but not required for v1

Local persistent files:

- `./data/white-rabbit/white-rabbit.db`
- `./data/dex/dex.db` or Dex storage equivalent
- optional local mail catcher state

## 7.2 bunny.net Magic Containers deployment

The application must be deployable as one bunny.net Magic Containers application with multiple containers.

Target container set:

- `white-rabbit`
- `dex`

Containers should communicate via `localhost` on different ports.

Suggested port usage:

- White Rabbit: `8080`
- Dex: `5556`

No port collisions are allowed.

Use a private container registry for images.

Persistent storage requirement:

- White Rabbit SQLite file must be placed on persistent storage if long-lived data is required across restarts and redeployments
- if Dex uses persistent local storage, it must also be placed on persistent storage or otherwise treated as replaceable depending on chosen configuration

---

## 8. authentication design

## 8.1 user authentication method

Version 1 must use:

- email address
- one-time numeric or alphanumeric code
- short expiration time
- no password storage

Example flow:

1. user enters email address
2. White Rabbit generates one-time code
3. White Rabbit sends code by email
4. user enters the code
5. White Rabbit verifies the code
6. White Rabbit forwards the authenticated user to Dex authproxy callback
7. Dex issues OIDC tokens to the client

## 8.2 why this exists

This exists because Dex provides OIDC, but the chosen user login method is implemented in White Rabbit itself.

## 8.3 email code requirements

The system must:

- store only hashed codes if practical
- expire codes after a short duration, for example 10 minutes
- enforce a resend cooldown
- enforce rate limits per email and per IP
- invalidate a code after successful use
- support local development with a fake SMTP target
- support production SMTP configuration through environment variables

## 8.4 dex authproxy requirements

White Rabbit must act as the authenticating proxy in front of Dex callback handling.

Requirements:

- White Rabbit must strip any incoming `X-Remote-*` headers from untrusted client requests
- White Rabbit must set the configured identity header itself only after successful email-code authentication
- White Rabbit must forward the request to Dex callback exactly as needed for the authproxy connector flow
- the user identity should be based on verified email address

---

## 9. client authentication and oidc

Dex is the OIDC provider seen by external clients.

Version 1 assumptions:

- White Rabbit clients are registered OIDC clients in Dex
- White Rabbit itself trusts tokens issued by Dex
- White Rabbit reads the authenticated user identity and client identity from Dex-issued claims

Open point for implementation:

- decide whether all clients are confidential clients in v1, or whether public clients are also allowed

Recommended v1 choice:

- begin with confidential clients only if possible, because it is simpler and safer

---

## 10. authorisation model

## 10.1 model choice

Version 1 uses a simple capability-based authorisation model.

There is no:

- resource-level grant
- per-zone grant
- conditional policy engine
- ownership model

## 10.2 key rule

Every supported proxied bunny operation must map to exactly one of:

- an explicit capability, or
- a default-authenticated classification

### explicit capability

Examples:

- `pullzone.read`
- `pullzone.write`
- `dns.read`
- `dns.write`
- `statistics.read`
- `shield.read`
- `shield.write`

### default-authenticated classification

Some bunny API endpoints may not require an `AccessKey` in bunny itself, but White Rabbit must still require OIDC authentication for them.

These endpoints must:

- still pass through White Rabbit
- still require a valid authenticated session or access token
- not require an explicitly granted capability
- be marked internally as `RequiresAuthenticationOnly = true`

Examples may include read-only or public-ish bunny endpoints, if White Rabbit chooses to expose them.

## 10.3 deny by default

If an endpoint is not in the registry, White Rabbit must reject it.

Recommended response:

- `404 Not Found` for unsupported proxy routes, or
- `403 Forbidden` for supported routes without permission

Be consistent.

---

## 11. operation registry

## 11.1 purpose

White Rabbit must contain a hard-coded operation registry describing every supported proxied bunny operation.

This registry is the source of truth for:

- which routes are supported
- which HTTP methods are allowed
- which bunny destination should be called
- whether bunny credentials are required
- which capability is required, if any
- how the consent screen should describe the operation

## 11.2 suggested model

Suggested C# record:

```csharp
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
```

Suggested enum:

```csharp
public enum BunnyCredentialKind
{
    None,
    AccountApiKey,
    StorageZonePassword,
    StreamApiKey
}
```

## 11.3 registry rules

Rules:

- `RequiredCapability` and `RequiresAuthenticationOnly` must not both be empty or false
- if `CredentialKind` is not `None`, White Rabbit injects the correct credential server side
- operation IDs must be stable
- incoming path templates should be owned by White Rabbit, not copied blindly from bunny
- destination path templates map from White Rabbit route parameters to bunny route parameters

## 11.4 example entries

```text
GET  /proxy/core/pullzone                 -> capability: pullzone.read
POST /proxy/core/pullzone                 -> capability: pullzone.write
GET  /proxy/core/statistics               -> capability: statistics.read
GET  /proxy/core/region                   -> auth only
GET  /proxy/stream/library/{libraryId}    -> capability: stream.read
GET  /proxy/storage/{zoneName}/{**path}   -> capability: storage.read
```

Note: these examples are illustrative. Final mapping should be based on the selected supported bunny endpoints.

---

## 12. can proxying use bunny openapi specifications?

Yes, but only as a supporting input, not as the sole source of runtime security decisions.

### allowed uses of OpenAPI in v1

The bunny.net OpenAPI specifications may be used to:

- generate an initial list of candidate endpoints
- help generate DTOs or HTTP client code for selected APIs
- generate tests that verify known routes exist in the spec
- generate documentation snippets
- help detect when bunny adds, removes or changes endpoints

### not allowed as sole authority in v1

The OpenAPI specifications must not be the only runtime source for permission decisions.

Reason:

- White Rabbit must stay opinionated and explicit
- a generated route should not become proxyable automatically
- the security model must be controlled by White Rabbit's own operation registry

### recommended approach

Use a build-time or developer-time tool that:

1. downloads or reads selected bunny OpenAPI specs
2. produces a reviewable draft list of operations
3. lets a developer assign each operation one of:
   - capability
   - auth only
   - unsupported
4. outputs a strongly typed C# registry file or JSON file committed to source control

This keeps security deterministic.

---

## 13. proxy implementation

## 13.1 technology choice

Version 1 should use **YARP** inside the ASP.NET Core application.

YARP should be used as the forwarding engine, not as the owner of the security model.

## 13.2 responsibility split

White Rabbit code must handle:

- route resolution
- operation lookup
- capability check
- auth-only check
- destination selection
- credential injection
- audit log writing

YARP should handle:

- forwarding the HTTP request
- streaming the response back
- low-level proxying concerns

## 13.3 implementation shape

Suggested flow per request:

1. authenticate request
2. resolve operation from registry
3. reject if unsupported
4. check auth-only or capability requirement
5. construct target URI
6. copy selected headers
7. remove unsafe headers
8. inject bunny `AccessKey` if required
9. forward request with YARP
10. log audit result

## 13.4 header rules

Never forward client-supplied sensitive headers directly unless explicitly intended.

At minimum:

- strip incoming `AccessKey`
- strip incoming `Authorization` before outgoing bunny call unless there is a specific future reason not to
- strip any `X-Remote-*` headers on routes related to Dex authproxy
- define an allowlist for forwarded headers where practical

---

## 14. bunny credential handling

White Rabbit must support at least these credential types:

- account API key
- stream API key
- storage zone password

Requirements:

- credentials must never be returned to the client
- credentials must be read from environment variables or mounted secrets
- credentials must not be hard-coded in source control
- logging must never print credential values
- the operation registry decides which credential kind to use

Suggested environment variable names:

```text
WHITE_RABBIT_BUNNY_ACCOUNT_API_KEY
WHITE_RABBIT_BUNNY_STREAM_API_KEY
WHITE_RABBIT_BUNNY_STORAGE_PASSWORD
```

If more than one stream library or storage zone later needs distinct credentials, this can be redesigned in a future version.

---

## 15. consent and grants

## 15.1 consent screen

When a client requests access, White Rabbit must show:

- client name
- requested capabilities
- human-readable description of each capability
- any auth-only access that is always included
- approve or deny action

## 15.2 grant persistence

A grant represents that:

- a user approved a client
- for a set of capabilities
- at a specific time

A v1 grant may be indefinite until revoked.

## 15.3 auth-only endpoints and consent

Endpoints marked `RequiresAuthenticationOnly = true`:

- do not need explicit capability grant
- should still be shown as part of the behaviour of the application, either on the consent page or in documentation, so the user is not surprised

Recommended wording on consent page:

- "Basic authenticated access"
- "These operations require login but do not require extra delegated capability approval"

---

## 16. data model

White Rabbit uses SQLite.

Suggested tables:

### users

```text
Id
Subject
Email
DisplayName
CreatedUtc
LastLoginUtc
```

### oauth_clients

```text
Id
ClientId
ClientName
IsActive
CreatedUtc
```

### capabilities

```text
Id
Name
DisplayName
Description
CreatedUtc
```

### grants

```text
Id
UserId
ClientId
CreatedUtc
RevokedUtc
```

### grant_capabilities

```text
GrantId
CapabilityId
```

### login_codes

```text
Id
Email
CodeHash
CreatedUtc
ExpiresUtc
ConsumedUtc
RequestIp
```

### audit_events

```text
Id
OccurredUtc
UserId
ClientId
OperationId
RequestMethod
RequestPath
DestinationHost
DestinationPath
Outcome
HttpStatusCode
ErrorCode
```

### settings

Optional key/value table for simple app settings.

---

## 17. api and ui surface

## 17.1 end-user web pages

Minimum pages:

- `/login`
- `/login/verify`
- `/consent`
- `/error`

Optional pages:

- `/grants`
- `/grants/{id}`
- `/admin/clients`
- `/admin/capabilities`

## 17.2 backend endpoints

Examples:

```text
POST /auth/email/request-code
POST /auth/email/verify-code
GET  /consent
POST /consent/approve
POST /consent/deny
ANY  /proxy/{apiFamily}/{**path}
GET  /.well-known/health
GET  /.well-known/ready
```

The final proxy routing structure may differ, but should remain explicit and simple.

---

## 18. configuration

Configuration should come from:

- `appsettings.json`
- `appsettings.Development.json`
- environment variables
- mounted secret files if desired later

Required configuration areas:

- Dex issuer URL
- Dex client settings for White Rabbit
- SMTP settings
- database connection string for SQLite
- bunny credentials
- login code expiry
- rate limiting thresholds
- base URLs for supported bunny APIs

Suggested base URLs:

```text
https://api.bunny.net
https://video.bunnycdn.com
https://storage.bunnycdn.com
```

---

## 19. logging, audit and observability

## 19.1 application logs

Log at least:

- startup configuration summary without secrets
- login code requests
- login code verification results
- consent approvals and denials
- proxy decisions
- upstream bunny status codes
- unexpected exceptions

## 19.2 audit logs

Every proxied request should create an audit event containing:

- user
- client
- operation
- destination
- result

## 19.3 health endpoints

Provide:

- liveness endpoint
- readiness endpoint

Readiness should verify:

- SQLite available
- configuration loaded
- Dex connectivity if appropriate

Do not make readiness depend on live bunny API calls unless deliberately chosen.

---

## 20. security requirements

Mandatory security rules:

1. deny by default
2. never expose bunny credentials to clients
3. rate limit login code requests
4. rate limit code verification attempts
5. expire login codes quickly
6. hash login codes if practical
7. strip dangerous headers
8. validate redirect and callback behaviour carefully
9. log security-relevant events
10. do not auto-proxy newly discovered bunny endpoints

Recommended additional protections:

- CSRF protection on web forms
- secure cookies
- same-site cookie configuration
- strict HTTPS in production
- input validation on all route parameters

---

## 21. testing requirements

## 21.1 unit tests

Must cover:

- operation registry lookup
- capability checks
- auth-only route checks
- login code generation and validation
- consent decision logic
- credential selection logic

## 21.2 integration tests

Must cover:

- request code flow
- verify code flow
- Dex authproxy hand-off
- approval flow
- allowed proxy request
- denied proxy request
- unsupported route request
- audit event creation

## 21.3 contract tests

Recommended:

- test that every operation in the registry maps to an expected bunny path
- optionally compare selected operations against bunny OpenAPI specs to detect drift

---

## 22. implementation guidance for a less experienced developer

### build in this order

1. create solution and projects
2. add SQLite access through Activout.DatabaseClient
3. implement login code flow
4. integrate Dex authproxy
5. implement simple consent UI
6. add grant persistence
7. create operation registry
8. add capability check middleware or service
9. add YARP forwarding
10. add audit logging
11. add Docker Compose
12. add container images for Magic Containers deployment

### do not build first

Do not start with:

- automatic OpenAPI-driven proxy generation
- generic proxy configuration
- OpenFGA
- resource scoping
- complex admin UI

---

## 23. recommended first capabilities

Suggested starter capability list:

```text
pullzone.read
pullzone.write
dns.read
dns.write
statistics.read
stream.read
stream.write
storage.read
storage.write
shield.read
shield.write
```

This list may change, but it is a useful starting point.

---

## 24. recommended first supported bunny routes

A small and safe first slice is recommended.

Suggested first slice:

- read-only region list
- read-only statistics endpoints
- pull zone read operations
- pull zone write operations only after the read path works
- a small number of stream read operations
- avoid storage write and destructive operations until the proxy flow is proven stable

---

## 25. open questions to decide before coding starts

1. which exact SMTP provider will be used in production?
2. should grants be revocable from a user-facing page in v1?
3. should the app support only confidential OIDC clients in v1?
4. which bunny API families are in scope for the first release?
5. should auth-only endpoints be shown on consent UI or just documented?
6. should Dex persistence be durable in production, or can it be rebuilt from config for v1?

---

## 26. suggested definition of done for v1

Version 1 is done when:

- a user can sign in via emailed code
- Dex issues OIDC tokens through the authproxy-based login flow
- a client can request capabilities
- White Rabbit stores grants in SQLite
- at least a small set of bunny endpoints can be proxied successfully
- unsupported routes are denied
- capability-protected routes are enforced
- auth-only routes still require OIDC
- audit events are written
- the app runs locally with Docker Compose
- the app can be deployed as a multi-container bunny.net Magic Containers application

---

## 27. practical recommendation on bunny OpenAPI use

Use the bunny OpenAPI files as a **developer productivity tool**, not as a runtime authority.

Practical recommendation:

- keep a hand-maintained `BunnyOperationRegistry`
- optionally build a small internal generator that reads bunny OpenAPI documents and proposes operation entries
- require code review for every new proxied operation
- never make "present in OpenAPI" equal "automatically allowed"

That keeps the security model simple and safe.

---

## 28. summary

For version 1, Nordray White Rabbit should be:

- a .NET application called `Nordray.WhiteRabbit`
- backed by SQLite
- fronted by Dex for OIDC
- using White Rabbit's own email code login in front of Dex authproxy
- using YARP for forwarding
- using a hard-coded operation registry
- using capability-based grants plus auth-only routes
- deployable locally with Docker Compose
- deployable to bunny.net Magic Containers as a single application with multiple containers

This is deliberately narrow and explicit.
That is a feature, not a limitation.
