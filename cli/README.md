# rabbit

`rabbit` runs bunny.net's official [BunnyCLI](https://github.com/BunnyWay/cli) (`bunny`) through a
[Nordray White Rabbit](../README.md) server, so neither developers nor CI jobs ever hold the real bunny.net API key.

```sh
rabbit env add prod https://whiterabbit.example.com
rabbit auth login            # browser sign-in (OIDC + PKCE), session kept in the OS credential store
rabbit auth whoami
rabbit -- whoami             # everything after -- goes to BunnyCLI, unchanged
rabbit -- api GET /pullzone
rabbit -- --help             # BunnyCLI's help, not rabbit's
```

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/activout/Nordray.WhiteRabbit/main/scripts/install-rabbit.sh | sh -s -- v0.1.0
```

The script downloads the release archive and `SHA256SUMS` from GitHub Releases, and refuses to install if the
checksum is missing or wrong. Pin a version in CI. Windows: download the zip from the release page.

BunnyCLI must be installed separately (`npm i -g @bunny.net/cli`, or its install script); rabbit never downloads it.
On Windows, rabbit runs the native `bunny.exe` that npm installs next to its `bunny.cmd` launcher, never the launcher through `cmd.exe`; set `RABBIT_BUNNY` to `bunny.exe` if it is elsewhere.
Tested with BunnyCLI 0.22.0.

## How it works

1. **Authenticate.**
   - Interactively, `rabbit auth login` signs in through White Rabbit's Dex as the public client `rabbit-cli`, using the authorization code flow with PKCE (S256), the system browser and a loopback redirect on `127.0.0.1`. No client secret is shipped in the binary.
   - In GitHub Actions or Forgejo Actions, rabbit requests the job's own OIDC token instead.
2. **Exchange.** The identity token is exchanged at `/api/cli/exchange` for a White Rabbit session.
   - Interactive sessions are stored only in the OS credential store (macOS Keychain, Windows Credential Manager, Secret Service on Linux). Without one, nothing is saved and the next command asks you to sign in again.
   - There are no refresh tokens: sign in again when the session expires (8 hours).
3. **`rabbit -- …`**
   - rabbit starts a forwarder on `127.0.0.1` and runs `bunny` with `BUNNYNET_API_URL` pointing at it and a one-time local key.
   - The forwarder obtains 5-minute virtual credentials from White Rabbit and renews them before they expire, so long-running commands work. It forwards each call to `<server>/proxy/api.bunny.net/…`.
   - `bunny` never sees a White Rabbit credential or a real key.
4. **The child environment.**
   - Removed: inherited `BUNNYNET_*` and `BUNNY_*` variables, CI token variables (`ACTIONS_ID_TOKEN_REQUEST_*`, `ACTIONS_RUNTIME_*`, `GITHUB_TOKEN`, `FORGEJO_TOKEN`) and `RABBIT_*`.
   - Set: `NO_PROXY`, so the local key never goes through an HTTP proxy, and `BUNNYNET_DASHBOARD_URL`, pointed at a dead address so `bunny login` cannot reach the real dashboard.
   - `--api-key` is refused.
5. **Passed through unchanged:** stdin, stdout, stderr, signals and the exit code.

**The `/database` and `/mc` prefixes.** BunnyCLI 0.22.0 drops them when `BUNNYNET_API_URL` is set. The forwarder restores them for the known Database and Magic Containers paths.

**Fails closed.** These all stop rabbit before `bunny` starts:
- no session, or an expired one;
- a refused credential;
- a missing BunnyCLI;
- a server URL that is not HTTPS (plain HTTP is allowed only for `localhost`).

rabbit never falls back to talking to api.bunny.net directly.

**Commands that talk to other hosts.**
- `storage files` is not supported through rabbit: it needs the zone password, which White Rabbit never hands out.
- `db shell` works when the session has `db.token`. White Rabbit issues the database token, and BunnyCLI then connects to the database host directly with it.

**Redacted values.** Magic Containers commands that show environment variable values (`apps env list/pull`, `apps pull`) see redacted values through rabbit; White Rabbit never returns them. `apps env set` and `apps env remove` still work with `mc.env`: they send every variable back, and White Rabbit puts the current value back wherever it finds the placeholder.

## Choosing the server

| | |
|---|---|
| `rabbit env add NAME URL`, `env use NAME`, `env list`, `env remove NAME` | Named servers in `<config dir>/rabbit/config.json` (`RABBIT_CONFIG` overrides). URLs only, never credentials |
| `--env NAME`, `--server URL` | Per command |
| `RABBIT_ENV`, `RABBIT_SERVER` | For CI or scripts |

With several environments and none selected, rabbit refuses to guess. Interactive commands always print the server they use.

## CI

| | GitHub Actions | Forgejo Actions |
|---|---|---|
| Job setting | `permissions: id-token: write` | `enable-openid-connect: true` on the job (`permissions` has no effect) |
| Detected by | `GITHUB_ACTIONS=true` | `FORGEJO_ACTIONS=true` |
| Binding matches | repository ID, ref, workflow, events (optionally owner ID, environment, reusable workflow) | repository name, ref, workflow, events |

Set `RABBIT_SERVER`. The token audience comes from the server (`/api/cli/config`). Pull-request events can never obtain a credential. A human creates the binding once:

```sh
rabbit admin bindings add --issuer github --repository acme/app --repository-id 123456789 \
  --ref refs/heads/main --workflow .github/workflows/deploy.yml --capability pullzone.read
rabbit admin bindings list
rabbit admin bindings rm 3
```

See [`examples/ci`](../examples/ci) for complete workflows.

AI agents: [`skills/rabbit/SKILL.md`](../skills/rabbit/SKILL.md) describes how to use rabbit and manage bindings. Copy it to `~/.claude/skills/rabbit/`.

## Other variables

`RABBIT_AUTH=ci|interactive` overrides CI detection. `RABBIT_BUNNY` is the BunnyCLI path (default: `bunny` on `PATH`).
`RABBIT_DEBUG=1` logs forwarded method, path and status, never headers or bodies.

## Development

```sh
go vet ./... && go test -race ./...
go run github.com/goreleaser/goreleaser/v2@v2.20.2 release --snapshot --clean --skip=publish
```

Releases are built by `.github/workflows/cli.yml` when a `vX.Y.Z` tag is pushed.
