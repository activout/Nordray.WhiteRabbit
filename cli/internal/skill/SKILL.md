---
name: rabbit
description: Run bunny.net's BunnyCLI through a Nordray White Rabbit server with the `rabbit` CLI instead of holding the bunny.net API key, and manage CI workload bindings (`rabbit admin bindings`). Use when the user works with bunny.net through White Rabbit or rabbit, signs in to a White Rabbit environment, asks which capabilities a command needs, sets up a GitHub Actions or Forgejo Actions job to use rabbit, or adds, lists or removes a binding.
---

# rabbit

`rabbit -- <bunny arguments>` runs the official BunnyCLI (`bunny`) through a White Rabbit server. Neither the agent
nor a CI job ever holds the real bunny.net API key. White Rabbit allows only the operations in its registry, and only
with the capabilities of the credential (`RABBIT_CAPABILITIES`) or CI binding. Details: `cli/README.md` in github.com/activout/Nordray.WhiteRabbit.
This file comes with rabbit: `rabbit skill install` updates it to match the installed version.

## Rules for the agent

- **Use `rabbit -- …`, not `bunny …`**, whenever the user works through White Rabbit. Never ask for, read or pass
  the bunny.net API key, and never use `--api-key` (rabbit refuses it).
- **Sign-in is the user's.** `rabbit auth login` opens a browser for an emailed one-time code. Suggest the exact
  command with the `!` prefix so the user runs it. The session may use every capability, so run BunnyCLI with
  `RABBIT_CAPABILITIES` set to the fewest the task needs.
- **The bunny.net API key is the user's too.** Only the user runs `rabbit admin key set`; it reads the key from a
  hidden prompt or stdin. Never put the key in a command, file or message.
- **Bindings change who can act on the user's Bunny account.** Show the full `rabbit admin bindings add` or `rm`
  command and get the user's confirmation before running it. Admin commands work only in an interactive session.
- **Never print a credential.** `RABBIT_DEBUG=1` logs only method, path and status. It is safe to use.
- **Check the environment first:** `rabbit auth status`. Interactive commands print the server they use. With
  several environments and none selected, rabbit refuses to guess: use `--env NAME`.

## Everyday use

```sh
rabbit env add test https://whiterabbit.example.com   # once per server; URLs only, never credentials
rabbit env use test
! rabbit auth login                                    # the user runs this: browser + emailed code, session for 8 h
! rabbit admin key set                                 # the user runs this once: stores their bunny.net API key
rabbit auth whoami                                     # who, which server, whether a key is stored, until when
RABBIT_CAPABILITIES=mc.read rabbit -- apps list        # everything after -- goes to BunnyCLI unchanged
rabbit auth logout
```

There are no refresh tokens: sign in again when the session expires.

## Capabilities

| Capability | Allows | Typical commands |
|---|---|---|
| (sign-in only) | List regions | `rabbit -- api GET /region` |
| `account.read` | Account ID, owner, billing and address | `bunny whoami`, `bunny apps deploy` (account ID = registry namespace) |
| `statistics.read` | Account traffic and billing statistics | `api GET /statistics` |
| `pullzone.read` / `pullzone.write` | Read / create, change, delete pull zones | `api GET /pullzone` |
| `dns.read` / `dns.write` | Read / create, change, delete DNS zones | `api GET /dnszone` |
| `shield.read` / `shield.write` | Read / change Shield zones | |
| `mc.read` | Read apps, containers, regions, registries. Environment values are **redacted** | `apps list`, `apps show` |
| `mc.deploy` | Change a container's image, deploy, restart | the deploy step of a pipeline |
| `mc.env` | Replace environment variables (current values are never shown) | `apps env set/remove` |
| `mc.manage` | Create and delete apps | preview deployments |
| `db.read` | Read databases, limits, regions, status | `db list`, `db show` |
| `db.manage` | Create and delete databases | |
| `db.token` | Create database tokens | `db tokens create`, `db shell` |

Every capability applies to the whole account: `mc.deploy` can change any app.

Not possible through rabbit:
- `storage files` (it needs the zone password);
- reading environment values (shown as `[redacted by White Rabbit]`);
- log forwarding;
- any operation missing from the registry.

## When something fails

| Symptom | Meaning |
|---|---|
| `✖ Not found.` / 404 | The operation is not in White Rabbit's registry. Run with `RABBIT_DEBUG=1` to see the path, then report it; don't work around it with the real key |
| 403 `capability_not_granted` (`required: X`) | Add `X` to `RABBIT_CAPABILITIES`, or to the CI binding |
| No session / expired | `! rabbit auth login` again |
| 403 `bunny_api_key_not_configured` | The user stores their key: `! rabbit admin key set` |
| CI: 401 `no_matching_binding` | No binding matches the job's repository, ref, workflow or event |
| CI: 401 `event_not_allowed` | A `pull_request` job. These never get a credential, by design |

BunnyCLI 0.22.0 drops the `/mc` and `/database` prefixes under `BUNNYNET_API_URL`. rabbit's forwarder restores them,
so this is not an error, but `bunny api` calls must include the prefix (`api GET /mc/apps`).

## CI: GitHub Actions and Forgejo Actions

A CI job does not request capabilities. It gets exactly those of the binding that matches it.

1. The job needs an OIDC token:
   - GitHub: `permissions: id-token: write`;
   - Forgejo: `enable-openid-connect: true` on the job (`permissions` has no effect).
2. Set `RABBIT_SERVER` to the server URL. The token audience comes from the server.
3. Install BunnyCLI and a pinned rabbit (`scripts/install-rabbit.sh <version>`), then run `rabbit -- …`.

Complete workflows: `examples/ci/github-actions.yml` and `examples/ci/forgejo-actions.yml`. No secret goes into the repository.

## Bindings

A binding lets matching CI jobs act **on behalf of the user who created it**, with that user's stored Bunny key and
only the listed capabilities.

```sh
rabbit admin bindings list

# GitHub: the numeric IDs make the binding survive renames. Get them with
#   gh api repos/OWNER/REPO --jq '.id, .owner.id'
rabbit admin bindings add --issuer github --repository OWNER/REPO \
  --repository-id 123456789 --repository-owner-id 987654 \
  --ref refs/heads/main --workflow .github/workflows/deploy.yml \
  --capability mc.read --capability mc.deploy --description "Deploy to test"

# Forgejo: matched by name (Forgejo tokens carry no repository ID).
rabbit admin bindings add --issuer codebahn --repository OWNER/REPO \
  --ref refs/heads/main --workflow .forgejo/workflows/deploy.yml \
  --capability mc.read --capability mc.deploy --description "Deploy to test"

rabbit admin bindings rm 3
```

- `--issuer` is a trusted issuer name configured on the server (e.g. `github`, `codebahn`).
- `--ref` is optional and exact (`refs/heads/…` or `refs/tags/…`).
  - With it, only that branch or tag matches.
  - Without it, the workflow matches from any branch or tag, e.g. for release tags.
  - **Before leaving it out**, ask the user how the repository protects the refs that can run the workflow: who may
    push branches and tags, rulesets, or on GitHub a protected environment (add `--environment`). Anyone who can push
    any branch can otherwise change the workflow there and use the binding.
- `--workflow` takes the workflow file path. The binding stores `<repository>/<path>@<ref>`, and the job's
  `workflow_ref` must match it exactly.
- `--event` defaults to `push` and `workflow_dispatch`. `pull_request` is always refused.
- GitHub only: `--environment` and `--job-workflow-ref` narrow the binding further.
- **There is no edit.** To change a binding, `rm` the old one and add the new one; two bindings that both match a job
  are refused as ambiguous.

Good bindings:
- one per repository and workflow, with a ref unless the workflow must run from several refs;
- only the capabilities that workflow uses, typically `mc.read` + `mc.deploy` for a container deploy;
- `mc.manage`, `db.manage` and `db.token` only when the workflow really creates or deletes things or issues tokens;
- removed when the workflow is retired.
