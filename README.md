<div align="center">

# 🔐 mykeep · Vault

### Your secrets, sealed on the drive — so an agent can act as you without ever seeing your keys.

![status](https://img.shields.io/badge/status-v1%20implemented-2ea043)
![pure Go · no CGo](https://img.shields.io/badge/pure%20Go-no%20CGo-00ADD8)
![at rest](https://img.shields.io/badge/at%20rest-AES--256--GCM-2ea043)

[mykeep.ai](https://mykeep.ai) · **Secured · Private · Portable**

</div>

---

Vault is the **"acts as you"** component of [mykeep](https://mykeep.ai). It holds your API keys
and secrets, encrypted on the drive, so your agent can take authenticated actions on your
behalf — call services, deploy, send mail — without your credentials ever touching the cloud or
the model provider.

## The core insight: a broker, not a key dispenser

If an agent can *read* a raw key, that key lands in the transcript — which goes to the model
provider — which defeats the entire point. So Vault never hands the agent a secret. The agent
works **by reference:**

```
POST /v1/secrets/{credential}/request
  { "method": "POST", "url": "https://api.stripe.com/v1/charges", "body": { ... } }

→ Vault attaches the auth header server-side, forwards the request, and returns the
  response. The agent gets the result — never the credential.
```

The secret stays sealed on the drive. Vault is, in effect, an **authenticated-egress proxy.**

## Bounded and observable — not "trust the agent"

At-rest encryption isn't runtime safety: once unlocked, an agent (or a prompt-injected one) can
act with your authority. Vault's honest promise isn't "your keys are safe" — it's that **the
blast radius is bounded and observable.** That falls out of the proxy model:

- **Per-credential host allowlist.** The `stripe` credential only ever attaches to
  `api.stripe.com`. A hijacked agent can't aim the proxy at `evil.com` to exfiltrate the key.
- **Approval tiers.** Read-only calls auto-allow; writes and destructive calls require explicit
  confirmation; some credentials are deny-by-default.
- **Encrypted audit log.** Every action taken as you — credential, destination, method, result,
  time — recorded on the drive and reviewable.
- **OAuth brokering** *(later)*. Hold refresh tokens sealed and run the refresh dance locally, so
  "act as you" extends to services like mail and calendar.

## How an agent uses it

The same shape as the rest of mykeep: a **loopback REST API + a pasted guide** — the zero-install
floor that works with any agent that can make an HTTP call. No client config, no plugin. Vault is
REST-native because it *is* an HTTP proxy.

## Quick start

```sh
make build    # -> bin/vault   (pure Go, CGO_ENABLED=0)

./bin/vault         # GUI: set a password, add/manage credentials, approve writes, read the audit
./bin/vault serve   # headless: unlock via MYKEEP_VAULT_PASSPHRASE / stdin, serve the API
```

- **GUI (default).** Authenticates by the unlock password → a loopback session cookie, so a
  co-resident agent (no password) can't reach the control plane. It shows the **use** token to
  paste into your agent.
- **`serve`.** Prints both tokens. `--lan` exposes *only* the use plane on the network; `--idle`
  sets the auto-lock minutes.

| Make target | What it does |
|---|---|
| `make test` | 46 tests — crypto, allowlist/SSRF, auth, reflect-guard, audit chain, plane separation, approvals |
| `make guard` | prove zero CGo in the dependency graph |
| `make cross` | all six win/mac/linux × amd64/arm64 targets |
| `go test -race ./...` | race detector (needs `CGO_ENABLED=1`) |

## Layout

```
internal/secret   argon2id KEK→DEK + AES-256-GCM whole-file seal
internal/vault    store (encrypted JSON), auth templates, allowlist + resolve-then-pin egress,
                  reflect-guard, hash-chained audit, rate limit, idle auto-lock
internal/server   the two planes, loopback guard + LAN toggle, token/session auth, pending-approval
internal/gui      the local web app: unlock, add/manage credentials, approvals, audit
cmd/vault         the runnable broker (gui | serve)
```

Architecture in **[DESIGN.md](./DESIGN.md)**, threat model in **[SECURITY.md](./SECURITY.md)**.

## Design principles

- **The key never leaves the vault** — agents and tools act by reference; no endpoint returns a
  plaintext secret into the model's context.
- **Scoped, gated, audited** — allowlist + approval + log, by default.
- **Portable & private** — pure Go, zero CGo, one binary; sealed at rest; no cloud.
- **The agent reasons, mykeep provides** — Vault brokers and records; it does no LLM reasoning.

## Where it fits

Vault is one of four mykeep components — all on one drive, under one password:

| | Component | Your agent can… |
|---|---|---|
| 🧠 | **[Capsule](https://github.com/lexxx233/mykeep-capsule)** | **know** you — encrypted, portable memory |
| 🔐 | **Vault** (this repo) | **act as** you — a secrets broker that acts by reference |
| 🔮 | **[Showstone](https://github.com/lexxx233/mykeep-showstone)** | **see** the web — a contained browser it drives over REST |
| 🧰 | **[Foundry](https://github.com/lexxx233/mykeep-foundry)** | **do** more — sandboxed tools + the backend they run on |

---

<div align="center">
<sub>A component of <a href="https://mykeep.ai">mykeep</a> · Secured · Private · Portable · © 2026 Domu Inc</sub>
</div>
