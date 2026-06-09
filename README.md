<div align="center">

# 🔐 mykeep · Vault

### Your secrets, sealed on the stick — so an agent can act as you without ever seeing your keys.

**Status: v1 implemented + tested** — pure-Go library, HTTP server, a **local GUI** (unlock + add
secrets in the browser), and a CLI. Integration into the one mykeep binary + OAuth come next.
Architecture in **[DESIGN.md](./DESIGN.md)**, threat model in **[SECURITY.md](./SECURITY.md)**.
Sibling: the [Capsule](https://github.com/lexxx233/mykeep-capsule) (component #1).

[mykeep.ai](https://mykeep.ai) · **Personal · Private · Portable**

</div>

---

Vault is the **"act as you"** component of [mykeep](https://mykeep.ai) — a portable
suite of local capabilities any AI agent can plug into, all on a USB stick. It holds your API
keys and secrets, encrypted on the stick, so your agent can take authenticated actions on your
behalf — call services, deploy, send mail — without your credentials ever touching the cloud
or the model provider.

## The core insight: a broker, not a key dispenser

If an agent can *read* a raw key, that key lands in the transcript — which goes to the model
provider — which defeats the entire point. So Vault never hands the agent a secret. It's
an **authenticated-egress proxy**: the agent works *by reference*.

```
POST /v1/secrets/{credential}/request
  { "method": "POST", "url": "https://api.stripe.com/v1/charges", "body": { ... } }

→ Vault attaches the auth header server-side, forwards the request,
  and returns the response. The agent never sees the key.
```

The secret stays sealed on the stick. The agent gets the *result*, not the *credential*.

## Bounded and observable — not "trust the agent"

At-rest encryption is not runtime safety: once unlocked, an agent (or a prompt-injected one)
can act with your authority. Vault's honest promise isn't "your keys are safe" — it's
that **the blast radius is bounded and observable.** That falls out of the proxy model as
policy:

- **Per-credential host allowlist** — the `stripe` credential only ever attaches to
  `api.stripe.com`. A confused or hijacked agent can't aim the proxy at `evil.com` to
  exfiltrate the key.
- **Approval tiers** — read-only calls auto-allow; writes and destructive calls require an
  explicit confirmation; some credentials are deny-by-default.
- **Encrypted audit log** — every action the agent took as you (credential, destination,
  method, result, time), recorded on the stick and reviewable.
- **OAuth brokering** *(later)* — hold refresh tokens sealed and run the refresh dance locally,
  so "act as you" extends to services like mail and calendar.

## How an agent uses it

The same shape as the rest of mykeep: a **loopback REST API + a pasted guide** — the
zero-install floor that works with any agent that can make an HTTP call. No client config, no
plugin. Vault is REST-native because it *is* an HTTP proxy.

## Where it fits

- **[Capsule](https://github.com/lexxx233/mykeep-capsule)** — *knows* you.
- **Foundry** — lets the agent *do* more; its tools request scoped credentials from Vault
  by reference.
- **Vault** — lets the agent *act as* you, safely.

All on one stick, under one password, sealed with the suite's whole-DB AES-256-GCM encryption.

## Build & test

```sh
make test     # go test ./...      (46 tests; crypto, allowlist/SSRF, auth, reflect-guard,
              #                      audit chain, plane separation, approval flow)
make build    # -> bin/vault
make guard    # prove the build pulls in zero CGo
make cross    # cross-compile all six win/mac/linux × amd64/arm64 targets
go test -race ./...   # needs CGO_ENABLED=1
```

Run it:

- **`vault`** (default) opens the **GUI** in your browser: set a password, then add and manage
  credentials, approve writes, and read the audit log. The GUI authenticates by the unlock password
  → a loopback session cookie, so a co-resident agent (no password) can't reach the control plane.
  It shows the **use** token to paste into your agent.
- **`vault serve`** is headless: unlock at launch (`MYKEEP_VAULT_PASSPHRASE` or stdin), serve
  the API only, print both tokens. `--lan` exposes *only* the use plane on the network; `--idle` sets
  the auto-lock minutes.

```
internal/secret   argon2id KEK→DEK + AES-256-GCM whole-file seal
internal/vault    store (encrypted JSON), auth templates, allowlist + resolve-then-pin egress,
                  reflect-guard, hash-chained audit, rate limit, idle auto-lock
internal/server   the two planes, loopback guard + LAN toggle, token/session auth, pending-approval
internal/gui      the local web app: unlock, add/manage credentials, approvals, audit
cmd/vault   the runnable broker (gui | serve)
```

## Design principles

- **The key never leaves the vault** — agents and tools act by reference; no endpoint returns a
  plaintext secret into the model's context.
- **Scoped, gated, audited** — allowlist + approval + log, by default.
- **Portable & private** — pure Go, zero CGo, one binary; sealed at rest; no cloud.
- **The agent reasons, mykeep provides** — Vault brokers and records; it does no LLM
  reasoning of its own.

---

<div align="center">
<sub>A component of <a href="https://mykeep.ai">mykeep</a> · Personal · Private · Portable · © 2026 Domu Inc</sub>
</div>
