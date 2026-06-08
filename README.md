<div align="center">

# 🔐 joyvend · SecretVault

### Your secrets, sealed on the stick — so an agent can act as you without ever seeing your keys.

**Status: vision / design.** No code yet — this repo holds the design while the
[Memory Capsule](https://github.com/lexxx233/JoyVend-memory-capsule) (component #1) ships.

[joyvend.io](https://joyvend.io) · **Personal · Private · Portable**

</div>

---

SecretVault is the **"act as you"** component of [joyvend](https://joyvend.io) — a portable
suite of local capabilities any AI agent can plug into, all on a USB stick. It holds your API
keys and secrets, encrypted on the stick, so your agent can take authenticated actions on your
behalf — call services, deploy, send mail — without your credentials ever touching the cloud
or the model provider.

## The core insight: a broker, not a key dispenser

If an agent can *read* a raw key, that key lands in the transcript — which goes to the model
provider — which defeats the entire point. So SecretVault never hands the agent a secret. It's
an **authenticated-egress proxy**: the agent works *by reference*.

```
POST /v1/secrets/{credential}/request
  { "method": "POST", "url": "https://api.stripe.com/v1/charges", "body": { ... } }

→ SecretVault attaches the auth header server-side, forwards the request,
  and returns the response. The agent never sees the key.
```

The secret stays sealed on the stick. The agent gets the *result*, not the *credential*.

## Bounded and observable — not "trust the agent"

At-rest encryption is not runtime safety: once unlocked, an agent (or a prompt-injected one)
can act with your authority. SecretVault's honest promise isn't "your keys are safe" — it's
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

The same shape as the rest of joyvend: a **loopback REST API + a pasted guide** — the
zero-install floor that works with any agent that can make an HTTP call. No client config, no
plugin. SecretVault is REST-native because it *is* an HTTP proxy.

## Where it fits

- **[Memory Capsule](https://github.com/lexxx233/JoyVend-memory-capsule)** — *knows* you.
- **Foundry** — lets the agent *do* more; its tools request scoped credentials from SecretVault
  by reference.
- **SecretVault** — lets the agent *act as* you, safely.

All on one stick, under one password, sealed with the suite's whole-DB AES-256-GCM encryption.

## Design principles

- **The key never leaves the vault** — agents and tools act by reference; no endpoint returns a
  plaintext secret into the model's context.
- **Scoped, gated, audited** — allowlist + approval + log, by default.
- **Portable & private** — pure Go, zero CGo, one binary; sealed at rest; no cloud.
- **The agent reasons, joyvend provides** — SecretVault brokers and records; it does no LLM
  reasoning of its own.

---

<div align="center">
<sub>A component of <a href="https://joyvend.io">joyvend</a> · Personal · Private · Portable · © 2026 Domu Inc</sub>
</div>
