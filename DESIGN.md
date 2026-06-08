# SecretVault — Design

> **Status: design, no code yet.** This document is the settled architecture for the v1 build.
> It is the source of truth for the decisions below; `SECURITY.md` holds the threat model.
> Part of [joyvend](https://joyvend.io) — see the [README](./README.md).

SecretVault lets an AI agent take authenticated actions **as you** without ever seeing your
credentials. It is an **authenticated-egress broker**: the agent makes a request *by reference*
("send this to `api.stripe.com` using credential `stripe`"); SecretVault attaches the secret
server-side, forwards the request, and returns only the response. The raw secret never enters the
agent's context, the transcript, or the model provider.

It ships as a **module inside the one joyvend binary**, reusing the Memory Capsule's substrate:
the argon2id-KEK→DEK key hierarchy, AES-256-GCM sealing, the debounced off-lock re-seal, the
single-instance lock, and the one-password unlock. One unlock arms memory *and* secrets.

---

## 1. Storage — a single encrypted JSON file

Secrets are a tiny dataset (dozens of credentials, not millions of rows), so SecretVault does **not**
use SQLite. It uses one sealed JSON file beside the memory DB:

```
joyvend_kb/vault.json.enc        ← one AES-256-GCM blob, sealed under the same DEK
```

- Decrypted into an in-RAM struct **at launch** (same lifecycle as the memory server), re-sealed
  via the existing **debounced off-lock single-flight** path on every change.
- A `version` integer replaces the whole migration framework — new credential types or fields are
  additive, with no migration step and no fail-closed DB dance.
- **Whole-file seal is the integrity boundary.** The entire document — secrets *and* allowlists
  *and* tiers *and* the audit log — is under one AEAD tag, so a local edit to any policy field
  without the password breaks the seal. No per-field MAC needed.

```jsonc
{
  "version": 1,
  "credentials": {
    "stripe": {
      "type": "bearer",                 // bearer | header | basic | custom
      "secret": "<plaintext while unlocked; sealed inside the blob at rest>",
      "allow_hosts": ["api.stripe.com"],
      "read_tier":  "auto",             // auto | confirm
      "write_tier": "confirm",          // auto | confirm | deny
      "enabled": false,                 // per-session enable (see §6)
      "expires_at": null,
      "rate_per_min": 60,
      "created_at": "2026-06-08T...Z"
    }
  },
  "grants": [],                          // scoped "remember this" approvals (v1.1)
  "audit":  [ /* hash-chained; see §7 */ ]
}
```

> **RAM honesty.** Once the JSON is decrypted, secrets are Go strings resident in memory for the
> whole unlock session — byte-scrubbing is theater. The real runtime control is the at-rest seal
> plus **idle auto-lock** (zeroing the DEK + decrypted struct on lock). The claim is "sealed at
> rest; resident only while unlocked; auto-locks when idle," never "the key is never in memory."

---

## 2. Two planes — use vs. control

| Plane | Mount | Who | What |
|---|---|---|---|
| **Use** | `/v1/vault/*` | the agent | `POST /v1/vault/fetch` (act by reference) + `GET` metadata list |
| **Control** | `/api/vault/*` | the human, via GUI | create / edit / delete credentials, enable-for-session, approve writes, read the audit log |

The agent can **use** a credential but can never create, read, edit its allowlist, self-enable, or
self-approve. Credential creation is a human act in the GUI — which is both the product requirement
and the load-bearing security control (see `SECURITY.md` §2). The agent plane exposes **no endpoint
that returns a secret value**; `GET` on a credential returns metadata plus a salted, GUI-only
fingerprint, never the value.

---

## 3. Networking — loopback by default, LAN opt-in

The whole suite is loopback-only by default; LAN exposure is an explicit, per-launch choice.

- **Default, every launch:** loopback-only. No network surface.
- **GUI launch toggle (default OFF, per session):** *"Allow other devices on my network to use
  joyvend."* When on, the **use plane** binds to the LAN interface behind a **mandatory token**,
  with a plaintext-traffic warning.
- **The control plane stays loopback-only — always, even in LAN mode.** Secret creation and the
  write-approval prompts never travel the wire.
- The **use-plane token is always required** (cheap defense-in-depth on loopback; load-bearing on
  LAN).

This is a suite-wide model (memory + vault + future Foundry), replacing the hard loopback-only guard.

---

## 4. Auth types

A credential carries a typed **auth template**. Injection happens in Go, inside a `KeyStore.Use`
closure, at send time — never in any JSON the model can see.

| `type` | Injects | Fields |
|---|---|---|
| `bearer` | `Authorization: Bearer <secret>` | `secret` |
| `header` | `<header_name>: <secret>` | `secret`, `header_name` (e.g. `X-API-Key`) |
| `basic`  | `Authorization: Basic base64(user:secret)` | `secret`, `username` (server-pinned) |
| `custom` | `Authorization: <template>` with `${secret}` substituted | `secret`, `template` (e.g. `Token ${secret}`) |

There is deliberately **no `query` type** — putting a secret in the URL leaks it into logs,
`Referer`, and error strings. OAuth is **not** `custom`; it is a dynamic refresh flow and arrives as
a separate `oauth2` kind in v1.1 (additive, no migration).

---

## 5. The `fetch` verb

```
POST /v1/vault/fetch
{
  "credential": "stripe",
  "method": "POST",
  "url": "https://api.stripe.com/v1/charges",
  "headers": { "Idempotency-Key": "abc" },   // agent headers; auth headers stripped & overridden
  "body": "amount=2000&currency=usd",          // or "body_b64" for binary
  "max_response_bytes": 1048576
}

→ { "status": 200, "headers": {...}, "body": "...", "truncated": false, "audit_id": "a1b2..." }
```

Every call runs the same enforced pipeline, in order:

1. **Authn / state** — valid use-plane token; credential exists, is **enabled for this session**,
   and is not expired.
2. **URL parse** — reject any URL with userinfo (`user:pass@`); require `https` (unless a per-
   credential `allow_insecure` is set for a known internal target); normalize host (lowercase,
   IDNA→ASCII, strip one trailing dot).
3. **Allowlist** — host matches the credential's `allow_hosts` via **label-aware** glob
   (`*.x.com` matches one-or-more leading labels of `x.com`, never substring/suffix).
4. **Resolve-then-pin** — `LookupIP` once; deny loopback, link-local, `169.254/16` metadata, and
   the joyvend host's own address always; deny RFC1918/CGNAT unless the credential's allowlist
   explicitly names the private host; **pin** a surviving IP and `DialContext` to it with the
   original Host/SNI; the transport never re-resolves (anti-rebinding/TOCTOU).
5. **Tier** — method → `read` (GET/HEAD, auto) / `write` (mutating, **blocks** for a human confirm
   over loopback) / `deny` (403). Tier is derived server-side from the resolved method+host, never
   from an agent-stated intent.
6. **Rate** — per-credential `rate_per_min` token bucket; concurrency + in-flight-bytes capped to
   protect the RAM-resident process.
7. **Build outgoing request from scratch** — start from an empty `http.Header`; drop the agent's
   auth/denylist headers; inject the authoritative auth value **last**, so agent input can never
   override it.
8. **Forward** — redirects are **never auto-followed** (`CheckRedirect → ErrUseLastResponse`);
   TLS ≥ 1.2, never `InsecureSkipVerify`; response body capped via `io.LimitReader`.
9. **Sanitize response** — strip any `Location`/header whose host fails the allowlist; run the
   reflect-guard (multi-encoding scan for the injected value) as **defense-in-depth**; never let an
   error string that has seen the assembled URL/headers reach the agent.
10. **Audit** — append one hash-chained, metadata-only row.

Writes block synchronously (the call long-polls until the human clicks **Approve** in the GUI, or
returns 403 on deny/timeout) — no `approval_id` round-trip the agent could self-grant.

---

## 6. Lifecycle controls (v1)

- **Idle auto-lock** — after N idle minutes (default ~15) the DEK and decrypted vault are zeroed;
  the next call requires a re-unlock. Promotes "bounded standing authority" from aspiration to fact.
- **Per-session enable** — credentials are **disabled by default each unlock**; the human enables a
  credential for the session in the GUI before the broker will use it.
- **Expiry** — `expires_at` is enforced in step 1 of every fetch.

---

## 7. Audit log

Append-only entries live in the same `vault.json.enc`, **hash-chained** (`row_hash =
H(prev_hash || fields)`) so truncation or reordering is detectable on top of the whole-file AEAD
seal. Each row records timestamp, credential name, method, host, decision/tier, status, response
bytes, latency, and **source address** — never the secret and never the response body. It is
**human-only**, read via the GUI / `joyvend vault audit`; it is not on the agent plane. Retention is
user-managed (a GUI "clear entries older than N"), not automatic.

---

## 8. Scope

**v1** — the `fetch` verb + GUI credential CRUD; the four auth types; label-aware allowlist with
IDNA/case normalization + userinfo reject; resolve-then-pin egress; no-follow redirects + final-host
re-validation; strip-then-inject auth; https + TLS≥1.2; loopback control plane + opt-in LAN use
plane with a mandatory token; hash-chained audit; idle auto-lock + per-session enable; per-credential
rate + concurrency caps; expiry in the hot path; reflect-guard (multi-encoding) as defense-in-depth.

**v1.1+** — OAuth refresh-token brokering (`oauth2` kind, RFC 8252 loopback enroll, lazy
single-flight refresh, atomic RT rotation); the `sv://name/field` reference grammar + `{{sv://}}`
body templating; response-wrapping one-time tickets; scoped "remember this decision" grants;
cross-secret outbound-body exfil scan; SigV4; per-agent identity; streaming for large downloads.
