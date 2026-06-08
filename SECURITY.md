# SecretVault — Security Model & Threat Model

> **Status: design, no code yet.** This is the threat model the v1 build is designed against.
> See [`DESIGN.md`](./DESIGN.md) for the architecture. Part of [mykeep](https://mykeep.ai).

## The honest promise

SecretVault's promise is **not** "your keys are safe." Once the stick is unlocked, an AI agent acts
with your authority — and an agent can be prompt-injected. The honest, defensible promise is:

> **The blast radius is bounded and observable.**

- **Bounded** — a hijacked agent can only reach the hosts you allowlisted, only auto-run reads, and
  needs a human at the drive to approve writes; standing authority decays via idle auto-lock.
- **Observable** — every authenticated action it took as you is in a tamper-evident, on-stick audit
  log you can review.

"The agent never sees the raw key" is **table stakes** (other brokers ship it too), and it is *not*
the security boundary. The boundary is the allowlist + the human-in-the-loop on writes + the
network policy + the audit. Treat everything else as defense-in-depth.

## Adversary

The primary adversary is a **prompt-injected or confused agent inside the trust perimeter** — it
holds the use-plane token and can call `/v1/vault/fetch` with attacker-influenced `url`, `headers`,
and `body`. A secondary adversary (only in opt-in LAN mode) is **another device on your network**.
We do **not** defend against an attacker who already has your password, your unlocked drive, or code
execution able to read mykeep's process memory — at that point it is game over by construction.

## The two load-bearing controls

Everything else is secondary to these two. Each was a *critical* finding in an adversarial review of
the design; shipping without either makes v1 insecure, not merely limited.

### 1. Control plane ≠ use plane

Creating a credential, editing its allowlist, enabling it, and approving a write are **human-only**
actions on the loopback control plane (`/api/vault`, the GUI). They are never reachable by the agent.
If the agent could edit an allowlist or grant its own approval, every other control collapses — so
this separation is structural, gated by a control token minted at unlock and shown only in the GUI,
never in `/v1/guide` or the agent snippet. **The control plane stays loopback-only even when LAN
mode is on.**

### 2. Resolve-then-pin egress

The allowlist binds the **resolved IP**, not the hostname string. A string-only allowlist is
bypassable by DNS rebinding, or by an allowlisted name that resolves to `169.254.169.254` (cloud
metadata) or `127.0.0.1` (mykeep's own unlocked API). So every fetch resolves the host once, rejects
loopback / link-local / metadata / the mykeep host's own address (and RFC1918 unless the credential
explicitly allowlists a private host), **pins** a surviving IP, and dials that exact IP with the
original Host/SNI — the transport never re-resolves. Because reads are auto-approved, this control
carries the entire read-side blast radius; it cannot lean on the approval gate.

## Exfiltration is outbound, not the response

The intuitive worry — the upstream echoing the key back — is the *minor* channel. The dominant leak
is **outbound**: the agent pointing a credentialed request at a host that logs the injected header.
Defenses, in priority order:

1. **Allowlist edits are human-only** (control plane). The secret rides the outbound request; if the
   agent could add `attacker.com` to a credential's allowlist, nothing else matters.
2. **No auto-follow redirects; strip any off-allowlist `Location`** before returning it — otherwise
   the agent reads the redirect target and re-fetches with the secret attached.
3. **No `query` auth type** — a secret in the URL leaks into logs, `Referer`, and error strings.
4. **Errors never echo the assembled URL/headers** — fixed error kinds only; the audit redacts by
   template position, never by scrubbing the raw value.
5. **Reflect-guard** (scrubbing the injected value from responses, across base64/hex/percent
   encodings and the Basic wire form) is **defense-in-depth against an honest upstream that echoes**,
   not a guarantee against a malicious one. A determined hostile upstream can always transform the
   value; the real control is *don't allowlist hosts that log credentials*.

## Networking posture

- **Loopback-only by default**, every launch — no network attack surface.
- **LAN exposure is opt-in, per-session, via a GUI toggle**, with a plaintext-traffic warning. Only
  the **use plane** is exposed, behind a **mandatory** token; the control plane never is.
- v1 uses plaintext HTTP on the LAN. This is acceptable *because* LAN mode is a deliberate, warned,
  per-launch choice. The residual risk of a sniffed use-plane token is bounded: an attacker gets
  only **allowlist-bounded reads + queued write-confirms the human still approves at the drive-host
  GUI.** It cannot create credentials, self-approve, or reach the control plane. (TLS with a pinned
  self-signed cert is a candidate hardening for a later version.)

## What an attacker can and cannot do

Assume a fully prompt-injected agent holding the use-plane token, drive unlocked:

| Can | Cannot |
|---|---|
| Call any **enabled** credential against its **allowlisted hosts** | Reach a host not on that credential's allowlist |
| Auto-run **reads** (GET/HEAD) within the allowlist | Auto-run **writes** — they block for a human confirm |
| Queue a write for human approval | Create, read, edit, or enable a credential |
| See **response bodies** from allowlisted hosts | See the **raw secret**, or grant its own approval |
| Act until **idle auto-lock** fires | Act after auto-lock without a re-unlock |

The corollaries you own: **the allowlist is a trust decision** (don't allowlist a host that logs or
reflects requests), and **writes are only as safe as the human approving them.**

## Defense-in-depth (not guarantees)

Stated honestly so they are never over-trusted:

- **RAM hygiene** — secrets are Go strings resident while unlocked; the at-rest seal + idle
  auto-lock are the real controls, not byte-zeroing.
- **Reflect-guard** — best-effort against honest echo; bypassable by a hostile upstream.
- **Whole-file AEAD seal** — protects at rest and makes offline policy tampering detectable, but the
  data is plaintext in RAM while unlocked.
- **Audit hash chain** — detects truncation/reorder on top of the seal; it is evidence, not
  prevention.

## Reporting

This is pre-release software with no implementation yet. Once code lands, security reports go to the
address in the repository's security policy. There is **no password recovery** — a forgotten
password means the vault is unrecoverable, by design.
