package server

import (
	"fmt"
	"net/http"
)

// SnippetText is the one-paragraph block a human pastes into their AI agent. It
// carries the loopback URL + use token and points the agent at the full guide.
func SnippetText(baseURL, useToken string) string {
	return fmt.Sprintf(`You have a local Vault at %s — it lets you take authenticated API
actions AS the user WITHOUT ever seeing their secrets. Authenticate EVERY call with the header:
    X-Vault-Token: %s
▶ First, fetch your operating manual:  GET %s/v1/vault/guide
Then follow it. You act BY REFERENCE: never ask for a key. To make an authenticated request,
POST it to %s/v1/vault/fetch naming a credential; Vault attaches the auth server-side and
returns the response (never the secret). Use your shell or fetch tool to call the API.`,
		baseURL, useToken, baseURL, baseURL)
}

// GuideText is the full operating manual served at GET /v1/vault/guide.
const GuideText = `Vault — operating manual for an AI agent
================================================

WHAT THIS IS
  A local broker that holds the user's API keys, encrypted on their machine. You can make
  authenticated requests "as the user" WITHOUT the key ever entering this conversation. You
  work BY REFERENCE: you name a credential, Vault injects its secret server-side, sends
  the request, and returns only the response. You never see, and must never ask for, a raw key.

AUTH
  Every call needs the header:  X-Vault-Token: <use token>   (shown to the user in the GUI).

ENDPOINTS
  GET  /v1/vault/credentials
       Lists the credentials you may use. Each has: name, type, allow_hosts, enabled.
       You can ONLY use a credential whose "enabled" is true (the user enables it in the GUI).

  POST /v1/vault/fetch
       Make an authenticated request by reference. Body (JSON):
         {
           "credential": "stripe",                     // a name from the list above
           "method": "GET",                            // GET|HEAD|POST|PUT|PATCH|DELETE
           "url": "https://api.stripe.com/v1/charges", // MUST be an allowlisted host, https
           "headers": { "Idempotency-Key": "..." },    // optional; you cannot set auth headers
           "body": "...",                              // optional (or "body_b64" for binary)
           "max_response_bytes": 1048576               // optional cap
         }
       Returns: { "status", "headers", "body", "truncated", "audit_id" }.

RULES (read these — they explain the errors you will hit)
  • Act by reference. NEVER place a secret in the url/headers/body yourself — you don't have it,
    and a request that contains a stored secret is rejected ("outbound_exfil_blocked").
  • Allowlist. A credential only works against its allow_hosts. Off-list → "host_not_allowed".
  • Enable. If a credential is disabled, calls fail with "credential_disabled" — ASK THE USER to
    enable it in the Vault GUI; do not retry blindly.
  • Approvals. Reads (GET/HEAD) usually run automatically. WRITES may BLOCK while the user
    approves them in the GUI (your call simply waits), or be refused ("approval_denied" /
    "denied_by_policy"). Do not spam retries; tell the user a write is awaiting their approval.
  • Rate limits → "rate_limited"; back off.
  • The response never contains the secret; a reflected secret is stripped ("reflect_blocked").

EXAMPLE
  curl -s http://127.0.0.1:8770/v1/vault/fetch \
       -H "X-Vault-Token: $TOKEN" \
       -d '{"credential":"github","method":"GET","url":"https://api.github.com/user"}'

That's the whole protocol: list what's enabled, then fetch by reference.
`

func (s *Server) handleGuide(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(GuideText))
}
