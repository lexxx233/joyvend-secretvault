package vault

// fetchError is a fixed, safe error: its message is a stable code that NEVER
// contains the request URL, headers, or the secret. The fetch pipeline returns only
// these to the agent, so a url.Error embedding `?api_key=…` can never leak
// (SECURITY.md, red-team: error-message leak).
type fetchError struct {
	Code   string
	Status int
}

func (e *fetchError) Error() string { return e.Code }

var (
	errNoCred       = &fetchError{"credential_not_found", 404}
	errCredDisabled = &fetchError{"credential_disabled", 403}
	errCredExpired  = &fetchError{"credential_expired", 403}
	errBadURL       = &fetchError{"bad_url", 400}
	errInsecure     = &fetchError{"https_required", 400}
	errBadHeader    = &fetchError{"bad_header", 400}
	errNotAllowed   = &fetchError{"host_not_allowed", 403}
	errSSRFBlocked  = &fetchError{"egress_blocked", 403}
	errDNS          = &fetchError{"dns_failed", 502}
	errDenied       = &fetchError{"denied_by_policy", 403}
	errApproval     = &fetchError{"approval_denied", 403}
	errRateLimited  = &fetchError{"rate_limited", 429}
	errExfil        = &fetchError{"outbound_exfil_blocked", 400}
	errUpstream     = &fetchError{"upstream_unreachable", 502}
	errReflect      = &fetchError{"reflect_blocked", 502}
)
