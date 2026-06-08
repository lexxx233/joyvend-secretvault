package vault

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testSecret = "supersecretvalue123"

// fetchFixture builds a store with one enabled bearer credential allowlisted to
// 127.0.0.1 (so an httptest server is reachable), and an Engine whose deny-func
// permits loopback for the test.
func fetchFixture(t *testing.T, approve bool) (*Engine, *Store) {
	t.Helper()
	s, _ := mkStore(t)
	c := &Credential{
		Type:          AuthBearer,
		Secret:        testSecret,
		AllowHosts:    []string{"127.0.0.1"},
		AllowInsecure: true, // httptest is plain HTTP
		ReadTier:      TierAuto,
		WriteTier:     TierConfirm,
	}
	if err := s.Put("api", c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_ = s.Enable("api", true)

	e := NewEngine(s, ApproverFunc(func(ctx context.Context, r ConfirmRequest) (bool, error) {
		return approve, nil
	}))
	e.deny = func(ip net.IP, allowPrivate bool) bool { return false } // allow loopback in tests
	return e, s
}

func TestFetchReadAutoSucceeds(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("hello"))
	}))
	defer srv.Close()
	e, store := fetchFixture(t, true)

	resp, ferr := e.Fetch(context.Background(), "127.0.0.1:1", FetchRequest{
		Credential: "api", Method: "GET", URL: srv.URL + "/x",
	})
	if ferr != nil {
		t.Fatalf("fetch: %v", ferr)
	}
	if resp.Status != 200 || resp.Body != "hello" {
		t.Fatalf("resp = %d %q", resp.Status, resp.Body)
	}
	if gotAuth != "Bearer "+testSecret {
		t.Fatalf("upstream got auth %q", gotAuth)
	}
	if a := store.Audit(); len(a) != 1 || a[0].Decision != "allowed" {
		t.Fatalf("audit = %+v", a)
	}
}

func TestFetchDisabledCredential(t *testing.T) {
	e, store := fetchFixture(t, true)
	_ = store.Enable("api", false)
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: "https://127.0.0.1/"})
	if ferr == nil || ferr.Code != "credential_disabled" {
		t.Fatalf("disabled => %v", ferr)
	}
}

func TestFetchWriteNeedsApproval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }))
	defer srv.Close()

	// Denying approver blocks the write.
	eDeny, _ := fetchFixture(t, false)
	_, ferr := eDeny.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "POST", URL: srv.URL + "/"})
	if ferr == nil || ferr.Code != "approval_denied" {
		t.Fatalf("denied write => %v", ferr)
	}
	// Approving approver lets it through.
	eOK, _ := fetchFixture(t, true)
	resp, ferr := eOK.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "POST", URL: srv.URL + "/"})
	if ferr != nil || resp.Status != 201 {
		t.Fatalf("approved write => %v %d", ferr, resp.Status)
	}
}

func TestFetchWriteDenyTier(t *testing.T) {
	e, store := fetchFixture(t, true)
	c, _, _ := store.lookup("api")
	c.WriteTier = TierDeny
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "DELETE", URL: "https://127.0.0.1/"})
	if ferr == nil || ferr.Code != "denied_by_policy" {
		t.Fatalf("deny tier => %v", ferr)
	}
}

func TestFetchOffAllowlistBlockedAndUpstreamNotHit(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	// host "evil.test" is not in the allowlist (["127.0.0.1"]).
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: "https://evil.test/"})
	if ferr == nil || ferr.Code != "host_not_allowed" {
		t.Fatalf("off-allowlist => %v", ferr)
	}
	if hit {
		t.Fatal("upstream was contacted for an off-allowlist host")
	}
}

func TestFetchRedirectNotFollowedLocationStripped(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "https://evil.test/steal")
		w.WriteHeader(302)
	}))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	resp, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: srv.URL + "/"})
	if ferr != nil {
		t.Fatalf("fetch: %v", ferr)
	}
	if resp.Status != 302 {
		t.Fatalf("status = %d, want 302 (not followed)", resp.Status)
	}
	if loc := resp.Headers["Location"]; len(loc) != 0 {
		t.Fatalf("off-allowlist Location not stripped: %v", loc)
	}
	if hits != 1 {
		t.Fatalf("server hit %d times (redirect followed?)", hits)
	}
}

func TestFetchReflectGuardBlocksBodyEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hostile upstream echoes the injected Authorization into the body.
		w.Write([]byte("debug: " + r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: srv.URL + "/"})
	if ferr == nil || ferr.Code != "reflect_blocked" {
		t.Fatalf("reflect echo => %v", ferr)
	}
}

func TestFetchUpstreamErrorDoesNotLeak(t *testing.T) {
	e, _ := fetchFixture(t, true)
	// Port 1 is closed → connection refused. The error must be a fixed code with no URL.
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: "http://127.0.0.1:1/secretpath"})
	if ferr == nil || ferr.Code != "upstream_unreachable" {
		t.Fatalf("upstream error => %v", ferr)
	}
	if strings.Contains(ferr.Error(), "secretpath") || strings.Contains(ferr.Error(), testSecret) {
		t.Fatalf("error leaked detail: %q", ferr.Error())
	}
}

func TestFetchSizeCap(t *testing.T) {
	big := strings.Repeat("A", 100000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(big)) }))
	defer srv.Close()
	e, _ := fetchFixture(t, true)
	resp, ferr := e.Fetch(context.Background(), "x", FetchRequest{
		Credential: "api", Method: "GET", URL: srv.URL + "/", MaxResponseBytes: 1000,
	})
	if ferr != nil {
		t.Fatalf("fetch: %v", ferr)
	}
	if !resp.Truncated || len(resp.Body) != 1000 {
		t.Fatalf("truncated=%v len=%d", resp.Truncated, len(resp.Body))
	}
}

func TestFetchExpiredCredential(t *testing.T) {
	e, store := fetchFixture(t, true)
	c, _, _ := store.lookup("api")
	past := time.Now().Add(-time.Hour)
	c.ExpiresAt = &past
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: "https://127.0.0.1/"})
	if ferr == nil || ferr.Code != "credential_expired" {
		t.Fatalf("expired => %v", ferr)
	}
}

func TestFetchOutboundExfilBlocked(t *testing.T) {
	e, _ := fetchFixture(t, true)
	// Agent tries to smuggle the secret out in the request body.
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{
		Credential: "api", Method: "GET", URL: "https://127.0.0.1/", Body: "leak=" + testSecret,
	})
	if ferr == nil || ferr.Code != "outbound_exfil_blocked" {
		t.Fatalf("exfil => %v", ferr)
	}
}

func TestFetchHTTPSRequired(t *testing.T) {
	e, store := fetchFixture(t, true)
	c, _, _ := store.lookup("api")
	c.AllowInsecure = false
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "api", Method: "GET", URL: "http://127.0.0.1/"})
	if ferr == nil || ferr.Code != "https_required" {
		t.Fatalf("http with AllowInsecure=false => %v", ferr)
	}
}

func TestFetchUnknownCredential(t *testing.T) {
	e, _ := fetchFixture(t, true)
	_, ferr := e.Fetch(context.Background(), "x", FetchRequest{Credential: "nope", Method: "GET", URL: "https://127.0.0.1/"})
	if ferr == nil || ferr.Code != "credential_not_found" {
		t.Fatalf("unknown cred => %v", ferr)
	}
}
