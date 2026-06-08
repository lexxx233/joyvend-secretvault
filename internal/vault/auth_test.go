package vault

import (
	"encoding/base64"
	"testing"
)

func TestInjectAuthTypes(t *testing.T) {
	t.Run("bearer", func(t *testing.T) {
		h, _ := buildHeaders(nil, "Authorization")
		injectAuth(&Credential{Type: AuthBearer, Secret: "tok123456"}, h)
		if got := h.Get("Authorization"); got != "Bearer tok123456" {
			t.Fatalf("bearer => %q", got)
		}
	})
	t.Run("header", func(t *testing.T) {
		h, _ := buildHeaders(nil, "X-API-Key")
		injectAuth(&Credential{Type: AuthHeader, HeaderName: "X-API-Key", Secret: "k_abcdef"}, h)
		if got := h.Get("X-API-Key"); got != "k_abcdef" {
			t.Fatalf("header => %q", got)
		}
	})
	t.Run("basic", func(t *testing.T) {
		h, _ := buildHeaders(nil, "Authorization")
		injectAuth(&Credential{Type: AuthBasic, Username: "alice", Secret: "pw_secret"}, h)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:pw_secret"))
		if got := h.Get("Authorization"); got != want {
			t.Fatalf("basic => %q want %q", got, want)
		}
	})
	t.Run("custom", func(t *testing.T) {
		h, _ := buildHeaders(nil, "Authorization")
		injectAuth(&Credential{Type: AuthCustom, Template: "Token ${secret}", Secret: "s_xyz123"}, h)
		if got := h.Get("Authorization"); got != "Token s_xyz123" {
			t.Fatalf("custom => %q", got)
		}
	})
}

func TestAgentCannotOverrideInjectedAuth(t *testing.T) {
	// Agent tries to set Authorization itself; strip-then-inject must win.
	agent := map[string]string{
		"Authorization": "Bearer EVIL",
		"Cookie":        "session=steal",
		"X-Foo":         "keep",
	}
	h, err := buildHeaders(agent, "Authorization")
	if err != nil {
		t.Fatalf("buildHeaders: %v", err)
	}
	if h.Get("Authorization") != "" || h.Get("Cookie") != "" {
		t.Fatal("denylisted headers survived agent input")
	}
	if h.Get("X-Foo") != "keep" {
		t.Fatal("benign agent header was dropped")
	}
	injectAuth(&Credential{Type: AuthBearer, Secret: "realsecret"}, h)
	if got := h.Get("Authorization"); got != "Bearer realsecret" {
		t.Fatalf("agent override won: Authorization = %q", got)
	}
}

func TestBuildHeadersRejectsCRLF(t *testing.T) {
	if _, err := buildHeaders(map[string]string{"X-Foo": "bar\r\nEvil: 1"}, "Authorization"); err == nil {
		t.Fatal("CRLF header value accepted (header splitting)")
	}
	if _, err := buildHeaders(map[string]string{"Bad\r\nName": "x"}, "Authorization"); err == nil {
		t.Fatal("CRLF header name accepted")
	}
}

func TestBuildHeadersStripsInjectedName(t *testing.T) {
	// For a header-type cred, the agent must not pre-set the injected header.
	h, _ := buildHeaders(map[string]string{"X-API-Key": "agentguess"}, "X-API-Key")
	if h.Get("X-API-Key") != "" {
		t.Fatal("agent-supplied injected header survived")
	}
}
