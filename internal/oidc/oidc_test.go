package oidc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestCSRFValid verifies the per-session CSRF check: matching token passes,
// mismatch and empty tokens fail closed.
func TestCSRFValid(t *testing.T) {
	a, err := New(Config{
		Issuer:        "https://auth.harmonicr.com",
		ClientID:      "x",
		ClientSecret:  "s",
		RedirectURL:   "https://support.harmonicr.com/callback",
		SessionSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	tok := newCSRF()
	a.mu.Lock()
	a.sessions["sub-1"] = Session{Subject: "sub-1", CSRF: tok}
	a.mu.Unlock()

	// A request carrying the session cookie for sub-1.
	req := httptest.NewRequest(http.MethodPost, "/tickets/1/comment", nil)
	w := httptest.NewRecorder()
	a.cookie.Set(w, req, "support_sess", "sub-1", time.Hour)
	// Carry the Set-Cookie header onto the request so CurrentSession sees it.
	if sc := w.Header().Get("Set-Cookie"); sc != "" {
		req.Header.Set("Cookie", sc)
	}

	if !a.CSRFValid(req, tok) {
		t.Fatal("matching CSRF token should validate")
	}
	if a.CSRFValid(req, "wrong") {
		t.Fatal("mismatched CSRF token must fail")
	}
	if a.CSRFValid(req, "") {
		t.Fatal("empty CSRF token must fail closed")
	}
}
func TestRequireAuthFailClosed(t *testing.T) {
	a, err := New(Config{
		Issuer:        "", // not configured
		ClientID:      "x",
		ClientSecret:  "s",
		RedirectURL:   "https://support.harmonicr.com/callback",
		SessionSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if a.Enabled() {
		t.Fatal("Enabled() should be false with empty issuer")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	a.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 (fail closed), got %d", w.Code)
	}
}

// TestRequireAuthRedirect verifies an unauthenticated user is redirected.
func TestRequireAuthRedirect(t *testing.T) {
	// Use a fake provider so Enabled() is true; the guard only needs the
	// session cookie check, not a real network call.
	a, err := New(Config{
		Issuer:        "https://auth.harmonicr.com",
		ClientID:      "x",
		ClientSecret:  "s",
		RedirectURL:   "https://support.harmonicr.com/callback",
		SessionSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// No session cookie -> redirect to /login.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	a.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302 redirect, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.Contains(loc, "/login") {
		t.Fatalf("redirect to %q, want /login", loc)
	}
}

// TestCookieSignVerify verifies the HMAC-signed cookie round-trips and rejects
// a tampered value.
func TestCookieSignVerify(t *testing.T) {
	cs := NewCookieStore("secret", "support_sess")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	cs.Set(rec, req, "support_sess", "user-123", time.Hour)
	cookie := rec.Result().Cookies()[0]
	req.AddCookie(cookie)
	val, ok := cs.Get(req, "support_sess")
	if !ok || val != "user-123" {
		t.Fatalf("roundtrip: got %q ok=%v", val, ok)
	}
	// Tamper: change the payload, keep the sig -> must fail.
	tampered := *cookie
	tampered.Value = strings.Replace(cookie.Value, "user-123", "attacker", 1)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&tampered)
	if _, ok := cs.Get(req2, "support_sess"); ok {
		t.Fatal("tampered cookie accepted")
	}
}

// TestPKCE verifies the verifier + S256 challenge are produced.
func TestPKCE(t *testing.T) {
	v, c, err := pkce()
	if err != nil {
		t.Fatalf("pkce: %v", err)
	}
	if v == "" || c == "" {
		t.Fatal("empty pkce output")
	}
	if strings.ContainsAny(v+c, "=+/") {
		t.Fatal("base64url should not contain =+/")
	}
}

// TestBeginLoginRedirects verifies BeginLogin issues a 302 to the provider.
func TestBeginLoginRedirects(t *testing.T) {
	a, err := New(Config{
		Issuer:        "https://auth.harmonicr.com",
		ClientID:      "x",
		ClientSecret:  "s",
		RedirectURL:   "https://support.harmonicr.com/callback",
		SessionSecret: "secret",
	}, nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login/start", nil)
	w := httptest.NewRecorder()
	a.BeginLogin(w, req)
	if w.Code != http.StatusFound {
		t.Fatalf("want 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "auth.harmonicr.com") || !strings.Contains(loc, "code_challenge") {
		t.Fatalf("redirect %q missing provider/code_challenge", loc)
	}
}
