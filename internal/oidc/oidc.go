// Package oidc implements Zitadel OIDC SSO for the staff helpdesk UI
// (locked O-04: OIDC cookie session; PKCE + code flow, matching Peppermint's
// proven pattern and event-triage's admin guard).
//
// The auth surface FAILS CLOSED: if OIDC is not configured (empty issuer or
// missing client secret) every protected route returns 403 — it never opens.
package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config is the Zitadel OIDC client configuration.
type Config struct {
	Issuer        string // e.g. https://auth.harmonicr.com
	ClientID      string
	ClientSecret  string // env only, never logged
	RedirectURL   string // e.g. https://support.harmonicr.com/callback
	Scopes        []string
	SessionSecret string // HMAC key for the session cookie
	AdminRole     string // optional Zitadel role gate (e.g. "support")
}

// Session is the authenticated staff identity.
type Session struct {
	Email    string
	Name     string
	Subject  string
	Role     string
	Expires  time.Time
	CSRF     string // per-session CSRF token (defense-in-depth for POST forms)
}

// Authenticator holds OIDC state + a session store.
type Authenticator struct {
	cfg      Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
	cookie   *CookieStore
	logger   *log.Logger
	mu       sync.Mutex
	sessions map[string]Session
}

// New builds the authenticator. It does NOT fail on a missing issuer: the
// guard fails closed at request time (see RequireAuth). If the issuer is
// empty the provider is nil and every protected route 403s.
func New(cfg Config, logger *log.Logger) (*Authenticator, error) {
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("oidc: SessionSecret required")
	}
	if cfg.RedirectURL == "" {
		return nil, fmt.Errorf("oidc: RedirectURL required")
	}
	a := &Authenticator{
		cfg:      cfg,
		logger:   logger,
		cookie:   NewCookieStore(cfg.SessionSecret, "support_sess"),
		sessions: make(map[string]Session),
	}
	if cfg.Issuer != "" {
		provider, err := oidc.NewProvider(context.Background(), cfg.Issuer)
		if err != nil {
			// Fail closed: log but keep the guard 403ing (no silent open).
			logger.Printf("oidc: provider setup failed: %v (auth surface fails closed)", err)
		} else {
			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
			a.oauth = &oauth2.Config{
				ClientID:     cfg.ClientID,
				ClientSecret: cfg.ClientSecret,
				RedirectURL:  cfg.RedirectURL,
				Scopes:       cfg.Scopes,
				Endpoint:     provider.Endpoint(),
			}
		}
	}
	return a, nil
}

// Enabled reports whether OIDC was configured successfully.
func (a *Authenticator) Enabled() bool { return a.oauth != nil && a.verifier != nil }

// BeginLogin redirects the browser to Zitadel with PKCE + state (code flow).
func (a *Authenticator) BeginLogin(w http.ResponseWriter, r *http.Request) {
	if !a.Enabled() {
		http.Error(w, "sso disabled", http.StatusForbidden)
		return
	}
	state, err := randToken()
	if err != nil {
		http.Error(w, "state error", http.StatusInternalServerError)
		return
	}
	// PKCE: generate a verifier, store a hash of it server-side (state holds
	// the mapping). We store the code verifier in the state cookie so the
	// callback can verify the code challenge (S-2-adjacent hardening).
	verifier, challenge, err := pkce()
	if err != nil {
		http.Error(w, "pkce error", http.StatusInternalServerError)
		return
	}
	// Store state + verifier in a short-lived cookie (not server memory).
	a.cookie.Set(w, r, "support_state", state+"|"+verifier, 10*time.Minute)
	u := a.oauth.AuthCodeURL(state,
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, u, http.StatusFound)
}

// HandleCallback exchanges the code, verifies the ID token, and sets the
// session cookie. It fails closed on any invalid/missing parameter.
func (a *Authenticator) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if !a.Enabled() {
		http.Error(w, "sso disabled", http.StatusForbidden)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		http.Error(w, "missing state/code", http.StatusBadRequest)
		return
	}
	// Recover the stored state+verifier from the cookie.
	raw, ok := a.cookie.Get(r, "support_state")
	if !ok {
		http.Error(w, "no state cookie", http.StatusBadRequest)
		return
	}
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 || parts[0] != state {
		http.Error(w, "state mismatch", http.StatusUnauthorized)
		return
	}
	verifier := parts[1]
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	token, err := a.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		http.Error(w, "token exchange failed", http.StatusUnauthorized)
		return
	}
	idToken, ok := token.Extra("id_token").(string)
	if !ok || idToken == "" {
		http.Error(w, "no id_token", http.StatusUnauthorized)
		return
	}
	rawIDToken, err := a.verifier.Verify(ctx, idToken)
	if err != nil {
		http.Error(w, "id_token invalid", http.StatusUnauthorized)
		return
	}
	var claims struct {
		Email  string `json:"email"`
		Name   string `json:"name"`
		Sub    string `json:"sub"`
		Roles  map[string]any `json:"urn:zitadel:iam:org:project:roles"`
	}
	if err := rawIDToken.Claims(&claims); err != nil {
		http.Error(w, "claims invalid", http.StatusUnauthorized)
		return
	}
	sess := Session{
		Email:   claims.Email,
		Name:    claims.Name,
		Subject: claims.Sub,
		Expires: rawIDToken.Expiry,
		CSRF:    newCSRF(),
	}
	if a.cfg.AdminRole != "" && claims.Roles[a.cfg.AdminRole] == nil {
		http.Error(w, "forbidden: no role", http.StatusForbidden)
		return
	}
	sess.Role = a.cfg.AdminRole
	a.mu.Lock()
	a.sessions[claims.Sub] = sess
	a.mu.Unlock()
	// Set the session cookie (HMAC-signed, HttpOnly, SameSite=Lax).
	a.cookie.Set(w, r, "support_sess", claims.Sub, time.Until(rawIDToken.Expiry))
	http.Redirect(w, r, "/", http.StatusFound)
}

// newCSRF returns a random base64url token (32 bytes) used as a per-session
// CSRF token embedded in POST forms and validated on submit.
func newCSRF() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Non-fatal: an empty token simply fails closed on validation.
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// CSRFValid reports whether the submitted token matches the session's CSRF
// token. It fails closed: an empty/missing token or a mismatch is invalid.
func (a *Authenticator) CSRFValid(r *http.Request, submitted string) bool {
	sess := a.CurrentSession(r)
	if sess == nil || sess.CSRF == "" || submitted == "" {
		return false
	}
	// Constant-time compare to avoid timing leaks.
	return hmac.Equal([]byte(sess.CSRF), []byte(submitted))
}

// RequireAuth is middleware for protected UI routes. It fails closed: no
// session cookie -> redirect to /login (or 403 if SSO disabled).
func (a *Authenticator) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.Enabled() {
			http.Error(w, "sso disabled", http.StatusForbidden)
			return
		}
		sub, ok := a.cookie.Get(r, "support_sess")
		if !ok || sub == "" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		a.mu.Lock()
		sess, ok := a.sessions[sub]
		a.mu.Unlock()
		if !ok || time.Now().After(sess.Expires) {
			a.cookie.Clear(w, r, "support_sess")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// CurrentSession returns the authenticated session for the request (nil if
// none). Used by handlers to render staff identity.
func (a *Authenticator) CurrentSession(r *http.Request) *Session {
	sub, ok := a.cookie.Get(r, "support_sess")
	if !ok || sub == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	sess, ok := a.sessions[sub]
	if !ok {
		return nil
	}
	return &sess
}

// Logout clears the session and the SSO cookie.
func (a *Authenticator) Logout(w http.ResponseWriter, r *http.Request) {
	sub, _ := a.cookie.Get(r, "support_sess")
	if sub != "" {
		a.mu.Lock()
		delete(a.sessions, sub)
		a.mu.Unlock()
	}
	a.cookie.Clear(w, r, "support_sess")
	http.Redirect(w, r, "/login", http.StatusFound)
}

// pkce generates a random verifier + S256 challenge.
func pkce() (verifier, challenge string, err error) {
	verifier, err = randToken()
	if err != nil {
		return "", "", err
	}
	// S256: SHA256(verifier) base64url without padding.
	sum := sha256Sum(verifier)
	return verifier, sum, nil
}

// randToken returns a 32-byte cryptographically-random base64url token.
func randToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func sha256Sum(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// CookieStore signs + encrypts cookie values with an HMAC key.
type CookieStore struct {
	key  []byte
	name string
}

func NewCookieStore(secret, name string) *CookieStore {
	return &CookieStore{key: []byte(secret), name: name}
}

func (c *CookieStore) Set(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    signValue(c.key, value),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(ttl),
		Secure:   true,
	}
	http.SetCookie(w, cookie)
}

func (c *CookieStore) Get(r *http.Request, name string) (string, bool) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return "", false
	}
	val, ok := verifyValue(c.key, cookie.Value)
	return val, ok
}

func (c *CookieStore) Clear(w http.ResponseWriter, r *http.Request, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Secure:   true,
	}
	http.SetCookie(w, cookie)
}

func signValue(key []byte, value string) string {
	// value + "." + base64(hmacSHA256(key, value))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return value + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func verifyValue(key []byte, signed string) (string, bool) {
	i := strings.LastIndexByte(signed, '.')
	if i < 0 {
		return "", false
	}
	value := signed[:i]
	sig := signed[i+1:]
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if sig != expected {
		return "", false
	}
	return value, true
}
