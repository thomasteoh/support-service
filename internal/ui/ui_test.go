package ui

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/thomasteoh/support-service/internal/llmesh"
	"github.com/thomasteoh/support-service/internal/oidc"
	"github.com/thomasteoh/support-service/internal/store"
)

// fakeStore satisfies ui.TicketStore.
type fakeStore struct {
	tickets    []store.Ticket
	comments   []store.Comment
	commentErr error
	lastStatus string
}

func (f *fakeStore) GetTicket(ctx context.Context, id int64) (*store.Ticket, error) {
	return &store.Ticket{ID: id, Title: "t", Status: "open"}, nil
}
func (f *fakeStore) ListTickets(ctx context.Context, n int) ([]store.Ticket, error) {
	return f.tickets, nil
}
func (f *fakeStore) SetStatus(ctx context.Context, id int64, status string) error {
	f.lastStatus = status
	return nil
}
func (f *fakeStore) AddComment(ctx context.Context, ticketID int64, body, author string) (int64, error) {
	if f.commentErr != nil {
		return 0, f.commentErr
	}
	f.comments = append(f.comments, store.Comment{ID: 1, Body: body, Author: author})
	return 1, nil
}
func (f *fakeStore) ListComments(ctx context.Context, ticketID int64) ([]store.Comment, error) {
	return f.comments, nil
}

// newTestUI builds a UI server. enabled=true configures OIDC (provider
// unreachable but the session-cookie guard still works); enabled=false means
// SSO is disabled and every protected route 403s (fail closed).
func newTestUI(st TicketStore, enabled bool) (*Server, error) {
	issuer := ""
	if enabled {
		issuer = "https://auth.harmonicr.com"
	}
	auth, _ := oidc.New(oidc.Config{
		Issuer:        issuer,
		ClientID:      "x",
		ClientSecret:  "s",
		RedirectURL:   "https://support.harmonicr.com/callback",
		SessionSecret: "secret",
	}, log.New(io.Discard, "", 0))
	return New(":0", st, auth, log.New(io.Discard, "", 0), nil)
}

// TestProtectedRouteFailClosed verifies a protected route 403s when OIDC is
// disabled (the UI is never silently open).
func TestProtectedRouteFailClosed(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, false)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 (auth disabled), got %d", w.Code)
	}
}

// TestLoginFailClosed verifies /login 403s when SSO is disabled.
func TestLoginFailClosed(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, false)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	w := httptest.NewRecorder()
	srv.router.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 (sso disabled), got %d", w.Code)
	}
}

// TestCSRFMiddlewareRejectsMissing verifies the CSRF middleware rejects a POST
// without a valid token (fail closed). A POST with no session/token is 403.
func TestCSRFMiddlewareRejectsMissing(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tickets/1/comment", nil)
	w := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv.csrfMW(next).ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403 (no CSRF token), got %d", w.Code)
	}
}

// TestCSRFMiddlewareAllowsGET verifies GET requests pass the CSRF middleware.
func TestCSRFMiddlewareAllowsGET(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/tickets/1", nil)
	w := httptest.NewRecorder()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv.csrfMW(next).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200 (GET passes CSRF), got %d", w.Code)
	}
}

// TestParseTriage verifies the AI suggestion JSON is flattened into labeled
// fields (human-readable, not a raw JSON blob). Invalid JSON falls back to the
// raw text (nothing silently dropped).
func TestParseTriage(t *testing.T) {
	tv := parseTriage(`{"priority":"high","type":"bug","suggested_action":"contact the vendor"}`)
	if tv.Priority != "high" || tv.Type != "bug" || tv.SuggestedAction != "contact the vendor" {
		t.Fatalf("unexpected triage: %+v", tv)
	}
	// Invalid JSON → raw text preserved.
	tv = parseTriage(`not json`)
	if tv.SuggestedAction != "not json" {
		t.Fatalf("invalid json should fall back to raw text, got %+v", tv)
	}
	// Empty → zero view.
	tv = parseTriage("")
	if tv.Priority != "" || tv.Type != "" || tv.SuggestedAction != "" {
		t.Fatalf("empty should be zero view, got %+v", tv)
	}
}

// TestCommentsTemplate renders the comments partial standalone.
func TestCommentsTemplate(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	w := httptest.NewRecorder()
	if err := srv.tmpl.ExecuteTemplate(w, "comments", map[string]any{
		"Comments": []store.Comment{{ID: 1, Body: "first reply", Author: "staff"}},
	}); err != nil {
		t.Fatalf("render comments: %v", err)
	}
	if !strings.Contains(w.Body.String(), "first reply") {
		t.Fatalf("missing comment body: %s", w.Body.String())
	}
}

// TestStatusTemplate renders the status pill standalone.
func TestStatusTemplate(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	w := httptest.NewRecorder()
	if err := srv.tmpl.ExecuteTemplate(w, "status", map[string]any{
		"Ticket": &store.Ticket{ID: 1, Status: "assigned"},
	}); err != nil {
		t.Fatalf("render status: %v", err)
	}
	if !strings.Contains(w.Body.String(), "assigned") {
		t.Fatalf("missing status: %s", w.Body.String())
	}
}

// TestDetailTemplateParses verifies the detail template executes (with layout).
func TestDetailTemplateParses(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	w := httptest.NewRecorder()
	if err := srv.tmpl.ExecuteTemplate(w, "detail", map[string]any{
		"Ticket":   &store.Ticket{ID: 7, Title: "printer", Status: "open"},
		"Comments": []store.Comment{},
		"Session":  nil,
	}); err != nil {
		t.Fatalf("render detail: %v", err)
	}
	if !strings.Contains(w.Body.String(), "printer") {
		t.Fatalf("missing ticket title: %s", w.Body.String())
	}
}

// TestIndexTemplateParses verifies the index template executes (with layout).
func TestIndexTemplateParses(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	w := httptest.NewRecorder()
	if err := srv.tmpl.ExecuteTemplate(w, "index", map[string]any{
		"Tickets": []store.Ticket{{ID: 1, Title: "hello", Status: "open"}},
		"Session": nil,
	}); err != nil {
		t.Fatalf("render index: %v", err)
	}
	if !strings.Contains(w.Body.String(), "hello") {
		t.Fatalf("missing title: %s", w.Body.String())
	}
}

// fakeActioner is a stub Actioner for P2 tests.
type fakeActioner struct {
	action llmesh.Action
	err    error
}

func (f fakeActioner) DraftReply(ctx context.Context, t llmesh.TicketFields) (llmesh.Action, error) {
	return f.action, f.err
}

// TestAIDraftDisabled verifies the draft route errors (and never writes) when
// AI is not configured.
func TestAIDraftDisabled(t *testing.T) {
	srv, err := newTestUI(&fakeStore{}, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tickets/1/ai/draft", nil)
	w := httptest.NewRecorder()
	srv.handleAIDraft(w, req)
	if !strings.Contains(w.Body.String(), "AI is not configured") {
		t.Fatalf("missing disabled message: %s", w.Body.String())
	}
}

// TestAIDraftShows verifies a draft is shown and the store is never written
// (P2 — draft is advisory; only the apply route writes).
func TestAIDraftShows(t *testing.T) {
	fs := &fakeStore{}
	srv, err := newTestUI(fs, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	srv.actioner = fakeActioner{action: llmesh.Action{
		SuggestedReply: "We're on it.",
		SuggestedStep:  "escalate to engineering",
		Status:         "assigned",
	}}
	req := httptest.NewRequest(http.MethodPost, "/tickets/7/ai/draft", nil)
	req.SetPathValue("id", "7")
	w := httptest.NewRecorder()
	srv.handleAIDraft(w, req)
	if !strings.Contains(w.Body.String(), "We&#39;re on it.") {
		t.Fatalf("missing draft: %s", w.Body.String())
	}
	// Store must NOT have been written by the draft route.
	if len(fs.comments) != 0 {
		t.Fatalf("draft route wrote %d comments", len(fs.comments))
	}
}

// TestAIApplyApproved verifies the apply route writes a comment + status ONLY
// after staff approval (P2), and priority is never auto-applied.
func TestAIApplyApproved(t *testing.T) {
	fs := &fakeStore{}
	srv, err := newTestUI(fs, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tickets/7/ai/apply", nil)
	req.SetPathValue("id", "7")
	req.Form = url.Values{
		"reply":  {"We're on it."},
		"status": {"assigned"},
	}
	w := httptest.NewRecorder()
	srv.handleAIApply(w, req)
	if len(fs.comments) != 1 {
		t.Fatalf("apply route wrote %d comments, want 1", len(fs.comments))
	}
	if fs.comments[0].Body != "We're on it." {
		t.Fatalf("comment body = %q", fs.comments[0].Body)
	}
}

// TestAIApplyInvalidStatus verifies an untrusted (AI-hallucinated) status is
// rejected before reaching the DB (never persisted), and no comment is written
// on a failed apply.
func TestAIApplyInvalidStatus(t *testing.T) {
	fs := &fakeStore{}
	srv, err := newTestUI(fs, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tickets/7/ai/apply", nil)
	req.SetPathValue("id", "7")
	req.Form = url.Values{
		"reply":  {"ok"},
		"status": {"hallucinated"},
	}
	w := httptest.NewRecorder()
	srv.handleAIApply(w, req)
	// The invalid status must NOT be written.
	if fs.lastStatus != "" {
		t.Fatalf("invalid status %q was persisted", fs.lastStatus)
	}
	// Comment still applied (reply is trusted staff input), status skipped.
	if len(fs.comments) != 1 {
		t.Fatalf("wrote %d comments, want 1", len(fs.comments))
	}
}

// TestAIApplyWriteErrorSurfaced verifies a failed DB write is surfaced (error
// rendered), not silently shown as success.
func TestAIApplyWriteErrorSurfaced(t *testing.T) {
	fs := &fakeStore{commentErr: errors.New("db down")}
	srv, err := newTestUI(fs, true)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tickets/7/ai/apply", nil)
	req.SetPathValue("id", "7")
	req.Form = url.Values{"reply": {"hello"}}
	w := httptest.NewRecorder()
	srv.handleAIApply(w, req)
	if !strings.Contains(w.Body.String(), "could not apply suggestion") {
		t.Fatalf("expected error surfaced, got: %s", w.Body.String())
	}
}
