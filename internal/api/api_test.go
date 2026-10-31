package api

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/thomasteoh/support-service/internal/store"
)

// fakeStore is a minimal TicketStore for tests (no Postgres needed).
type fakeStore struct {
	created []*store.Ticket
}

func (f *fakeStore) CreateTicket(ctx context.Context, t *store.Ticket) (int64, error) {
	f.created = append(f.created, t)
	return 42, nil
}
func (f *fakeStore) GetTicket(ctx context.Context, id int64) (*store.Ticket, error) {
	return &store.Ticket{ID: id}, nil
}
func (f *fakeStore) ListTickets(ctx context.Context, n int) ([]store.Ticket, error) {
	return []store.Ticket{{ID: 1, Title: "t"}}, nil
}
func (f *fakeStore) SetStatus(ctx context.Context, id int64, status string) error { return nil }
func (f *fakeStore) AddComment(ctx context.Context, ticketID int64, body, author string) (int64, error) {
	return 1, nil
}
func (f *fakeStore) ListComments(ctx context.Context, ticketID int64) ([]store.Comment, error) {
	return []store.Comment{{ID: 1, Body: "hi", Author: "staff"}}, nil
}
func (f *fakeStore) Ping(ctx context.Context) error { return nil }

func newTestServer(key string, st TicketStore, on func(context.Context, *store.Ticket)) *Server {
	return New(":0", key, st, on, log.New(io.Discard, "", 0))
}

// TestCreateRequiresSecret verifies C-2: a request without the correct
// X-API-Key is rejected (401); with it, the ticket is created.
func TestCreateRequiresSecret(t *testing.T) {
	fs := &fakeStore{}
	s := newTestServer("secret-key", fs, nil)

	payload := `{"title":"hi","name":"a","detail":"d","priority":"normal","type":"support"}`
	body := bytes.NewBufferString(payload)

	// No X-API-Key header -> 401, no insert.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ticket/public/create", body)
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no key: want 401, got %d", w.Code)
	}
	if len(fs.created) != 0 {
		t.Fatalf("no key: store should be untouched, got %d inserts", len(fs.created))
	}

	// Wrong key -> 401.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ticket/public/create", bytes.NewBufferString(payload))
	req.Header.Set("X-API-Key", "wrong")
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong key: want 401, got %d", w.Code)
	}

	// Correct key -> 200, {id, success:true}, one insert.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ticket/public/create", bytes.NewBufferString(payload))
	req.Header.Set("X-API-Key", "secret-key")
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("good key: want 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"success":true`) || !strings.Contains(w.Body.String(), `"id":42`) {
		t.Fatalf("bad response body: %s", w.Body.String())
	}
	if len(fs.created) != 1 {
		t.Fatalf("want 1 insert, got %d", len(fs.created))
	}
}

// TestCreateValidation verifies required-field checks: empty title/name -> 400.
func TestCreateValidation(t *testing.T) {
	s := newTestServer("secret-key", &fakeStore{}, nil)
	for name, payload := range map[string]string{
		"empty title": `{"title":"","name":"a","detail":"d"}`,
		"empty name":  `{"title":"t","name":"","detail":"d"}`,
		"garbage":     `{not json`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ticket/public/create", bytes.NewBufferString(payload))
		req.Header.Set("X-API-Key", "secret-key")
		w := httptest.NewRecorder()
		s.router.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: want 400, got %d", name, w.Code)
		}
	}
}

// TestAPISurfaceGated verifies the WHOLE /api/v1 surface (not just create)
// requires the shared secret — the read/update routes are no longer open on
// the shared bridge. Health stays open (readiness probe needs no key).
func TestAPISurfaceGated(t *testing.T) {
	s := newTestServer("secret-key", &fakeStore{}, nil)
	// GET /ticket/{id} without key -> 401.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ticket/1", nil)
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("get no key: want 401, got %d", w.Code)
	}
	// GET /ticket/{id} with key -> 200.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/ticket/1", nil)
	req.Header.Set("X-API-Key", "secret-key")
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("get with key: want 200, got %d", w.Code)
	}
	// POST /ticket/1/status without key -> 401.
	req = httptest.NewRequest(http.MethodPost, "/api/v1/ticket/1/status", bytes.NewBufferString(`{"status":"assigned"}`))
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status no key: want 401, got %d", w.Code)
	}
	// Health stays open (no key needed).
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health: want 200, got %d", w.Code)
	}
	// The bridge's documented health path is /health — it must also 200 (the
	// bridge's Ready() GETs it; contract preservation C-2/C-1).
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	w = httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("health alias: want 200, got %d", w.Code)
	}
}

// TestHealth verifies the health probe returns 200 when the store pings OK.
func TestHealth(t *testing.T) {
	s := newTestServer("secret-key", &fakeStore{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
}

// TestOnTicketAsync verifies the AI hook is invoked (async) after creation.
func TestOnTicketAsync(t *testing.T) {
	fs := &fakeStore{}
	called := make(chan *store.Ticket, 1)
	s := newTestServer("secret-key", fs, func(_ context.Context, t *store.Ticket) {
		called <- t
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ticket/public/create",
		bytes.NewBufferString(`{"title":"t","name":"a"}`))
	req.Header.Set("X-API-Key", "secret-key")
	w := httptest.NewRecorder()
	s.router.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	select {
	case got := <-called:
		if got.Title != "t" {
			t.Fatalf("hook got title %q", got.Title)
		}
	case <-time.After(time.Second):
		t.Fatal("AI hook was not called within 1s")
	}
}
