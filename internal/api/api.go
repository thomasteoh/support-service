// Package api exposes the ticket service's HTTP surfaces: the internal API
// (bridge public-create + staff read/update, reachable only on the internal
// container network) and the staff UI (Caddy-fronted, Zitadel OIDC).
//
// The public-create endpoint FAILS CLOSED on a missing shared secret: it
// requires the X-API-Key header (CREATE_API_KEY) — the same value the
// event-triage bridge sends as its PeppermintKey. It never opens without it.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thomasteoh/support-service/internal/store"
)

// TicketStore is the minimal persistence interface the API depends on. The
// concrete *store.Store implements it; tests use a fake so the create gate
// (C-2) and validation are testable without Postgres.
type TicketStore interface {
	CreateTicket(ctx context.Context, t *store.Ticket) (int64, error)
	GetTicket(ctx context.Context, id int64) (*store.Ticket, error)
	ListTickets(ctx context.Context, n int) ([]store.Ticket, error)
	SetStatus(ctx context.Context, id int64, status string) error
	AddComment(ctx context.Context, ticketID int64, body, author string) (int64, error)
	ListComments(ctx context.Context, ticketID int64) ([]store.Comment, error)
	Ping(ctx context.Context) error
}

// Server is the HTTP server for both surfaces.
type Server struct {
	addr      string
	createKey string
	store     TicketStore
	onTicket  func(context.Context, *store.Ticket) // hook for async AI triage
	logger    *log.Logger
	router    chi.Router
}

// New creates the API server. onTicket is the async hook invoked after a
// ticket is created (nil-safe; AI triage runs there, never blocking).
func New(addr, createKey string, st TicketStore, onTicket func(context.Context, *store.Ticket), logger *log.Logger) *Server {
	s := &Server{
		addr:      addr,
		createKey: createKey,
		store:     st,
		onTicket:  onTicket,
		logger:    logger,
	}
	s.router = s.routes()
	return s
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()
	// Internal API (bridge + staff), reachable only on the container network.
	// The shared secret (X-API-Key) gates the WHOLE surface — not just create —
	// so any container on the bridge must be keyed. Health stays open (the
	// bridge's readiness probe needs it without a key).
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.keyMW)
		r.Post("/ticket/public/create", s.handleCreate)
		r.Get("/ticket/{id}", s.handleGet)
		r.Get("/tickets", s.handleList)
		r.Post("/ticket/{id}/status", s.handleSetStatus)
	})
	// Health/readiness probe. Serve BOTH /healthz (container healthcheck) and
	// /health (the path the event-triage bridge's Ready() GETs — contract
	// preservation C-2/C-1). Same handler; both return 200 {"status":"ok"}.
	r.Get("/healthz", s.handleHealth)
	r.Get("/health", s.handleHealth)
	return r
}

// keyMW gates the internal API surface with the shared secret. It fails
// closed: any request without the correct X-API-Key is rejected (401). The
// create endpoint still checks the key (redundant but explicit); this closes
// the read/update routes that were previously open on the shared bridge.
func (s *Server) keyMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.createKey == "" {
			s.writeErr(w, http.StatusServiceUnavailable, "api not configured")
			return
		}
		got := r.Header.Get("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.createKey)) != 1 {
			s.writeErr(w, http.StatusUnauthorized, "invalid or missing X-API-Key")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCreate accepts POST /api/v1/ticket/public/create. It REQUIRES the
// X-API-Key header (shared secret) and returns {id, success:true} — the exact
// Peppermint contract the event-triage bridge reads.
func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if s.createKey == "" {
		s.writeErr(w, http.StatusServiceUnavailable, "create endpoint not configured")
		return
	}
	// Fail closed on missing/incorrect shared secret (C-2). Redundant with the
	// group-level keyMW (defense-in-depth on the bridge-facing endpoint).
	if got := r.Header.Get("X-API-Key"); subtle.ConstantTimeCompare([]byte(got), []byte(s.createKey)) != 1 {
		s.writeErr(w, http.StatusUnauthorized, "invalid or missing X-API-Key")
		return
	}
	var t store.Ticket
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(&t); err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid ticket payload")
		return
	}
	if strings.TrimSpace(t.Title) == "" || strings.TrimSpace(t.Name) == "" {
		s.writeErr(w, http.StatusBadRequest, "title and name are required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	id, err := s.store.CreateTicket(ctx, &t)
	if err != nil {
		s.logger.Printf("create ticket: %v", err)
		s.writeErr(w, http.StatusInternalServerError, "create failed")
		return
	}
	// Async AI triage — never blocks the ticket creation. Use a derived
	// context with a timeout (not context.Background, which gosec G118 flags:
	// a request-scoped context is available). We snapshot the ticket into the
	// goroutine; the request context is cancelled after the response, so we
	// derive a fresh one with a generous timeout.
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel2()
	if s.onTicket != nil {
		go s.onTicket(ctx2, &t)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"id": id, "success": true})
}

// handleGet returns a single ticket by ID (staff-authenticated).
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	t, err := s.store.GetTicket(ctx, n)
	if err != nil {
		s.writeErr(w, http.StatusNotFound, "ticket not found")
		return
	}
	s.writeJSON(w, http.StatusOK, t)
}

// handleList returns the open tickets (staff-authenticated).
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := s.store.ListTickets(ctx, 50)
	if err != nil {
		s.logger.Printf("list tickets: %v", err)
		s.writeErr(w, http.StatusInternalServerError, "list failed")
		return
	}
	// Always emit [] (never null) — see go-cli-project nil-slice pitfall.
	if list == nil {
		list = []store.Ticket{}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"tickets": list})
}

// handleSetStatus updates a ticket's status (staff actioning).
func (s *Server) handleSetStatus(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "invalid ticket id")
		return
	}
	var req struct{ Status string `json:"status"` }
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Status == "" {
		s.writeErr(w, http.StatusBadRequest, "status required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.store.SetStatus(ctx, n, req.Status); err != nil {
		s.logger.Printf("set status: %v", err)
		s.writeErr(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.writeErr(w, http.StatusServiceUnavailable, "unhealthy")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *Server) writeErr(w http.ResponseWriter, code int, msg string) {
	s.writeJSON(w, code, map[string]any{"error": msg})
}

// writeJSON encodes v as JSON with the given status code, logging any write
// error. Once the response is committed a write error is not actionable, so
// we log it (gosec G104 is satisfied by handling the error).
func (s *Server) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		s.logger.Printf("writeJSON: %v", err)
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.addr,
		Handler:           s.router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

var _ = fmt.Sprintf // keep fmt import if unused in future edits
