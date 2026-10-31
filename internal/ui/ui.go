// Package ui serves the staff helpdesk UI. Server-rendered Go templates +
// htmx (locked O-02), authenticated via Zitadel OIDC cookie session (O-04).
//
// Every route is wrapped in RequireAuth EXCEPT /login, /callback, and /logout.
// The login surface FAILS CLOSED: if OIDC is disabled, /login and /callback
// 403 so the UI is never silently open.
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/thomasteoh/support-service/internal/llmesh"
	"github.com/thomasteoh/support-service/internal/oidc"
	"github.com/thomasteoh/support-service/internal/store"
)

//go:embed templates/*.html
var templatesFS embed.FS

// TicketStore is the persistence the UI reads/writes.
type TicketStore interface {
	GetTicket(ctx context.Context, id int64) (*store.Ticket, error)
	ListTickets(ctx context.Context, n int) ([]store.Ticket, error)
	SetStatus(ctx context.Context, id int64, status string) error
	AddComment(ctx context.Context, ticketID int64, body, author string) (int64, error)
	ListComments(ctx context.Context, ticketID int64) ([]store.Comment, error)
}

// Actioner drafts a staff-facing AI suggestion for a ticket. It is advisory
// and non-mutating; the UI shows the draft and requires explicit staff
// approval before applying (P2 — staff approves before any write).
type Actioner interface {
	DraftReply(ctx context.Context, t llmesh.TicketFields) (llmesh.Action, error)
}

// Server is the helpdesk UI server.
type Server struct {
	addr      string
	store     TicketStore
	actioner  Actioner
	auth      *oidc.Authenticator
	logger    *log.Logger
	router    chi.Router
	tmpl      *template.Template
}

// New creates the UI server. auth must be non-nil (auth fails closed).
// actioner may be nil (AI disabled) — the draft route then shows an error and
// never writes.
func New(addr string, st TicketStore, auth *oidc.Authenticator, logger *log.Logger, actioner Actioner) (*Server, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s := &Server{
		addr:     addr,
		store:    st,
		actioner: actioner,
		auth:     auth,
		logger:   logger,
		tmpl:     tmpl,
	}
	s.router = s.routes()
	return s, nil
}

func (s *Server) routes() chi.Router {
	r := chi.NewRouter()
	// Public (login flow).
	r.Get("/login", s.handleLogin)
	r.Get("/login/start", s.auth.BeginLogin)
	r.Get("/callback", s.auth.HandleCallback)
	r.Get("/logout", s.auth.Logout)
	// Protected (staff).
	r.Group(func(r chi.Router) {
		r.Use(s.authMW)
		r.Use(s.csrfMW)
		r.Get("/", s.handleIndex)
		r.Get("/tickets", s.handleList)
		r.Get("/tickets/{id}", s.handleDetail)
		r.Post("/tickets/{id}/ai/draft", s.handleAIDraft)
		r.Post("/tickets/{id}/ai/apply", s.handleAIApply)
		r.Post("/tickets/{id}/comment", s.handleComment)
		r.Post("/tickets/{id}/status", s.handleStatus)
		r.Get("/tickets/{id}/comments", s.handleCommentsPartial) // htmx swap
	})
	return r
}

// authMW adapts the oidc.RequireAuth middleware for chi's Use signature.
func (s *Server) authMW(next http.Handler) http.Handler {
	return http.HandlerFunc(s.auth.RequireAuth(next.ServeHTTP))
}

// csrfMW validates the per-session CSRF token on POST requests. It fails
// closed: any POST without a valid token is rejected. GET requests pass
// through untouched. This is defense-in-depth over the OIDC session guard.
func (s *Server) csrfMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		if !s.auth.CSRFValid(r, r.FormValue("csrf_token")) {
			http.Error(w, "csrf token invalid", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleLogin shows the SSO entry page.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !s.auth.Enabled() {
		http.Error(w, "sso disabled", http.StatusForbidden)
		return
	}
	// If already logged in, go straight to the UI.
	if s.auth.CurrentSession(r) != nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	s.render(w, "login", map[string]any{
		"SSOURL": "/callback", // BeginLogin is invoked via the /login form
		"Error":  r.URL.Query().Get("error"),
	})
}

// handleIndex lists the open tickets.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := s.store.ListTickets(ctx, 50)
	if err != nil {
		s.logger.Printf("list: %v", err)
		s.render(w, "error", map[string]any{"Error": "could not load tickets"})
		return
	}
	if list == nil {
		list = []store.Ticket{}
	}
	s.render(w, "index", map[string]any{
		"Tickets": list,
		"Session": s.auth.CurrentSession(r),
	})
}

// handleDetail shows one ticket + its comments.
func (s *Server) handleDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	t, err := s.store.GetTicket(ctx, id)
	if err != nil {
		s.render(w, "error", map[string]any{"Error": "ticket not found"})
		return
	}
	comments, _ := s.store.ListComments(ctx, id)
	if comments == nil {
		comments = []store.Comment{}
	}
	s.render(w, "detail", map[string]any{
		"Ticket":   t,
		"Comments": comments,
		"Session":  s.auth.CurrentSession(r),
		"CSRF":     s.csrfToken(r),
		"Triage":   parseTriage(t.AISuggestion),
	})
}

// csrfToken returns the current session's CSRF token for embedding in POST
// forms (empty if no session, which fails closed on submit).
func (s *Server) csrfToken(r *http.Request) string {
	sess := s.auth.CurrentSession(r)
	if sess == nil {
		return ""
	}
	return sess.CSRF
}

// TriageView is the human-readable rendering of an AI triage suggestion. The
// stored value is JSON (e.g. {"priority":"high","type":"bug","suggested_action":"..."});
// this flattens it into labeled fields so staff see prose, not a JSON blob.
type TriageView struct {
	Priority        string
	Type            string
	SuggestedAction string
}

// parseTriage parses a raw AI suggestion JSON string into a TriageView. On
// parse failure it returns the raw text (so nothing is silently dropped).
func parseTriage(raw string) TriageView {
	var v struct {
		Priority        string `json:"priority"`
		Type            string `json:"type"`
		SuggestedAction string `json:"suggested_action"`
	}
	if raw == "" {
		return TriageView{}
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		// Not valid JSON — show it as-is (still auto-escaped by the template).
		return TriageView{SuggestedAction: raw}
	}
	return TriageView{Priority: v.Priority, Type: v.Type, SuggestedAction: v.SuggestedAction}
}

// handleList returns the ticket list as an htmx partial.
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	list, err := s.store.ListTickets(ctx, 50)
	if err != nil {
		s.logger.Printf("list: %v", err)
		return
	}
	if list == nil {
		list = []store.Ticket{}
	}
	s.render(w, "ticket-list", map[string]any{"Tickets": list})
}

// handleCommentsPartial returns the comments list as an htmx partial.
func (s *Server) handleCommentsPartial(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	comments, err := s.store.ListComments(ctx, id)
	if err != nil {
		s.logger.Printf("comments: %v", err)
		return
	}
	if comments == nil {
		comments = []store.Comment{}
	}
	s.render(w, "comments", map[string]any{"Comments": comments, "CSRF": s.csrfToken(r)})
}

// handleAIDraft generates an AI suggestion for a ticket and shows it. It
// never writes — the returned draft is advisory only (P2).
func (s *Server) handleAIDraft(w http.ResponseWriter, r *http.Request) {
	if s.actioner == nil {
		s.renderAIDraft(w, map[string]any{"Error": "AI is not configured", "TicketID": chi.URLParam(r, "id"), "CSRF": s.csrfToken(r)})
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.store.GetTicket(r.Context(), id)
	if err != nil {
		s.renderAIDraft(w, map[string]any{"Error": "ticket not found", "TicketID": id})
		return
	}
	act, err := s.actioner.DraftReply(r.Context(), llmesh.TicketFields{
		Title: t.Title, Detail: t.Detail, Priority: t.Priority,
		Type: t.Type, Status: t.Status,
	})
	if err != nil {
		s.logger.Printf("ai draft: %v", err)
		s.renderAIDraft(w, map[string]any{"Error": "could not draft: " + err.Error(), "TicketID": id, "CSRF": s.csrfToken(r)})
		return
	}
	s.renderAIDraft(w, map[string]any{"Action": act, "TicketID": id, "CSRF": s.csrfToken(r)})
}

// renderAIDraft renders the ai-draft partial (htmx swap target).
func (s *Server) renderAIDraft(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "ai-draft", data); err != nil {
		s.logger.Printf("ai draft render: %v", err)
	}
}

// handleAIApply applies an AI suggestion ONLY after staff approval: it writes
// a comment and optionally updates status, then returns the refreshed comments
// partial (P2 — staff approves before any write).
func (s *Server) handleAIApply(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	reply := r.FormValue("reply")
	step := r.FormValue("step")
	status := r.FormValue("status")
	if reply == "" && step == "" {
		s.logger.Printf("ai apply %d: empty action", id)
		return
	}
	// Staff-approved: write the reply as a comment (if any) and set status (if
	// any). Priority changes are NOT auto-applied (staff sets those manually).
	// The AI status is UNTRUSTED — whitelist it against the known set before
	// writing; on mismatch, skip the status change (never write an invalid
	// value from model output).
	var statusErr error
	if status != "" {
		if !validStatus(status) {
			s.logger.Printf("ai apply %d: rejecting invalid status %q", id, status)
			status = "" // never persist an untrusted status
		} else {
			statusErr = s.store.SetStatus(r.Context(), id, status)
		}
	}
	var commentErr error
	if reply != "" {
		_, commentErr = s.store.AddComment(r.Context(), id, reply, "staff")
	}
	if statusErr != nil || commentErr != nil {
		s.logger.Printf("ai apply %d: comment=%v status=%v", id, commentErr, statusErr)
		s.render(w, "error", map[string]any{"Error": "could not apply suggestion"})
		return
	}
	s.handleCommentsPartial(w, r)
}

// validStatus reports whether s is one of the known ticket statuses. Used to
// reject AI-suggested (untrusted) status values before they reach the DB.
func validStatus(s string) bool {
	switch s {
	case "open", "assigned", "closed":
		return true
	}
	return false
}

// handleComment posts a staff comment (htmx form).
func (s *Server) handleComment(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	body := r.FormValue("body")
	if body == "" {
		s.render(w, "error", map[string]any{"Error": "comment body required"})
		return
	}
	author := ""
	if sess := s.auth.CurrentSession(r); sess != nil {
		author = sess.Name
		if author == "" {
			author = sess.Email
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if _, err := s.store.AddComment(ctx, id, body, author); err != nil {
		s.logger.Printf("add comment: %v", err)
		s.render(w, "error", map[string]any{"Error": "could not add comment"})
		return
	}
	comments, _ := s.store.ListComments(ctx, id)
	if comments == nil {
		comments = []store.Comment{}
	}
	s.render(w, "comments", map[string]any{"Comments": comments})
}

// handleStatus updates a ticket's status (htmx form).
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	status := r.FormValue("status")
	if status == "" {
		s.render(w, "error", map[string]any{"Error": "status required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	if err := s.store.SetStatus(ctx, id, status); err != nil {
		s.logger.Printf("set status: %v", err)
		s.render(w, "error", map[string]any{"Error": "could not update status"})
		return
	}
	s.render(w, "status", map[string]any{"Ticket": &store.Ticket{ID: id, Status: status}})
}

// render executes a template by name.
func (s *Server) render(w http.ResponseWriter, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Printf("render %s: %v", name, err)
		http.Error(w, "render error", http.StatusInternalServerError)
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
	if err := srv.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

var _ = json.Marshal // keep encoding/json if unused later
