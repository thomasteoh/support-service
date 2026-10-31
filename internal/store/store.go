// Package store persists tickets in Postgres (dedicated support-postgres).
// The schema mirrors the Peppermint public-create payload so the event-triage
// bridge contract is preserved exactly.
package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Ticket is a support ticket. Field names mirror the Peppermint public-create
// payload (name, company, detail, title, priority, email, engineer, type,
// createdBy) so the bridge contract is unchanged.
type Ticket struct {
	ID             int64     `json:"id"`
	Name           string    `json:"name"`
	Company        string    `json:"company"`
	Detail         string    `json:"detail"`
	Title          string    `json:"title"`
	Priority       string    `json:"priority"`
	Email          string    `json:"email"`
	Engineer       string    `json:"engineer"`
	Type           string    `json:"type"`
	CreatedBy      string    `json:"createdBy"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
	AISuggestion   string    `json:"aiSuggestion,omitempty"` // llmesh triage result (JSON)
}

// Store wraps the Postgres connection pool.
type Store struct {
	pool *pgxpool.Pool
}

// New opens the pool and applies the schema.
func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if err := migrate(ctx, pool); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

func migrate(ctx context.Context, pool *pgxpool.Pool) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS tickets (
	id          BIGSERIAL PRIMARY KEY,
	name        TEXT NOT NULL,
	company     TEXT NOT NULL DEFAULT '',
	detail      TEXT NOT NULL DEFAULT '',
	title       TEXT NOT NULL,
	priority    TEXT NOT NULL DEFAULT 'normal',
	email       TEXT NOT NULL DEFAULT '',
	engineer    TEXT NOT NULL DEFAULT '',
	type        TEXT NOT NULL DEFAULT 'support',
	created_by  TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'open',
	ai_suggestion JSONB,
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
	updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS comments (
	id          BIGSERIAL PRIMARY KEY,
	ticket_id   BIGINT NOT NULL REFERENCES tickets(id) ON DELETE CASCADE,
	body        TEXT NOT NULL,
	author      TEXT NOT NULL DEFAULT '',
	created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
`
	_, err := pool.Exec(ctx, ddl)
	return err
}

// CreateTicket inserts a ticket and returns its ID. The public-create endpoint
// calls this after validating the shared secret; it mirrors the Peppermint
// {id, success:true} contract.
func (s *Store) CreateTicket(ctx context.Context, t *Ticket) (int64, error) {
	if t.CreatedBy == "" {
		t.CreatedBy = "support"
	}
	if t.Status == "" {
		t.Status = "open"
	}
	var sug any
	if t.AISuggestion != "" {
		var v any
		if err := json.Unmarshal([]byte(t.AISuggestion), &v); err == nil {
			sug = v
		}
	}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO tickets (name, company, detail, title, priority, email,
			engineer, type, created_by, status, ai_suggestion)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING id`,
		t.Name, t.Company, t.Detail, t.Title, t.Priority, t.Email,
		t.Engineer, t.Type, t.CreatedBy, t.Status, sug,
	).Scan(&t.ID)
	if err != nil {
		return 0, fmt.Errorf("insert ticket: %w", err)
	}
	return t.ID, nil
}

// GetTicket loads one ticket by ID.
func (s *Store) GetTicket(ctx context.Context, id int64) (*Ticket, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, name, company, detail, title, priority, email, engineer,
			type, created_by, status, ai_suggestion, created_at, updated_at
		FROM tickets WHERE id=$1`, id)
	var t Ticket
	var sug []byte
	if err := row.Scan(&t.ID, &t.Name, &t.Company, &t.Detail, &t.Title,
		&t.Priority, &t.Email, &t.Engineer, &t.Type, &t.CreatedBy, &t.Status,
		&sug, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("get ticket: %w", err)
	}
	if len(sug) > 0 {
		t.AISuggestion = string(sug)
	}
	return &t, nil
}

// ListTickets returns the open tickets (newest first), limited to n.
func (s *Store) ListTickets(ctx context.Context, n int) ([]Ticket, error) {
	if n <= 0 {
		n = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, company, detail, title, priority, email, engineer,
			type, created_by, status, ai_suggestion, created_at, updated_at
		FROM tickets ORDER BY created_at DESC LIMIT $1`, n)
	if err != nil {
		return nil, fmt.Errorf("list tickets: %w", err)
	}
	defer rows.Close()
	var out []Ticket
	for rows.Next() {
		var t Ticket
		var sug []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Company, &t.Detail, &t.Title,
			&t.Priority, &t.Email, &t.Engineer, &t.Type, &t.CreatedBy,
			&t.Status, &sug, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan ticket: %w", err)
		}
		if len(sug) > 0 {
			t.AISuggestion = string(sug)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// SetStatus updates a ticket's status (staff actioning).
func (s *Store) SetStatus(ctx context.Context, id int64, status string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE tickets SET status=$2, updated_at=now() WHERE id=$1`,
		id, status)
	if err != nil {
		return fmt.Errorf("set status: %w", err)
	}
	return nil
}

// SetSuggestion stores the AI triage suggestion JSON on a ticket.
func (s *Store) SetSuggestion(ctx context.Context, id int64, sug string) error {
	var v any
	if err := json.Unmarshal([]byte(sug), &v); err != nil {
		return fmt.Errorf("invalid suggestion json: %w", err)
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE tickets SET ai_suggestion=$2, updated_at=now() WHERE id=$1`,
		id, v)
	if err != nil {
		return fmt.Errorf("set suggestion: %w", err)
	}
	return nil
}

// Comment is a staff reply on a ticket (Phase 3 helpdesk UI).
type Comment struct {
	ID        int64     `json:"id"`
	TicketID  int64     `json:"ticketId"`
	Body      string    `json:"body"`
	Author    string    `json:"author"`
	CreatedAt time.Time `json:"createdAt"`
}

// AddComment appends a staff comment to a ticket.
func (s *Store) AddComment(ctx context.Context, ticketID int64, body, author string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO comments (ticket_id, body, author)
		VALUES ($1,$2,$3) RETURNING id`, ticketID, body, author).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("add comment: %w", err)
	}
	return id, nil
}

// ListComments returns a ticket's comments (oldest first).
func (s *Store) ListComments(ctx context.Context, ticketID int64) ([]Comment, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, ticket_id, body, author, created_at
		FROM comments WHERE ticket_id=$1 ORDER BY created_at ASC`, ticketID)
	if err != nil {
		return nil, fmt.Errorf("list comments: %w", err)
	}
	defer rows.Close()
	var out []Comment
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.TicketID, &c.Body, &c.Author, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Ping verifies the DB is reachable (health/readiness probe).
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }
