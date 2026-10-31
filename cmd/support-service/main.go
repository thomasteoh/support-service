// Command support-service is the harmonicr helpdesk ticket service.
//
// It accepts ticket creation from the event-triage bridge via the internal
// public-create endpoint (gated by a shared secret X-API-Key), provides a
// staff helpdesk UI over Zitadel OIDC, stores tickets in a dedicated
// support-postgres container, and integrates with llmesh (llm.harmonicr.com)
// for AI-assisted triage/actioning (advisory only, never blocking).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/thomasteoh/support-service/internal/api"
	"github.com/thomasteoh/support-service/internal/config"
	"github.com/thomasteoh/support-service/internal/llmesh"
	"github.com/thomasteoh/support-service/internal/oidc"
	"github.com/thomasteoh/support-service/internal/store"
	"github.com/thomasteoh/support-service/internal/ui"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: support-service <serve> [flags]")
		os.Exit(2)
	}
	cmd := os.Args[1]
	switch cmd {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		apiAddr := fs.String("api-addr", "", "internal API listen address (default from env)")
		uiAddr := fs.String("ui-addr", "", "UI listen address (default from env)")
		if err := fs.Parse(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := run(*apiAddr, *uiAddr); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			os.Exit(1)
		}
	case "healthcheck":
		// Container healthcheck (compose.yaml): ping the DB, exit non-zero on
		// failure so Podman restarts/retries. No secrets printed.
		cfg, err := config.Load()
		if err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck:", err)
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
			cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
		st, err := store.New(ctx, dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: db ping failed:", err)
			os.Exit(1)
		}
		defer st.Close()
		if err := st.Ping(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "healthcheck: db ping failed:", err)
			os.Exit(1)
		}
		fmt.Println("ok")
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		os.Exit(2)
	}
}

func run(apiOverride, uiOverride string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	apiAddr := cfg.APIListenAddr
	if apiOverride != "" {
		apiAddr = apiOverride
	}
	// UI surface (staff helpdesk).
	uiAddr := cfg.UIListenAddr
	if uiOverride != "" {
		uiAddr = uiOverride
	}

	// Connect Postgres (dedicated support-postgres).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		cfg.DBUser, cfg.DBPassword, cfg.DBHost, cfg.DBPort, cfg.DBName)
	st, err := store.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// AI triage client (llmesh). Advisory only — degrades gracefully.
	ai := llmesh.New(cfg.LLMESHURL, cfg.LLMESHKey, "triage-fast")

	logger := log.New(os.Stderr, "support-service: ", log.LstdFlags)

	// OIDC SSO (staff UI). Fails closed: if the issuer is unreachable the
	// auth guard 403s — the UI is never silently open.
	auth, err := oidc.New(oidc.Config{
		Issuer:        cfg.OIDCIssuer,
		ClientID:      cfg.OIDCClientID,
		ClientSecret:  cfg.OIDCClientSecret,
		RedirectURL:   cfg.OIDCRedirectURL,
		Scopes:        []string{"openid", "email", "profile"},
		SessionSecret: cfg.SessionSecret,
		AdminRole:     "support",
	}, logger)
	if err != nil {
		return fmt.Errorf("oidc setup: %w", err)
	}

	// Async AI hook: classify the ticket, store the suggestion on it.
	// Never blocks ticket creation; on failure just log (no AI, no error).
	onTicket := func(ctx context.Context, t *store.Ticket) {
		sug, err := ai.Triage(ctx, t.Title, t.Detail, t.Priority, t.Type)
		if err != nil {
			logger.Printf("ai triage skipped: %v", err)
			return
		}
		b, err := json.Marshal(sug)
		if err != nil {
			logger.Printf("ai triage marshal: %v", err)
			return
		}
		t.AISuggestion = string(b)
		if err := st.SetSuggestion(ctx, t.ID, t.AISuggestion); err != nil {
			logger.Printf("ai triage store: %v", err)
		}
	}

	// API surface (internal, bridge + staff read/update).
	apiSrv := api.New(apiAddr, cfg.CreateAPIKey, st, onTicket, logger)

	// Staff helpdesk UI (Caddy-fronted, Zitadel OIDC). The llmesh client is
	// passed as the Actioner so staff can request AI drafts (P2); if AI is
	// disabled the draft route shows an error and never writes.
	uiSrv, err := ui.New(uiAddr, st, auth, logger, ai)
	if err != nil {
		return fmt.Errorf("ui setup: %w", err)
	}

	// Run both servers; block until SIGINT/SIGTERM.
	ctx2, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 2)
	go func() { errCh <- apiSrv.ListenAndServe() }()
	go func() { errCh <- uiSrv.ListenAndServe() }()

	select {
	case <-ctx2.Done():
		logger.Println("shutting down")
		return nil
	case err := <-errCh:
		return err
	}
}
