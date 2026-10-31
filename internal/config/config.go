// Package config loads the support-service configuration from environment
// variables. Secrets (Postgres password, create endpoint key, llmesh key,
// OIDC client secret) are read from env — never committed, never logged.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the full support-service configuration, loaded from env vars.
type Config struct {
	// Postgres (dedicated support-postgres container).
	DBUser     string
	DBPassword string // env only, never committed/logged
	DBHost     string // e.g. "support-postgres"
	DBPort     string
	DBName     string

	// Create endpoint shared secret (X-API-Key). The event-triage bridge
	// sends this header; the endpoint rejects requests without it.
	CreateAPIKey string // env only

	// AI via llmesh (llm.harmonicr.com, host-network — reached via Caddy route).
	LLMESHURL string // e.g. "https://llm.harmonicr.com"
	LLMESHKey string // team key scoped by RBAC allow policy (env only)

	// Zitadel OIDC (UI auth, app "support").
	OIDCIssuer    string // e.g. "https://auth.harmonicr.com"
	OIDCClientID  string
	OIDCClientSecret string // env only
	OIDCRedirectURL   string // e.g. "https://support.harmonicr.com/callback"

	// Session cookie.
	SessionSecret string // env only, HMAC key for the cookie

	// Listen addresses.
	APIListenAddr string // e.g. ":5003" (internal create/read/update)
	UIListenAddr  string // e.g. ":3000" (staff helpdesk, Caddy-fronted)

	// Triage/limits.
	DedupWindow time.Duration
	RateLimit   int
}

// Load reads the config from environment variables. Missing required values
// produce an error so the service fails closed rather than silently running
// with an empty config.
func Load() (*Config, error) {
	cfg := &Config{
		DBUser:          os.Getenv("DB_USERNAME"),
		DBPassword:      os.Getenv("DB_PASSWORD"),
		DBHost:          getenv("DB_HOST", "support-postgres"),
		DBPort:          getenv("DB_PORT", "5432"),
		DBName:          getenv("DB_NAME", "support"),
		CreateAPIKey:    os.Getenv("CREATE_API_KEY"),
		LLMESHURL:       getenv("LLMESH_URL", "https://llm.harmonicr.com"),
		LLMESHKey:       os.Getenv("LLMESH_KEY"),
		OIDCIssuer:      getenv("OIDC_ISSUER", "https://auth.harmonicr.com"),
		OIDCClientID:    os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURL: getenv("OIDC_REDIRECT_URL", "https://support.harmonicr.com/callback"),
		SessionSecret:   os.Getenv("SESSION_SECRET"),
		APIListenAddr:   getenv("API_LISTEN_ADDR", ":5003"),
		UIListenAddr:    getenv("UI_LISTEN_ADDR", ":3000"),
		DedupWindow:     durDefault(getenv("DEDUP_WINDOW", "1h"), time.Hour),
		RateLimit:       atoiDefault(getenv("RATE_LIMIT", "100"), 100),
	}
	// Fail closed on missing required secrets.
	var missing []string
	if cfg.DBPassword == "" {
		missing = append(missing, "DB_PASSWORD")
	}
	if cfg.CreateAPIKey == "" {
		missing = append(missing, "CREATE_API_KEY")
	}
	if cfg.LLMESHKey == "" {
		missing = append(missing, "LLMESH_KEY")
	}
	if cfg.OIDCClientID == "" {
		missing = append(missing, "OIDC_CLIENT_ID")
	}
	if cfg.OIDCClientSecret == "" {
		missing = append(missing, "OIDC_CLIENT_SECRET")
	}
	if cfg.SessionSecret == "" {
		missing = append(missing, "SESSION_SECRET")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func durDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
