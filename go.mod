module github.com/thomasteoh/support-service

// Pin a patch release that fixes known stdlib CVEs (GO-2026-6218, 6090,
// 6089, 5972, 5026, 6809). The Go toolchain directive ensures builds use >= 1.26.10.
go 1.26.10

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/go-chi/chi/v5 v5.5.0
	github.com/jackc/pgx/v5 v5.9.2
	golang.org/x/oauth2 v0.37.0
)

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
