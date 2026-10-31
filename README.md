# support-service

harmonicr helpdesk ticket service — a self-built replacement for the
abandoned Peppermint helpdesk. It preserves the event-triage bridge contract
exactly and adds a staff UI + AI-assisted triage via the existing llmesh LLM
gateway.

See the PRD: `../docs/projects/infrastructure/support-service-prd.md`.

## What it is

- **Internal API** (`:5003`, container-network only): the WHOLE `/api/v1`
  surface — create, read, list, status — is **gated by a shared secret**
  (`X-API-Key`, `CREATE_API_KEY`); only `/health` and `/healthz` are open
  (bridge readiness probe + container healthcheck). The bridge calls
  `POST /api/v1/ticket/public/create`; it returns `{id, success:true}` — the
  exact Peppermint contract (C-2).
- **Staff UI** (`:3000`, Caddy-fronted, Zitadel OIDC) — list, view, assign,
  comment, close tickets.
- **Dedicated Postgres** (`support-postgres`) — no reuse of Peppermint's DB.
- **AI triage/actioning** via llmesh (`llm.harmonicr.com`) — advisory,
  async, never blocks ticket creation. Staff can request a **draft reply /
  next step** (`POST /tickets/{id}/ai/draft`) — **staff approves before any
  write** (`POST /tickets/{id}/ai/apply`); the draft route never mutates.
- **Admin settings** (`/admin`, staff) — maintain runtime non-secret
  settings: **AI model** (`LLMESH_MODEL` env default), **AI enabled** toggle
  (`AI_ENABLED` env default), and **ticket list limit** (`TICKET_LIST_LIMIT`
  env default). Persisted in the `settings` table; env vars are the fallback
  when the row is absent. Secrets are never exposed here.

## Build & test

```sh
go build ./...
go vet ./...
go test ./...        # C-2 secret gate, S-2 JSON fallback, OIDC fail-closed, UI templates
go test -race ./...
```

## Deploy (solo.harmonicr.com, rootless Podman)

```sh
# Version-pin the pull — never float on :latest (the Peppermint escape).
# Substitute the built :sha (or a tagged release, e.g. :v1.0.0) for :sha.
podman pull ghcr.io/thomasteoh/support-service:<sha> --force-recreate
podman compose up -d
```

- **C-1**: join the `zitadel` bridge; reachable as `support-service:5003`.
  event-triage env changes `peppermint:5003` → `support-service:5003`.
- **C-3**: package public OR token in `~/.config/containers/auth.json` (600).
- **S-4**: `support-postgres` must be healthy before the service starts.

## Layout

```
cmd/support-service/     entry point (serve + healthcheck commands)
internal/api/            HTTP surfaces (create gate, health)
internal/config/         env config, fails closed on missing secrets
internal/llmesh/         AI triage client (JSON contract, parse fallback)
internal/oidc/           Zitadel OIDC SSO (PKCE, cookie session, fail-closed)
internal/store/          Postgres persistence (tickets + comments)
internal/ui/             staff helpdesk UI (htmx, OIDC-protected)
compose.yaml             deploy compose (solo)
Dockerfile               multi-stage Go → scratch (uid 10001)
.github/workflows/       GHCR build+test+publish
```

## Security notes

- Secrets are env-only: `DB_PASSWORD`, `CREATE_API_KEY`, `LLMESH_KEY`,
  `OIDC_CLIENT_SECRET`, `SESSION_SECRET` — never committed, never logged.
- Create endpoint fails closed on missing/incorrect `X-API-Key`.
- AI sends only ticket fields (title/detail/priority/type) — never secrets.
- **CSRF**: every protected POST route validates a per-session token
  (`csrf_token`), generated on OIDC session creation and embedded in all
  htmx POST forms; POSTs without a valid token are rejected (403). Defense
  in depth over the OIDC session guard.
- **Accessibility/UX**: skip-to-content link, `aria-live` on htmx swap
  targets (comments/AI draft), touch targets ≥ 44px, responsive table
  overflow, and AI triage rendered as labeled fields (not raw JSON).
- Runs as uid 10001 (non-root), `userns_mode keep-id`.
