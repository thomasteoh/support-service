# support-service — harmonicr helpdesk ticket service
# Multi-stage Go build, minimal scratch runtime (mirrors smtp-router / event-triage).
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /support-service ./cmd/support-service

FROM scratch
# CA certificates are REQUIRED: verifies OIDC ID tokens against
# https://auth.harmonicr.com (Let's Encrypt cert) and calls llmesh over HTTPS
# at https://llm.harmonicr.com; without a CA bundle Go's x509 verifier rejects
# those certs.
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /support-service /support-service
# Run as non-root (uid 10001 to match the harmonicr rootless pattern).
USER 10001:10001
EXPOSE 3000 5003
ENTRYPOINT ["/support-service"]
