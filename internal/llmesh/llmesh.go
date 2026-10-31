// Package llmesh is a thin OpenAI-compatible client for the harmonicr LLM
// gateway (llm.harmonicr.com). It is used for AI-assisted ticket triage —
// advisory only, never blocking ticket creation.
//
// Model access is gated by llmesh RBAC policies (S-1): the API key must be a
// team key scoped by an allow policy on the triage model(s). The prompt
// contract (S-2) emits structured JSON; a validator falls back to a default
// priority on parse failure.
package llmesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Suggestion is the AI triage result. The prompt MUST emit this shape
// (structured JSON); on parse failure the caller falls back to a default.
type Suggestion struct {
	Priority        string `json:"priority"`
	Type            string `json:"type"`
	SuggestedAction string `json:"suggested_action"`
}

// Client calls the llmesh OpenAI-compatible /v1/chat/completions endpoint.
type Client struct {
	url   string // e.g. https://llm.harmonicr.com
	key   string // team key, scoped by RBAC allow policy (env only)
	model string // triage model allowed by the RBAC policy
	http  *http.Client
}

// New builds the client. key is the team key (never logged).
func New(url, key, model string) *Client {
	return &Client{
		url:   url,
		key:   key,
		model: model,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Triage classifies a ticket. It sends only ticket-derived fields (title,
// detail, priority, type) — never passwords, secrets, or credentials. On any
// error it returns a zero Suggestion and an error so the caller degrades
// gracefully (never blocks ticket creation).
func (c *Client) Triage(ctx context.Context, title, detail, priority, typ string) (Suggestion, error) {
	if c.model == "" {
		return Suggestion{}, fmt.Errorf("llmesh: no model configured")
	}
	// Stable system prompt — emits structured JSON (S-2 contract).
	const sys = `You are a support-ticket triage assistant. Classify the ticket
and reply with STRICT JSON only, no prose:
{"priority":"low|normal|high|urgent","type":"support|bug|request|escalation","suggested_action":"<one short action>"}`

	body := map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": sys},
			{"role": "user", "content": fmt.Sprintf("title: %s\ndetail: %s\npriority: %s\ntype: %s", title, detail, priority, typ)},
		},
		"temperature": 0.2,
		"max_tokens":  200,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return Suggestion{}, fmt.Errorf("llmesh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)

	resp, err := c.http.Do(req)
	if err != nil {
		return Suggestion{}, fmt.Errorf("llmesh call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain (bounded) so the connection can be reused; ignore the copy
		// error — the body is discarded by design (gosec G104 satisfied).
		if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
			// body already discarded; nothing actionable
			_ = err
		}
		return Suggestion{}, fmt.Errorf("llmesh status %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Suggestion{}, fmt.Errorf("llmesh decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return Suggestion{}, fmt.Errorf("llmesh: no choices")
	}
	content := out.Choices[0].Message.Content
	// Strip possible code fences, then validate against the JSON contract.
	var sug Suggestion
	if err := decodeJSON(content, &sug); err != nil {
		return Suggestion{}, fmt.Errorf("llmesh parse: %w", err)
	}
	if sug.Priority == "" {
		return Suggestion{}, fmt.Errorf("llmesh: empty priority")
	}
	return sug, nil
}

// Action is the AI-suggested staff action for a ticket. It is a DRAFT: the
// staff member sees it and explicitly approves before anything is written
// (P2 — staff approves before any write).
type Action struct {
	SuggestedReply string `json:"suggested_reply"`  // draft reply to the reporter
	SuggestedStep  string `json:"suggested_step"`   // next step / propose label
	Priority       string `json:"priority"`         // optional priority change
	Status         string `json:"status"`           // optional status change
}

// DraftReply generates a staff-facing action draft for a ticket. It is
// advisory and non-mutating: the returned Action is a proposal only. The
// caller (UI) shows it and requires explicit staff approval before applying.
// On any error it returns a zero Action and an error; the UI shows the error
// and never writes.
func (c *Client) DraftReply(ctx context.Context, t TicketFields) (Action, error) {
	if c.model == "" {
		return Action{}, fmt.Errorf("llmesh: no model configured")
	}
	const sys = `You are a support-ticket triage assistant. For the given ticket,
propose a concise staff reply to the reporter and a single suggested next step.
Reply with STRICT JSON only, no prose:
{"suggested_reply":"<one short reply>","suggested_step":"<one short next step>","priority":"low|normal|high|urgent","status":"open|assigned|closed"}`

	body := map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": sys},
			{"role": "user", "content": fmt.Sprintf(
				"title: %s\ndetail: %s\npriority: %s\ntype: %s\nstatus: %s",
				t.Title, t.Detail, t.Priority, t.Type, t.Status)},
		},
		"temperature": 0.3,
		"max_tokens":  300,
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url+"/v1/chat/completions", bytes.NewReader(buf))
	if err != nil {
		return Action{}, fmt.Errorf("llmesh draft request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.key)

	resp, err := c.http.Do(req)
	if err != nil {
		return Action{}, fmt.Errorf("llmesh draft call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 4096)); err != nil {
			_ = err
		}
		return Action{}, fmt.Errorf("llmesh draft status %d", resp.StatusCode)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return Action{}, fmt.Errorf("llmesh draft decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return Action{}, fmt.Errorf("llmesh draft: no choices")
	}
	var act Action
	if err := decodeJSON(out.Choices[0].Message.Content, &act); err != nil {
		return Action{}, fmt.Errorf("llmesh draft parse: %w", err)
	}
	if act.SuggestedReply == "" && act.SuggestedStep == "" {
		return Action{}, fmt.Errorf("llmesh draft: empty action")
	}
	return act, nil
}

// TicketFields is the subset of a ticket the AI actioning prompt uses. It
// never carries secrets — only ticket content for drafting.
type TicketFields struct {
	Title    string
	Detail   string
	Priority string
	Type     string
	Status   string
}

// decodeJSON parses the model's content as JSON, tolerating a ```json fence
// wrapper if the model added one. Falls back to default on failure (S-2).
func decodeJSON(s string, v any) error {
	s = trimFence(s)
	return json.Unmarshal([]byte(s), v)
}

func trimFence(s string) string {
	const open = "```json"
	if len(s) >= len(open) && s[:len(open)] == open {
		s = s[len(open):]
	}
	const close = "```"
	if len(s) >= len(close) && s[len(s)-len(close):] == close {
		s = s[:len(s)-len(close)]
	}
	// Trim surrounding whitespace/newlines left by the fence markers.
	s = strings.TrimSpace(s)
	return s
}
