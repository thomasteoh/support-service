package llmesh

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeLLM is a tiny HTTP server that returns a canned chat completion.
func fakeLLM(status int, content string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"content": content}},
			},
		})
	}))
}

// TestTriageHappyPath verifies the JSON contract is parsed when the model
// returns valid structured JSON (S-2).
func TestTriageHappyPath(t *testing.T) {
	srv := fakeLLM(200, `{"priority":"urgent","type":"escalation","suggested_action":"call the client"}`)
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	sug, err := c.Triage(context.Background(), "t", "d", "normal", "support")
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if sug.Priority != "urgent" || sug.Type != "escalation" {
		t.Fatalf("got %+v", sug)
	}
}

// TestTriageFenceTolerant verifies a ```json fence wrapper is tolerated.
func TestTriageFenceTolerant(t *testing.T) {
	srv := fakeLLM(200, "```json\n{\"priority\":\"high\"}\n```")
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	sug, err := c.Triage(context.Background(), "t", "d", "normal", "support")
	if err != nil {
		t.Fatalf("fence: %v", err)
	}
	if sug.Priority != "high" {
		t.Fatalf("got %+v", sug)
	}
}

// TestTriageParseFallback verifies S-2: non-JSON or empty priority yields an
// error so the caller degrades to a default (never blocks ticket creation).
func TestTriageParseFallback(t *testing.T) {
	for name, content := range map[string]string{
		"prose":       `I think this is urgent.`,
		"empty":       `{"priority":""}`,
		"garbage":     `not json`,
		"missing":     `{"type":"support"}`,
	} {
		srv := fakeLLM(200, content)
		c := New(srv.URL, "k", "triage-fast")
		_, err := c.Triage(context.Background(), "t", "d", "normal", "support")
		if err == nil {
			t.Fatalf("%s: expected parse error, got nil", name)
		}
		srv.Close()
	}
}

// TestTriageHTTPError verifies non-200 responses degrade gracefully.
func TestTriageHTTPError(t *testing.T) {
	srv := fakeLLM(500, `{}`)
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	if _, err := c.Triage(context.Background(), "t", "d", "normal", "support"); err == nil {
		t.Fatal("expected error on 500")
	}
}

// TestTriageNoModel verifies an empty model fails closed.
func TestTriageNoModel(t *testing.T) {
	c := New("http://x", "k", "")
	if _, err := c.Triage(context.Background(), "t", "d", "normal", "support"); err == nil {
		t.Fatal("expected error with no model")
	}
}

// TestDraftReplyHappyPath verifies the actioning draft parses (P2).
func TestDraftReplyHappyPath(t *testing.T) {
	srv := fakeLLM(200, `{"suggested_reply":"We're on it.","suggested_step":"escalate to engineering","priority":"high","status":"assigned"}`)
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	act, err := c.DraftReply(context.Background(), TicketFields{Title: "t", Detail: "d", Priority: "normal", Type: "support", Status: "open"})
	if err != nil {
		t.Fatalf("draft: %v", err)
	}
	if act.SuggestedReply == "" || act.SuggestedStep == "" {
		t.Fatalf("got %+v", act)
	}
}

// TestDraftReplyParseFallback verifies a non-JSON draft degrades to an error
// (the UI shows it and never writes).
func TestDraftReplyParseFallback(t *testing.T) {
	srv := fakeLLM(200, `I think you should reply politely.`)
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	if _, err := c.DraftReply(context.Background(), TicketFields{Title: "t", Detail: "d", Priority: "normal", Type: "support", Status: "open"}); err == nil {
		t.Fatal("expected parse error on prose")
	}
}

// TestDraftReplyEmptyAction verifies an empty action (no reply, no step)
// returns an error so nothing is applied.
func TestDraftReplyEmptyAction(t *testing.T) {
	srv := fakeLLM(200, `{"suggested_reply":"","suggested_step":""}`)
	defer srv.Close()
	c := New(srv.URL, "k", "triage-fast")
	if _, err := c.DraftReply(context.Background(), TicketFields{Title: "t", Detail: "d", Priority: "normal", Type: "support", Status: "open"}); err == nil {
		t.Fatal("expected error on empty action")
	}
}

// TestDraftReplyNoModel verifies a missing model fails closed.
func TestDraftReplyNoModel(t *testing.T) {
	c := New("http://x", "k", "")
	if _, err := c.DraftReply(context.Background(), TicketFields{Title: "t", Detail: "d", Priority: "normal", Type: "support", Status: "open"}); err == nil {
		t.Fatal("expected error with no model")
	}
}

// TestTrimFence verifies the fence trimmer.
func TestTrimFence(t *testing.T) {
	if got := trimFence("```json\n{\"a\":1}\n```"); got != "{\"a\":1}" {
		t.Fatalf("got %q", got)
	}
	if got := trimFence("{\"a\":1}"); got != "{\"a\":1}" {
		t.Fatalf("plain: got %q", got)
	}
}
