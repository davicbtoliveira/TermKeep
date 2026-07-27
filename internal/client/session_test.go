package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestListSessionsReturnsOnlineSessionMetadata(t *testing.T) {
	created := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sessions" || r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"sessions": []map[string]any{{
			"session_id":   "session-123",
			"host":         "workstation",
			"source_ip":    "192.0.2.10",
			"created_at":   created,
			"last_used_at": created.Add(time.Minute),
			"current":      true,
		}}})
	}))
	defer server.Close()

	sessions, err := ListSessions(context.Background(), Config{ServerURL: server.URL}, "access-token")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Host != "workstation" || !sessions[0].Current {
		t.Fatalf("unexpected sessions: %+v", sessions)
	}
}

func TestRevokeSessionDeletesAuthenticatedSession(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete ||
			r.URL.Path != "/api/v1/sessions/session-123" ||
			r.Header.Get("Authorization") != "Bearer access-token" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	err := RevokeSession(context.Background(), Config{ServerURL: server.URL}, "access-token", "session-123")
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("session endpoint was not called")
	}
}
