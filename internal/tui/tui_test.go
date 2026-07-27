package tui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/davicbtoliveira/TermKeep/internal/client"
)

func TestActiveSessionsScreenShowsSessionMetadata(t *testing.T) {
	created := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	initial := model{
		cfg:         client.Config{ServerURL: server.URL},
		loaded:      true,
		vaultOpen:   true,
		accessToken: "access-token",
	}
	updated, command := initial.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'s'}})
	if command == nil {
		t.Fatal("sessions key did not load Active Sessions")
	}
	updated, _ = updated.(model).Update(command())
	view := updated.(model).View()
	for _, want := range []string{
		"Active Sessions",
		"workstation",
		"192.0.2.10",
		"2026-07-27T12:00:00Z",
		"2026-07-27T12:01:00Z",
		"current",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("Active Sessions missing %q:\n%s", want, view)
		}
	}
}

func TestActiveSessionsRevokesSelectedRemoteSession(t *testing.T) {
	revoked := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/sessions/remote-123" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		revoked = true
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	initial := model{
		cfg:          client.Config{ServerURL: server.URL},
		loaded:       true,
		vaultOpen:    true,
		accessToken:  "access-token",
		showSessions: true,
		sessions: []client.OnlineSession{{
			SessionID: "remote-123",
			Host:      "laptop",
		}},
	}
	_, command := initial.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	if command == nil {
		t.Fatal("revoke key did not issue request")
	}
	command()
	if !revoked {
		t.Fatal("selected remote session was not revoked")
	}
}
