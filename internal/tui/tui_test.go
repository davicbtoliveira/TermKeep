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

func TestActivityScreenShowsOwnOperationalEvents(t *testing.T) {
	occurredAt := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/activity" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{{
				"event_id":    "event-123",
				"type":        "login.succeeded",
				"account_id":  "account-123",
				"actor_id":    "account-123",
				"source_ip":   "192.0.2.10",
				"occurred_at": occurredAt,
			}},
		})
	}))
	defer server.Close()

	initial := model{
		cfg:         client.Config{ServerURL: server.URL},
		loaded:      true,
		vaultOpen:   true,
		accessToken: "access-token",
	}
	updated, command := initial.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	if command == nil {
		t.Fatal("activity key did not load Activity")
	}
	updated, _ = updated.(model).Update(command())
	view := updated.(model).View()
	for _, want := range []string{
		"Activity",
		"my account",
		"login.succeeded",
		"2026-07-27T12:00:00Z",
		"account-123",
		"192.0.2.10",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("Activity missing %q:\n%s", want, view)
		}
	}
}

func TestAdministratorActivityCanShowAllAccounts(t *testing.T) {
	adminRequested := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/activity":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events":       []any{},
				"can_view_all": true,
			})
		case "/api/v1/admin/activity":
			adminRequested = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": []map[string]any{{
					"event_id":    "event-456",
					"type":        "registration.succeeded",
					"account_id":  "account-other",
					"actor_id":    "actor-uuid",
					"occurred_at": time.Date(2026, 7, 27, 13, 0, 0, 0, time.UTC),
				}},
				"can_view_all": true,
			})
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}))
	defer server.Close()

	initial := model{
		cfg:         client.Config{ServerURL: server.URL},
		loaded:      true,
		vaultOpen:   true,
		accessToken: "access-token",
	}
	updated, command := initial.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	updated, _ = updated.(model).Update(command())
	updated, command = updated.(model).Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'g'}})
	if command == nil {
		t.Fatal("administrator global key did not load all-account activity")
	}
	updated, _ = updated.(model).Update(command())
	view := updated.(model).View()
	if !adminRequested {
		t.Fatal("administrative activity endpoint was not requested")
	}
	for _, want := range []string{
		"all accounts",
		"Account: account-other",
		"Actor: actor-uuid",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("administrative Activity missing %q:\n%s", want, view)
		}
	}
}

func TestActivityLoadsNextPageFromCursor(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		eventType := "login.succeeded"
		nextCursor := "cursor-2"
		if r.URL.Query().Get("cursor") == "cursor-2" {
			eventType = "session.revoked"
			nextCursor = ""
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"events": []map[string]any{{
				"event_id":    eventType,
				"type":        eventType,
				"occurred_at": time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
			}},
			"next_cursor": nextCursor,
		})
	}))
	defer server.Close()

	initial := model{
		cfg:         client.Config{ServerURL: server.URL},
		loaded:      true,
		vaultOpen:   true,
		accessToken: "access-token",
	}
	updated, command := initial.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	updated, _ = updated.(model).Update(command())
	updated, command = updated.(model).Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if command == nil {
		t.Fatal("next-page key did not use activity cursor")
	}
	updated, _ = updated.(model).Update(command())
	view := updated.(model).View()
	if !strings.Contains(view, "session.revoked") ||
		strings.Contains(view, "login.succeeded") {
		t.Fatalf("next activity page not rendered:\n%s", view)
	}
}
