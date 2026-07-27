package tui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
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

func TestUnlockedVaultListsLoginsWithoutPasswords(t *testing.T) {
	initial := model{loaded: true, vaultOpen: true}
	updated, _ := initial.Update(loginsMsg{{
		Login: client.LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Production database",
			Username: "operator@example.com",
			Password: "Password-Sentinel",
		},
		Revision: 1,
	}})
	view := updated.(model).View()
	for _, want := range []string{"Production database", "operator@example.com"} {
		if !strings.Contains(view, want) {
			t.Fatalf("Vault list missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Password-Sentinel") {
		t.Fatalf("Vault list exposed password:\n%s", view)
	}

	locked := model{loaded: true}.View()
	if strings.Contains(locked, "Production database") {
		t.Fatalf("locked TUI exposed Login:\n%s", locked)
	}
}

func TestLoginDetailShowsFieldsWithMaskedPassword(t *testing.T) {
	initial := model{
		loaded:    true,
		vaultOpen: true,
		logins: []loginRecord{{
			Login: client.LoginItem{
				ItemID:   "11111111-1111-4111-8111-111111111111",
				Name:     "Production database",
				Username: "operator@example.com",
				Password: "Password-Sentinel",
				URLs: []string{
					"https://db.example.com",
					"postgres://db.internal",
				},
				Notes: "Primary credentials",
				CustomFields: []client.CustomField{
					{Name: "region", Value: "us-east-1"},
				},
			},
			Revision: 1,
		}},
	}
	updated, _ := initial.Update(tea.KeyMsg{Type: tea.KeyEnter})
	view := updated.(model).View()
	for _, want := range []string{
		"Login — Production database",
		"operator@example.com",
		"https://db.example.com",
		"postgres://db.internal",
		"Primary credentials",
		"region: us-east-1",
		"Password: ••••••••",
	} {
		if !strings.Contains(view, want) {
			t.Fatalf("Login detail missing %q:\n%s", want, view)
		}
	}
	if strings.Contains(view, "Password-Sentinel") {
		t.Fatalf("Login detail exposed password by default:\n%s", view)
	}
}

func TestLoginPasswordRevealsOnlyAfterExplicitKey(t *testing.T) {
	initial := model{
		loaded:    true,
		vaultOpen: true,
		logins: []loginRecord{{
			Login: client.LoginItem{
				ItemID:   "11111111-1111-4111-8111-111111111111",
				Name:     "Production database",
				Password: "Password-Sentinel",
			},
			Revision: 1,
		}},
	}
	updated, _ := initial.Update(tea.KeyMsg{Type: tea.KeyEnter})
	updated, _ = updated.(model).Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	view := updated.(model).View()
	if !strings.Contains(view, "Password: Password-Sentinel") {
		t.Fatalf("explicit reveal did not show password:\n%s", view)
	}
}

func TestVaultRefreshLoadsDecryptedLogins(t *testing.T) {
	store := &fakeLoginStore{records: []loginRecord{{
		Login: client.LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Mail account",
			Username: "user@example.com",
		},
		Revision: 1,
	}}}
	initial := model{
		loaded:     true,
		vaultOpen:  true,
		loginStore: store,
	}
	updated, command := initial.Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if command == nil {
		t.Fatal("Vault refresh did not load Logins")
	}
	updated, _ = updated.(model).Update(command())
	view := updated.(model).View()
	if !strings.Contains(view, "Mail account") {
		t.Fatalf("refreshed Vault missing Login:\n%s", view)
	}
}

func TestCreateLoginCapturesAllNativeFields(t *testing.T) {
	store := &fakeLoginStore{}
	var current tea.Model = model{
		loaded:     true,
		vaultOpen:  true,
		loginStore: store,
	}
	current, _ = current.Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'c'}})
	values := []string{
		"Production database",
		"operator@example.com",
		"Password-Sentinel",
		"https://db.example.com, postgres://db.internal",
		"Primary credentials",
		"region=us-east-1, owner=platform",
	}
	var command tea.Cmd
	for _, value := range values {
		current, _ = current.Update(
			tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)})
		current, command = current.Update(tea.KeyMsg{Type: tea.KeyEnter})
	}
	if command == nil {
		t.Fatal("final Login field did not save")
	}
	current, _ = current.Update(command())

	if len(store.saved) != 1 {
		t.Fatalf("saved Logins: want 1, got %d", len(store.saved))
	}
	login := store.saved[0].Login
	if login.ItemID == "" ||
		login.Name != values[0] ||
		login.Username != values[1] ||
		login.Password != values[2] ||
		!reflect.DeepEqual(login.URLs, []string{
			"https://db.example.com",
			"postgres://db.internal",
		}) ||
		login.Notes != values[4] ||
		!reflect.DeepEqual(login.CustomFields, []client.CustomField{
			{Name: "region", Value: "us-east-1"},
			{Name: "owner", Value: "platform"},
		}) {
		t.Fatalf("saved Login differs: %+v", login)
	}
	if strings.Contains(current.(model).View(), values[2]) {
		t.Fatal("Vault exposed saved password")
	}
}

func TestEditLoginPreservesFieldsAndIncrementsRevision(t *testing.T) {
	store := &fakeLoginStore{records: []loginRecord{{
		Login: client.LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Old name",
			Username: "operator@example.com",
			Password: "Password-Sentinel",
			URLs:     []string{"https://db.example.com"},
			Notes:    "Primary credentials",
			CustomFields: []client.CustomField{
				{Name: "region", Value: "us-east-1"},
			},
		},
		Revision: 1,
	}}}
	var current tea.Model = model{
		loaded:     true,
		vaultOpen:  true,
		loginStore: store,
		logins:     store.records,
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyEnter})
	current, _ = current.Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'e'}})
	if !strings.Contains(current.(model).View(), "Edit Login") {
		t.Fatalf("edit key did not open form:\n%s", current.(model).View())
	}
	current, _ = current.Update(tea.KeyMsg{Type: tea.KeyCtrlU})
	current, _ = current.Update(
		tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("New name")})

	var command tea.Cmd
	for range loginFormFieldCount {
		current, command = current.Update(tea.KeyMsg{Type: tea.KeyEnter})
	}
	if command == nil {
		t.Fatal("edited Login was not saved")
	}
	current, _ = current.Update(command())

	if len(store.saved) != 1 {
		t.Fatalf("saved Logins: want 1, got %d", len(store.saved))
	}
	got := store.saved[0]
	if got.Revision != 2 {
		t.Fatalf("revision: want 2, got %d", got.Revision)
	}
	if got.Login.Name != "New name" ||
		got.Login.Username != "operator@example.com" ||
		got.Login.Password != "Password-Sentinel" ||
		!reflect.DeepEqual(got.Login.URLs, []string{"https://db.example.com"}) ||
		got.Login.Notes != "Primary credentials" ||
		!reflect.DeepEqual(got.Login.CustomFields, []client.CustomField{
			{Name: "region", Value: "us-east-1"},
		}) {
		t.Fatalf("edited Login lost fields: %+v", got.Login)
	}
}

type fakeLoginStore struct {
	records []loginRecord
	saved   []loginRecord
	err     error
}

func (s *fakeLoginStore) List(context.Context) ([]loginRecord, error) {
	return s.records, s.err
}

func (s *fakeLoginStore) Save(_ context.Context, record loginRecord) error {
	if s.err != nil {
		return s.err
	}
	s.saved = append(s.saved, record)
	for index := range s.records {
		if s.records[index].Login.ItemID == record.Login.ItemID {
			s.records[index] = record
			return nil
		}
	}
	s.records = append(s.records, record)
	return nil
}
