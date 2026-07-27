package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"testing"
	"time"
)

func TestActivityShowsOnlyAuthenticatedAccountEvents(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	auditStore := &memoryAuditStore{events: []AuditEvent{
		{
			EventID:   "11111111-1111-4111-8111-111111111111",
			Type:      "login.succeeded",
			AccountID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ActorID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			OccurredAt: time.Date(2026, 7, 27, 12, 0, 0, 0,
				time.UTC),
		},
		{
			EventID:   "22222222-2222-4222-8222-222222222222",
			Type:      "session.revoked",
			AccountID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			ActorID:   "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			OccurredAt: time.Date(2026, 7, 27, 11, 0, 0, 0,
				time.UTC),
		},
	}}
	activity := NewActivityService(NewAuditLog(auditStore, 90*24*time.Hour), auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	authStore.account.AccountID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	authStore.accounts["admin@example.com"].AccountID = authStore.account.AccountID
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("activity status: want 200, got %d", response.StatusCode)
	}
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	if len(body.Events) != 1 || body.Events[0].Type != "login.succeeded" {
		t.Fatalf("cross-account activity exposed: %+v", body.Events)
	}
}

func TestAdministratorActivityShowsAllAccountsAndActorUUID(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	auditStore := &memoryAuditStore{events: []AuditEvent{
		{
			EventID:    "11111111-1111-4111-8111-111111111111",
			Type:       "invite.created",
			AccountID:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			ActorID:    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			OccurredAt: time.Now(),
		},
		{
			EventID:    "22222222-2222-4222-8222-222222222222",
			Type:       "registration.succeeded",
			AccountID:  "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			ActorID:    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			OccurredAt: time.Now().Add(-time.Minute),
		},
	}}
	activity := NewActivityService(NewAuditLog(auditStore, 90*24*time.Hour), auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/admin/activity", token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("administrator activity status: want 200, got %d", response.StatusCode)
	}
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	if len(body.Events) != 2 {
		t.Fatalf("administrator events: want 2, got %d", len(body.Events))
	}
	for _, event := range body.Events {
		if event.ActorID == "" {
			t.Fatalf("event missing actor UUID: %+v", event)
		}
	}
}

func TestActivityPaginatesWithoutRepeatingEvents(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	auditStore := &memoryAuditStore{events: []AuditEvent{
		{
			EventID:   "11111111-1111-4111-8111-111111111111",
			Type:      "session.created",
			AccountID: accountID,
			ActorID:   accountID,
			OccurredAt: time.Date(2026, 7, 27, 12, 0, 0, 0,
				time.UTC),
		},
		{
			EventID:   "22222222-2222-4222-8222-222222222222",
			Type:      "login.succeeded",
			AccountID: accountID,
			ActorID:   accountID,
			OccurredAt: time.Date(2026, 7, 27, 11, 0, 0, 0,
				time.UTC),
		},
	}}
	activity := NewActivityService(NewAuditLog(auditStore, 90*24*time.Hour), auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	authStore.account.AccountID = accountID
	authStore.accounts["admin@example.com"].AccountID = accountID
	token := mustLogin(t, server, "admin@example.com", password)

	firstResponse := getJSONWithAuth(t, server.URL+"/api/v1/activity?limit=1", token)
	var first struct {
		Events     []AuditEvent `json:"events"`
		NextCursor string       `json:"next_cursor"`
	}
	decodeJSON(t, firstResponse, &first)
	if len(first.Events) != 1 || first.NextCursor == "" {
		t.Fatalf("first page incomplete: %+v", first)
	}

	secondResponse := getJSONWithAuth(t,
		server.URL+"/api/v1/activity?limit=1&cursor="+url.QueryEscape(first.NextCursor), token)
	var second struct {
		Events     []AuditEvent `json:"events"`
		NextCursor string       `json:"next_cursor"`
	}
	decodeJSON(t, secondResponse, &second)
	if len(second.Events) != 1 || second.Events[0].EventID == first.Events[0].EventID {
		t.Fatalf("second page repeated first: first=%+v second=%+v", first, second)
	}
	if second.NextCursor != "" {
		t.Fatalf("last page returned cursor %q", second.NextCursor)
	}
}

func TestParseAuditRetention(t *testing.T) {
	tests := []struct {
		value string
		want  time.Duration
		ok    bool
	}{
		{value: "", want: 90 * 24 * time.Hour, ok: true},
		{value: "30", want: 30 * 24 * time.Hour, ok: true},
		{value: "0"},
		{value: "not-a-number"},
	}
	for _, test := range tests {
		got, err := ParseAuditRetention(test.value)
		if test.ok && (err != nil || got != test.want) {
			t.Errorf("ParseAuditRetention(%q): want %s, got %s, %v",
				test.value, test.want, got, err)
		}
		if !test.ok && err == nil {
			t.Errorf("ParseAuditRetention(%q): expected error", test.value)
		}
	}
}

func TestAdministrativeActivityRejectsOrdinaryAccount(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	activity := NewActivityService(NewAuditLog(&memoryAuditStore{}, defaultAuditRetention), auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "user@example.com", password)
	authStore.account.Administrator = false
	token := mustLogin(t, server, "user@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/admin/activity", token)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("ordinary account admin activity: want 401, got %d", response.StatusCode)
	}
}

func TestActivityRejectsInvalidCursor(t *testing.T) {
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	activity := NewActivityService(NewAuditLog(&memoryAuditStore{}, defaultAuditRetention), auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity?cursor=invalid", token)
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid activity cursor: want 400, got %d", response.StatusCode)
	}
}

func TestActivityAutomaticallyDeletesExpiredEvents(t *testing.T) {
	now := time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	accountID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	authStore := &memoryBootstrapStore{}
	auth := newTestAuthService(t, authStore)
	auditStore := &memoryAuditStore{events: []AuditEvent{
		{
			EventID:    "11111111-1111-4111-8111-111111111111",
			Type:       "login.succeeded",
			AccountID:  accountID,
			OccurredAt: now.Add(-29 * 24 * time.Hour),
		},
		{
			EventID:    "22222222-2222-4222-8222-222222222222",
			Type:       "login.failed",
			AccountID:  accountID,
			OccurredAt: now.Add(-31 * 24 * time.Hour),
		},
	}}
	audit := NewAuditLog(auditStore, 30*24*time.Hour)
	audit.now = func() time.Time { return now }
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	authStore.account.AccountID = accountID
	authStore.accounts["admin@example.com"].AccountID = accountID
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	if len(body.Events) != 1 || body.Events[0].Type != "login.succeeded" {
		t.Fatalf("expired activity returned: %+v", body.Events)
	}
	if len(auditStore.events) != 1 {
		t.Fatalf("expired activity remained stored: %+v", auditStore.events)
	}
}

type memoryAuditStore struct {
	events []AuditEvent
}

func (s *memoryAuditStore) CreateAuditEvent(_ context.Context, event AuditEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *memoryAuditStore) ListAuditEvents(_ context.Context, query AuditQuery) ([]AuditEvent, error) {
	var events []AuditEvent
	for _, event := range s.events {
		if query.AccountID != "" && event.AccountID != query.AccountID {
			continue
		}
		if !query.BeforeAt.IsZero() &&
			(event.OccurredAt.After(query.BeforeAt) ||
				(event.OccurredAt.Equal(query.BeforeAt) && event.EventID >= query.BeforeID)) {
			continue
		}
		events = append(events, event)
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].OccurredAt.Equal(events[j].OccurredAt) {
			return events[i].EventID > events[j].EventID
		}
		return events[i].OccurredAt.After(events[j].OccurredAt)
	})
	if query.Limit > 0 && len(events) > query.Limit {
		events = events[:query.Limit]
	}
	return events, nil
}

func (s *memoryAuditStore) DeleteAuditEventsBefore(_ context.Context, cutoff time.Time) error {
	var events []AuditEvent
	for _, event := range s.events {
		if !event.OccurredAt.Before(cutoff) {
			events = append(events, event)
		}
	}
	s.events = events
	return nil
}
