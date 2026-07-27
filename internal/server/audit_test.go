package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
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

func TestSuccessfulLoginAuditsLoginAndSessionCreation(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	eventTypes := make(map[string]AuditEvent)
	for _, event := range body.Events {
		eventTypes[event.Type] = event
	}
	login, ok := eventTypes["login.succeeded"]
	if !ok || login.AccountID != store.account.AccountID ||
		login.ActorID != store.account.AccountID {
		t.Fatalf("login success event missing or incomplete: %+v", body.Events)
	}
	session, ok := eventTypes["session.created"]
	if !ok || session.SessionID == "" ||
		session.AccountID != store.account.AccountID {
		t.Fatalf("session creation event missing or incomplete: %+v", body.Events)
	}
}

func TestFailedLoginIsVisibleInAccountActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	start := startLoginAttempt(t, server, "admin@example.com", password)
	var startBody struct {
		LoginID string `json:"login_id"`
	}
	decodeJSON(t, start, &startBody)
	failed := postJSON(t, server.URL+"/api/v1/login/finish", map[string]string{
		"login_id": startBody.LoginID,
		"ke3":      base64.RawStdEncoding.EncodeToString([]byte("invalid KE3")),
	})
	failed.Body.Close()
	if failed.StatusCode != http.StatusUnauthorized {
		t.Fatalf("failed login status: want 401, got %d", failed.StatusCode)
	}

	token := mustLogin(t, server, "admin@example.com", password)
	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "login.failed" &&
			event.AccountID == store.account.AccountID &&
			event.ActorID == "" {
			return
		}
	}
	t.Fatalf("login failure event missing: %+v", body.Events)
}

func TestClientReportedLoginFailureIsVisibleInAccountActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	start := startLoginAttempt(t, server, "admin@example.com", []byte("Wrong#Pass2026"))
	var startBody struct {
		LoginID string `json:"login_id"`
	}
	decodeJSON(t, start, &startBody)
	report := postJSON(t, server.URL+"/api/v1/login/fail", map[string]string{
		"login_id": startBody.LoginID,
	})
	report.Body.Close()
	if report.StatusCode != http.StatusNoContent {
		t.Fatalf("report login failure status: want 204, got %d", report.StatusCode)
	}

	token := mustLogin(t, server, "admin@example.com", password)
	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "login.failed" &&
			event.AccountID == store.account.AccountID {
			return
		}
	}
	t.Fatalf("client-reported login failure event missing: %+v", body.Events)
}

func TestThrottledLoginIsVisibleInAccountActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	for range 5 {
		response := startLoginAttempt(t, server, "admin@example.com", password)
		response.Body.Close()
	}
	throttled := startLoginAttempt(t, server, "admin@example.com", password)
	throttled.Body.Close()
	if throttled.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttled login status: want 429, got %d", throttled.StatusCode)
	}

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "login.throttled" &&
			event.AccountID == store.account.AccountID &&
			event.SourceIP == "127.0.0.1" {
			return
		}
	}
	t.Fatalf("login throttling event missing: %+v", body.Events)
}

func TestInviteCreationIsVisibleInAdministratorActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	invites := NewInviteService(store, auth)
	invites.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, invites, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	invite := mustCreateInvite(t, server, token, "friend@example.com")

	response := getJSONWithAuth(t, server.URL+"/api/v1/admin/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "invite.created" &&
			event.ActorID == store.account.AccountID &&
			event.InviteID == invite.InviteID {
			return
		}
	}
	t.Fatalf("invite creation event missing: %+v", body.Events)
}

func TestInvitedRegistrationIsVisibleInNewAccountActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	invites := NewInviteService(store, auth, audit)
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, invites, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	adminPassword := []byte("TermKeep#2026")
	userPassword := []byte("Friend#Pass2026")
	mustBootstrap(t, server, "admin@example.com", adminPassword)
	adminToken := mustLogin(t, server, "admin@example.com", adminPassword)
	invite := mustCreateInvite(t, server, adminToken, "friend@example.com")
	mustRegister(t, server, "friend@example.com", userPassword, invite.Token)
	userToken := mustLogin(t, server, "friend@example.com", userPassword)
	user := store.accounts["friend@example.com"]

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", userToken)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "registration.succeeded" &&
			event.AccountID == user.AccountID &&
			event.ActorID == user.AccountID {
			return
		}
	}
	t.Fatalf("registration event missing: %+v", body.Events)
}

func TestInviteRevocationIsVisibleInAdministratorActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	invites := NewInviteService(store, auth, audit)
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, invites, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)
	invite := mustCreateInvite(t, server, token, "friend@example.com")
	revoke := postJSONWithAuth(t,
		server.URL+"/api/v1/invites/"+invite.InviteID+"/revoke", nil, token)
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke invite status: want 204, got %d", revoke.StatusCode)
	}

	response := getJSONWithAuth(t, server.URL+"/api/v1/admin/activity", token)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "invite.revoked" &&
			event.ActorID == store.account.AccountID &&
			event.InviteID == invite.InviteID {
			return
		}
	}
	t.Fatalf("invite revocation event missing: %+v", body.Events)
}

func TestSessionRevocationIsVisibleInAccountActivity(t *testing.T) {
	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	sessions := NewSessionService(store, auth)
	sessions.audit = audit
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, sessions, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	mustLoginResponseFromHost(t, server, "admin@example.com", password, "remote")
	current := mustLoginResponseFromHost(t, server, "admin@example.com", password, "current")

	listResponse := getJSONWithAuth(t, server.URL+"/api/v1/sessions", current.AccessToken)
	var list struct {
		Sessions []OnlineSession `json:"sessions"`
	}
	decodeJSON(t, listResponse, &list)
	var remoteID string
	for _, session := range list.Sessions {
		if session.Host == "remote" {
			remoteID = session.SessionID
		}
	}
	request, err := http.NewRequest(
		http.MethodDelete, server.URL+"/api/v1/sessions/"+remoteID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+current.AccessToken)
	revoke, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	revoke.Body.Close()
	if revoke.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke session status: want 204, got %d", revoke.StatusCode)
	}

	response := getJSONWithAuth(t, server.URL+"/api/v1/activity", current.AccessToken)
	var body struct {
		Events []AuditEvent `json:"events"`
	}
	decodeJSON(t, response, &body)
	for _, event := range body.Events {
		if event.Type == "session.revoked" &&
			event.ActorID == store.account.AccountID &&
			event.SessionID == remoteID {
			return
		}
	}
	t.Fatalf("session revocation event missing: %+v", body.Events)
}

func TestAuditExcludesSecretsFromAPIStoreAndLogs(t *testing.T) {
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previousLogger)

	store := &memoryBootstrapStore{}
	auditStore := &memoryAuditStore{}
	audit := NewAuditLog(auditStore, defaultAuditRetention)
	auth := newTestAuthService(t, store)
	auth.audit = audit
	invites := NewInviteService(store, auth, audit)
	activity := NewActivityService(audit, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, invites, activity)
	server := httptest.NewServer(handler)
	defer server.Close()

	const password = "MasterPassword-Sentinel#2026"
	mustBootstrap(t, server, "admin@example.com", []byte(password))
	login := mustLoginResponse(t, server, "admin@example.com", []byte(password))
	invite := mustCreateInvite(t, server, login.AccessToken, "friend@example.com")
	forbiddenInput := map[string]string{
		"email":           "another@example.com",
		"master_password": "Master-Field-Sentinel",
		"recovery_key":    "Recovery-Key-Sentinel",
		"item_content":    "Item-Content-Sentinel",
		"search_term":     "Search-Term-Sentinel",
		"totp":            "TOTP-Sentinel",
	}
	rejected := postJSONWithAuth(
		t, server.URL+"/api/v1/invites", forbiddenInput, login.AccessToken)
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusBadRequest {
		t.Fatalf("secret-bearing unknown fields: want 400, got %d", rejected.StatusCode)
	}

	response := getJSONWithAuth(
		t, server.URL+"/api/v1/admin/activity", login.AccessToken)
	apiBody, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	stored, err := json.Marshal(auditStore.events)
	if err != nil {
		t.Fatal(err)
	}
	surfaces := map[string][]byte{
		"API":   apiBody,
		"store": stored,
		"logs":  logs.Bytes(),
	}
	for _, secret := range []string{
		password,
		"encrypted-recovery-envelope",
		login.AccessToken,
		invite.Token,
		"Master-Field-Sentinel",
		"Recovery-Key-Sentinel",
		"Item-Content-Sentinel",
		"Search-Term-Sentinel",
		"TOTP-Sentinel",
	} {
		for surface, contents := range surfaces {
			if strings.Contains(string(contents), secret) {
				t.Fatalf("%s contains forbidden secret %q", surface, secret)
			}
		}
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
