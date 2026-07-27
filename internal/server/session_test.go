package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLoginCreatesVisibleOnlineSession(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	sessions := NewSessionService(store, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, sessions)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/sessions", token)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("list sessions status: want 200, got %d", response.StatusCode)
	}
	var body struct {
		Sessions []struct {
			SessionID string    `json:"session_id"`
			CreatedAt time.Time `json:"created_at"`
			LastUsed  time.Time `json:"last_used_at"`
			Current   bool      `json:"current"`
		} `json:"sessions"`
	}
	decodeJSON(t, response, &body)
	if len(body.Sessions) != 1 {
		t.Fatalf("sessions: want 1, got %d", len(body.Sessions))
	}
	session := body.Sessions[0]
	if session.SessionID == "" || session.CreatedAt.IsZero() || session.LastUsed.IsZero() || !session.Current {
		t.Fatalf("incomplete current session: %+v", session)
	}
}

func TestOnlineSessionShowsHostAndApproximateIP(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	sessions := NewSessionService(store, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, sessions)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	login := mustLoginResponseFromHost(t, server, "admin@example.com", password, "workstation")

	response := getJSONWithAuth(t, server.URL+"/api/v1/sessions", login.AccessToken)
	var body struct {
		Sessions []OnlineSession `json:"sessions"`
	}
	decodeJSON(t, response, &body)
	if len(body.Sessions) != 1 {
		t.Fatalf("sessions: want 1, got %d", len(body.Sessions))
	}
	if body.Sessions[0].Host != "workstation" || body.Sessions[0].SourceIP != "127.0.0.1" {
		t.Fatalf("unexpected session metadata: %+v", body.Sessions[0])
	}
}

func TestUserRevokesRemoteOnlineSession(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	sessions := NewSessionService(store, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, sessions)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	remote := mustLoginResponseFromHost(t, server, "admin@example.com", password, "laptop")
	current := mustLoginResponseFromHost(t, server, "admin@example.com", password, "desktop")

	listResponse := getJSONWithAuth(t, server.URL+"/api/v1/sessions", current.AccessToken)
	var list struct {
		Sessions []OnlineSession `json:"sessions"`
	}
	decodeJSON(t, listResponse, &list)
	var remoteID string
	for _, item := range list.Sessions {
		if item.Host == "laptop" {
			remoteID = item.SessionID
		}
	}
	if remoteID == "" {
		t.Fatal("remote session missing from list")
	}

	request, err := http.NewRequest(http.MethodDelete, server.URL+"/api/v1/sessions/"+remoteID, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+current.AccessToken)
	revokeResponse, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke session status: want 204, got %d", revokeResponse.StatusCode)
	}

	rejected := getJSONWithAuth(t, server.URL+"/api/v1/sessions", remote.AccessToken)
	rejected.Body.Close()
	if rejected.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked session status: want 401, got %d", rejected.StatusCode)
	}
}

func TestAuthenticatedOperationUpdatesSessionLastUse(t *testing.T) {
	store := &memoryBootstrapStore{}
	auth := newTestAuthService(t, store)
	sessions := NewSessionService(store, auth)
	handler := NewHandler("test", stubSchema{version: 1}, nil, auth, sessions)
	server := httptest.NewServer(handler)
	defer server.Close()

	password := []byte("TermKeep#2026")
	mustBootstrap(t, server, "admin@example.com", password)
	token := mustLogin(t, server, "admin@example.com", password)

	response := getJSONWithAuth(t, server.URL+"/api/v1/sessions", token)
	var body struct {
		Sessions []OnlineSession `json:"sessions"`
	}
	decodeJSON(t, response, &body)
	if len(body.Sessions) != 1 {
		t.Fatalf("sessions: want 1, got %d", len(body.Sessions))
	}
	if !body.Sessions[0].LastUsed.After(body.Sessions[0].CreatedAt) {
		t.Fatalf("last use was not updated: %+v", body.Sessions[0])
	}
}
