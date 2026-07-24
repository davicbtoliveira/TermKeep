package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/server"
)

func TestRegisterCreatesIndependentZeroKnowledgeVault(t *testing.T) {
	store := &bootstrapStore{}
	h := server.NewHandler("test", schemaVersion{}, nil, bootstrapAuthService(t, store))
	var traffic bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		traffic.Write(body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		h.ServeHTTP(w, r)
	}))
	defer srv.Close()

	admin, err := Bootstrap(context.Background(), Config{ServerURL: srv.URL}, BootstrapInput{
		Email:                 "admin@example.com",
		MasterPassword:        "TermKeep#2026",
		ConfirmMasterPassword: "TermKeep#2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Vault.Clear()

	inviteToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
	tokenHash := sha256.Sum256([]byte(inviteToken))
	store.invites = append(store.invites, server.StoredInvite{
		InviteID:  "2fcd3d71-5b9d-4d6d-97a0-68a463ee4a54",
		Email:     "friend@example.com",
		TokenHash: tokenHash[:],
		CreatedBy: admin.AccountID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	})

	registered, err := Register(context.Background(), Config{ServerURL: srv.URL}, RegisterInput{
		Email:                 "friend@example.com",
		InviteToken:           inviteToken,
		MasterPassword:        "Friend#Pass2026",
		ConfirmMasterPassword: "Friend#Pass2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registered.Vault.Clear()

	if registered.AccountID == admin.AccountID {
		t.Fatal("invited registration reused the administrator account UUID")
	}
	if bytes.Contains(traffic.Bytes(), []byte("Friend#Pass2026")) {
		t.Fatal("invited master password appeared in HTTP traffic")
	}
	login, err := Login(context.Background(), Config{ServerURL: srv.URL}, LoginInput{
		Email:          "friend@example.com",
		MasterPassword: "Friend#Pass2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer login.Clear()
	if !bytes.Equal(login.VaultKey, registered.Vault.Key) {
		t.Fatal("invited account login did not unlock its own vault")
	}
}
