package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bytemare/opaque"
	"github.com/davicbtoliveira/TermKeep/internal/server"
)

func TestBootstrapCreatesZeroKnowledgeVault(t *testing.T) {
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

	result, err := Bootstrap(context.Background(), Config{ServerURL: srv.URL}, BootstrapInput{
		Email:                 "admin@example.com",
		MasterPassword:        "TermKeep#2026",
		ConfirmMasterPassword: "TermKeep#2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer result.Vault.Clear()

	if result.RecoveryKey == "" {
		t.Fatal("bootstrap did not return recovery key for one-time display")
	}
	if store.account == nil || !store.account.Administrator {
		t.Fatal("bootstrap did not persist an administrator")
	}
	knownPlaintext := []byte("TermKeep#2026")
	if bytes.Contains(traffic.Bytes(), knownPlaintext) ||
		bytes.Contains(store.account.OpaqueRecord, knownPlaintext) ||
		bytes.Contains(store.account.PasswordVaultEnvelope, knownPlaintext) ||
		bytes.Contains(store.account.RecoveryVaultEnvelope, knownPlaintext) {
		t.Fatal("master password appeared outside client memory")
	}

	login, err := Login(context.Background(), Config{ServerURL: srv.URL}, LoginInput{
		Email:          "admin@example.com",
		MasterPassword: "TermKeep#2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer login.Clear()
	if !bytes.Equal(login.VaultKey, result.Vault.Key) {
		t.Fatal("OPAQUE login did not unlock bootstrap vault")
	}
	if _, err := Login(context.Background(), Config{ServerURL: srv.URL}, LoginInput{
		Email:          "admin@example.com",
		MasterPassword: "WrongPassword#2026",
	}); err == nil {
		t.Fatal("wrong master password authenticated")
	}
}

type schemaVersion struct{}

func (schemaVersion) SchemaVersion(context.Context) (int, error) { return 2, nil }

type bootstrapStore struct {
	account *server.BootstrapAccount
}

func (s *bootstrapStore) InstanceEmpty(context.Context) (bool, error) {
	return s.account == nil, nil
}

func (s *bootstrapStore) CreateBootstrap(_ context.Context, account server.BootstrapAccount) error {
	if s.account != nil {
		return server.ErrBootstrapClosed
	}
	s.account = &account
	return nil
}

func (s *bootstrapStore) FindAccount(_ context.Context, email string) (server.StoredAccount, error) {
	if s.account == nil || s.account.Email != email {
		return server.StoredAccount{}, server.ErrAccountNotFound
	}
	return server.StoredAccount{
		AccountID:             s.account.AccountID,
		Email:                 s.account.Email,
		OpaqueRecord:          s.account.OpaqueRecord,
		PasswordVaultEnvelope: s.account.PasswordVaultEnvelope,
		RecoveryVaultEnvelope: s.account.RecoveryVaultEnvelope,
	}, nil
}

func bootstrapAuthService(t *testing.T, store server.BootstrapStore) *server.AuthService {
	t.Helper()
	configuration := opaque.DefaultConfiguration()
	opaqueServer, err := opaque.NewServer(configuration)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, publicKey := configuration.KeyGen()
	if err := opaqueServer.SetKeyMaterial(&opaque.ServerKeyMaterial{
		PrivateKey:     privateKey,
		PublicKeyBytes: publicKey.Encode(),
		OPRFGlobalSeed: configuration.GenerateOPRFSeed(),
	}); err != nil {
		t.Fatal(err)
	}
	return server.NewAuthService(opaqueServer, store)
}
