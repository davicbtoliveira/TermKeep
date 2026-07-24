package client

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

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
	if login.AccessToken == "" {
		t.Fatal("OPAQUE login did not return an access token")
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
	account      *server.BootstrapAccount
	accounts     map[string]*server.BootstrapAccount
	invites      []server.StoredInvite
	accessTokens map[string]server.StoredAccessToken
}

func (s *bootstrapStore) InstanceEmpty(context.Context) (bool, error) {
	return s.account == nil, nil
}

func (s *bootstrapStore) CreateBootstrap(_ context.Context, account server.BootstrapAccount) error {
	if s.account != nil {
		return server.ErrBootstrapClosed
	}
	s.account = &account
	s.accounts = map[string]*server.BootstrapAccount{account.Email: &account}
	return nil
}

func (s *bootstrapStore) FindAccount(_ context.Context, email string) (server.StoredAccount, error) {
	account, ok := s.accounts[email]
	if !ok {
		return server.StoredAccount{}, server.ErrAccountNotFound
	}
	return server.StoredAccount{
		AccountID:             account.AccountID,
		Email:                 account.Email,
		Administrator:         account.Administrator,
		OpaqueRecord:          account.OpaqueRecord,
		PasswordVaultEnvelope: account.PasswordVaultEnvelope,
		RecoveryVaultEnvelope: account.RecoveryVaultEnvelope,
	}, nil
}

func (s *bootstrapStore) CreateAccessToken(_ context.Context, token server.StoredAccessToken) error {
	if s.accessTokens == nil {
		s.accessTokens = make(map[string]server.StoredAccessToken)
	}
	s.accessTokens[string(token.TokenHash)] = token
	return nil
}

func (s *bootstrapStore) FindAccessToken(_ context.Context, tokenHash []byte) (server.StoredAccessToken, error) {
	if token, ok := s.accessTokens[string(tokenHash)]; ok {
		return token, nil
	}
	return server.StoredAccessToken{}, server.ErrAccessTokenNotFound
}

func (s *bootstrapStore) ValidateInvite(_ context.Context, tokenHash []byte, email string, now time.Time) error {
	for _, invite := range s.invites {
		if bytes.Equal(invite.TokenHash, tokenHash) &&
			invite.Email == email &&
			invite.ConsumedBy == "" &&
			invite.RevokedAt.IsZero() &&
			now.Before(invite.ExpiresAt) {
			return nil
		}
	}
	return server.ErrInvalidInvite
}

func (s *bootstrapStore) CreateInvitedAccount(_ context.Context, tokenHash []byte, account server.BootstrapAccount, now time.Time) error {
	if err := s.ValidateInvite(context.Background(), tokenHash, account.Email, now); err != nil {
		return err
	}
	s.accounts[account.Email] = &account
	for i := range s.invites {
		if bytes.Equal(s.invites[i].TokenHash, tokenHash) {
			s.invites[i].ConsumedBy = account.AccountID
			s.invites[i].ConsumedAt = now
			return nil
		}
	}
	return server.ErrInvalidInvite
}

func bootstrapAuthService(t *testing.T, store server.AuthStore) *server.AuthService {
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
