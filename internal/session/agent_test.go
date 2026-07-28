package session_test

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestAgentReportsUnlockedSession(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath:  socketPath,
		OwnerUID:    uint32(os.Getuid()),
		AccountID:   "account-123",
		Email:       "user@example.com",
		VaultKey:    []byte("01234567890123456789012345678901"),
		AccessToken: []byte("access-token"),
		AutoLock:    time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	info, err := session.Status(ctx, socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.AccountID != "account-123" || info.Email != "user@example.com" {
		t.Fatalf("unexpected session info: %+v", info)
	}
}

func TestAgentProvidesOnlineTokenToOwner(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath:  socketPath,
		OwnerUID:    uint32(os.Getuid()),
		VaultKey:    []byte("01234567890123456789012345678901"),
		AccessToken: []byte("access-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	token, err := session.AccessToken(ctx, socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(token) != "access-token" {
		t.Fatalf("online token: got %q", token)
	}
}

func TestAgentAllowsOfflineSessionWithoutToken(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		VaultKey:   []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	token, err := session.AccessToken(ctx, socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 0 {
		t.Fatalf("offline session returned token %q", token)
	}
}

func TestAgentSealsAndOpensLoginWithoutExposingVaultKey(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	vaultKey := []byte("01234567890123456789012345678901")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		AccountID:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		VaultKey:   vaultKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	login := client.LoginItem{
		ItemID:   "11111111-1111-4111-8111-111111111111",
		Name:     "Production",
		Username: "operator",
		Password: "Password-Sentinel",
	}
	encrypted, err := session.SealLogin(ctx, socketPath, login, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Envelope, []byte(login.Password)) ||
		bytes.Contains(encrypted.Envelope, vaultKey) {
		t.Fatal("sealed response exposed plaintext or vault key")
	}
	opened, err := session.OpenLogin(ctx, socketPath, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, login) {
		t.Fatalf("opened login differs:\nwant: %+v\ngot:  %+v", login, opened)
	}
}

func TestAgentSealsAndOpensSecureNoteWithoutExposingVaultKey(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	vaultKey := []byte("01234567890123456789012345678901")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		AccountID:  "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		VaultKey:   vaultKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	note := client.SecureNoteItem{
		ItemID:  "11111111-1111-4111-8111-111111111111",
		Title:   "Recovery procedure",
		Content: "Sensitive-Note-Content-Sentinel",
	}
	encrypted, err := session.SealSecureNote(
		ctx, socketPath, note, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Envelope, []byte(note.Title)) ||
		bytes.Contains(encrypted.Envelope, []byte(note.Content)) ||
		bytes.Contains(encrypted.Envelope, vaultKey) {
		t.Fatal("sealed response exposed plaintext or vault key")
	}
	opened, err := session.OpenSecureNote(ctx, socketPath, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(opened, note) {
		t.Fatalf("opened Note differs:\nwant: %+v\ngot:  %+v",
			note, opened)
	}
}

func TestAgentSocketIsOwnerOnly(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		VaultKey:   []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = agent.Close() })

	stat, err := os.Stat(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := stat.Mode().Perm(); got != 0o600 {
		t.Fatalf("socket mode: want 0600, got %04o", got)
	}
}

func TestAgentRejectsPeerFromAnotherOSUser(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid() + 1),
		VaultKey:   []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	if _, err := session.Status(ctx, socketPath); err == nil {
		t.Fatal("status from unauthorized peer succeeded")
	}
}

func TestLogoutEndsUnlockedSession(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath:  socketPath,
		OwnerUID:    uint32(os.Getuid()),
		VaultKey:    []byte("01234567890123456789012345678901"),
		AccessToken: []byte("access-token"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	if err := session.Logout(ctx, socketPath); err != nil {
		t.Fatal(err)
	}
	if _, err := session.Status(ctx, socketPath); err == nil {
		t.Fatal("status succeeded after logout")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket remains after logout: %v", err)
	}
}

func TestAgentAutoLocksAfterInactivity(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		VaultKey:   []byte("01234567890123456789012345678901"),
		AutoLock:   50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("session remained unlocked after inactivity timeout")
}

func TestAuthorizedUseResetsAutoLock(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		VaultKey:   []byte("01234567890123456789012345678901"),
		AutoLock:   100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	for range 3 {
		time.Sleep(60 * time.Millisecond)
		if _, err := session.Status(ctx, socketPath); err != nil {
			t.Fatalf("active session locked early: %v", err)
		}
	}
}

func TestDisabledAutoLockDoesNotExpire(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		VaultKey:   []byte("01234567890123456789012345678901"),
		AutoLock:   0,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	time.Sleep(150 * time.Millisecond)
	if _, err := session.Status(ctx, socketPath); err != nil {
		t.Fatalf("disabled auto-lock ended session: %v", err)
	}
}

func TestAgentEndsWhenOwnerProcessExits(t *testing.T) {
	owner := exec.Command("sleep", "30")
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if owner.Process != nil {
			_ = owner.Process.Kill()
			_ = owner.Wait()
		}
	})

	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath: socketPath,
		OwnerUID:   uint32(os.Getuid()),
		OwnerPID:   owner.Process.Pid,
		VaultKey:   []byte("01234567890123456789012345678901"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = agent.Close()
		if err := <-done; err != nil {
			t.Errorf("serve agent: %v", err)
		}
	})

	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Wait(); err == nil {
		t.Fatal("killed owner exited successfully")
	}
	owner.Process = nil

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("session remained unlocked after owner exited")
}

func TestAgentClosesLocallyBeforeRemoteRevocationReturns(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "agent.sock")
	revokeStarted := make(chan struct{})
	releaseRevoke := make(chan struct{})
	agent, err := session.NewAgent(session.AgentConfig{
		SocketPath:  socketPath,
		OwnerUID:    uint32(os.Getuid()),
		VaultKey:    []byte("01234567890123456789012345678901"),
		AccessToken: []byte("access-token"),
		RevokeOnline: func(context.Context, []byte) error {
			close(revokeStarted)
			<-releaseRevoke
			return context.DeadlineExceeded
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	closed := make(chan struct{})
	go func() {
		_ = agent.Close()
		close(closed)
	}()
	<-revokeStarted
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("local socket remains during offline revocation: %v", err)
	}
	close(releaseRevoke)
	<-closed
}
