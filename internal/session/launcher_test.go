package session_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__session-agent" {
		startup := os.NewFile(3, "session-startup")
		if err := session.RunAgentProcess(os.Args[2:], startup); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestLaunchStartsPersistentAgentProcess(t *testing.T) {
	_, info := launchTestAgent(t)
	if info.AccountID != "account-123" || info.AgentPID == os.Getpid() {
		t.Fatalf("unexpected launched session: %+v", info)
	}
}

func TestAgentProcessDisablesCoreDumps(t *testing.T) {
	_, info := launchTestAgent(t)
	limits, err := os.ReadFile(fmt.Sprintf("/proc/%d/limits", info.AgentPID))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(limits), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 6 && strings.Join(fields[:4], " ") == "Max core file size" {
			if fields[4] != "0" || fields[5] != "0" {
				t.Fatalf("agent core limit: want 0/0, got %s/%s", fields[4], fields[5])
			}
			return
		}
	}
	t.Fatal("agent process limits omit core file size")
}

func launchTestAgent(t *testing.T) (session.Scope, session.Info) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scope := session.Scope{
		SocketPath: filepath.Join(t.TempDir(), "agent.sock"),
		OwnerPID:   os.Getpid(),
		OwnerUID:   uint32(os.Getuid()),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = session.Launch(ctx, executable, scope, session.UnlockMaterial{
		AccountID:   "account-123",
		Email:       "user@example.com",
		VaultKey:    []byte("01234567890123456789012345678901"),
		AccessToken: []byte("access-token"),
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Logout(context.Background(), scope.SocketPath) })

	info, err := session.Status(ctx, scope.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	return scope, info
}
