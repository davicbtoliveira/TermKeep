package session_test

import (
	"os"
	"testing"

	"github.com/creack/pty"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

func TestSameTerminalAndShellResolveSameSession(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()

	first, err := session.ScopeForTerminal(terminal, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.ScopeForTerminal(terminal, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if first.SocketPath != second.SocketPath {
		t.Fatalf("same terminal resolved different sockets: %q and %q", first.SocketPath, second.SocketPath)
	}
}

func TestDifferentTerminalsResolveDifferentSessions(t *testing.T) {
	runtimeDir := t.TempDir()
	if err := os.Chmod(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	firstMaster, firstTerminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer firstMaster.Close()
	defer firstTerminal.Close()
	secondMaster, secondTerminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer secondMaster.Close()
	defer secondTerminal.Close()

	first, err := session.ScopeForTerminal(firstTerminal, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	second, err := session.ScopeForTerminal(secondTerminal, os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if first.SocketPath == second.SocketPath {
		t.Fatalf("different terminals share socket %q", first.SocketPath)
	}
}
