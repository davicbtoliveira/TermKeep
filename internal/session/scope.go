package session

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type Scope struct {
	SocketPath string
	OwnerPID   int
	OwnerUID   uint32
}

// CurrentScope identifies the terminal and shell that invoked the client.
func CurrentScope(terminal *os.File) (Scope, error) {
	return ScopeForTerminal(terminal, os.Getppid())
}

// ScopeForTerminal resolves one deterministic, user-private socket per
// terminal and owner process.
func ScopeForTerminal(terminal *os.File, ownerPID int) (Scope, error) {
	if terminal == nil || !term.IsTerminal(int(terminal.Fd())) {
		return Scope{}, errors.New("terminal session requires a TTY")
	}
	if ownerPID <= 0 {
		return Scope{}, errors.New("terminal session owner PID is required")
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(terminal.Fd()), &stat); err != nil {
		return Scope{}, fmt.Errorf("inspect terminal: %w", err)
	}
	uid := uint32(os.Getuid())
	runtimeDir, err := privateRuntimeDir(uid)
	if err != nil {
		return Scope{}, err
	}
	return Scope{
		SocketPath: filepath.Join(runtimeDir, fmt.Sprintf("session-%x-%d.sock", uint64(stat.Rdev), ownerPID)),
		OwnerPID:   ownerPID,
		OwnerUID:   uid,
	}, nil
}

func privateRuntimeDir(uid uint32) (string, error) {
	base := os.Getenv("XDG_RUNTIME_DIR")
	if base != "" {
		if err := validatePrivateDirectory(base, uid); err != nil {
			return "", fmt.Errorf("validate XDG runtime directory: %w", err)
		}
		return ensurePrivateDirectory(filepath.Join(base, "termkeep"), uid)
	}
	return ensurePrivateDirectory(fmt.Sprintf("/tmp/termkeep-%d", uid), uid)
}

func ensurePrivateDirectory(path string, uid uint32) (string, error) {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", fmt.Errorf("create session runtime directory: %w", err)
	}
	if err := validatePrivateDirectory(path, uid); err != nil {
		return "", fmt.Errorf("validate session runtime directory: %w", err)
	}
	return path, nil
}

func validatePrivateDirectory(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("path is not a directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s permissions must exclude group and other users", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid {
		return fmt.Errorf("%s is not owned by UID %d", path, uid)
	}
	return nil
}
