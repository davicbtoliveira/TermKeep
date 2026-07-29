package clipboard

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	ClearDelay       = 30 * time.Second
	operationTimeout = 2 * time.Second
)

// ErrUnavailable means no supported Linux clipboard command is usable.
var ErrUnavailable = errors.New("clipboard unavailable")

// Backend is the system boundary required for safe clipboard cleanup.
type Backend interface {
	Write(ctx context.Context, value string) error
	Read(ctx context.Context) (string, error)
	Clear(ctx context.Context) error
}

type command struct {
	path string
	args []string
}

type commandBackend struct {
	write command
	read  command
}

// Open selects an available Wayland or X11 clipboard backend.
func Open() (Backend, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		write, writeErr := exec.LookPath("wl-copy")
		read, readErr := exec.LookPath("wl-paste")
		if writeErr == nil && readErr == nil {
			return commandBackend{
				write: command{
					path: write,
					args: []string{"--type", "text/plain"},
				},
				read: command{
					path: read,
					args: []string{"--no-newline"},
				},
			}, nil
		}
	}
	if os.Getenv("DISPLAY") != "" {
		if path, err := exec.LookPath("xclip"); err == nil {
			return commandBackend{
				write: command{
					path: path,
					args: []string{"-selection", "clipboard", "-in"},
				},
				read: command{
					path: path,
					args: []string{"-selection", "clipboard", "-out"},
				},
			}, nil
		}
		if path, err := exec.LookPath("xsel"); err == nil {
			return commandBackend{
				write: command{
					path: path,
					args: []string{"--clipboard", "--input"},
				},
				read: command{
					path: path,
					args: []string{"--clipboard", "--output"},
				},
			}, nil
		}
	}
	return nil, ErrUnavailable
}

func (backend commandBackend) Write(
	ctx context.Context,
	value string,
) error {
	cmd := exec.CommandContext(
		ctx, backend.write.path, backend.write.args...)
	cmd.Stdin = strings.NewReader(value)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("clipboard write failed: %w", err)
	}
	return nil
}

func (backend commandBackend) Read(ctx context.Context) (string, error) {
	cmd := exec.CommandContext(
		ctx, backend.read.path, backend.read.args...)
	value, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("clipboard read failed: %w", err)
	}
	return string(value), nil
}

func (backend commandBackend) Clear(ctx context.Context) error {
	return backend.Write(ctx, "")
}

// Copy writes value and clears it after clearAfter only when still unchanged.
func Copy(
	ctx context.Context,
	backend Backend,
	value string,
	clearAfter time.Duration,
) (<-chan error, error) {
	if err := backend.Write(ctx, value); err != nil {
		return nil, err
	}
	cleanup := make(chan error, 1)
	go func() {
		timer := time.NewTimer(clearAfter)
		defer timer.Stop()
		<-timer.C
		cleanupCtx, cancel := context.WithTimeout(
			context.Background(), operationTimeout)
		defer cancel()
		current, err := backend.Read(cleanupCtx)
		if err == nil && current == value {
			err = backend.Clear(cleanupCtx)
		}
		cleanup <- err
		close(cleanup)
	}()
	return cleanup, nil
}
