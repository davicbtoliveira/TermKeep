package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/davicbtoliveira/TermKeep/internal/client"
)

type UnlockMaterial struct {
	AccountID   string `json:"account_id"`
	Email       string `json:"email"`
	VaultKey    []byte `json:"vault_key"`
	AccessToken []byte `json:"access_token"`
	ServerURL   string `json:"server_url"`
	CACertFile  string `json:"ca_cert_file"`
}

// Launch starts the per-terminal agent and transfers unlocked material
// through an anonymous pipe rather than command arguments or environment.
func Launch(ctx context.Context, executable string, scope Scope, material UnlockMaterial, autoLock time.Duration) error {
	if executable == "" {
		return errors.New("agent executable is required")
	}
	if scope.OwnerUID != uint32(os.Getuid()) {
		return errors.New("session owner must be the current OS user")
	}
	if scope.OwnerPID <= 0 || scope.SocketPath == "" {
		return errors.New("complete terminal session scope is required")
	}
	if autoLock < 0 {
		return errors.New("auto-lock duration cannot be negative")
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create agent startup pipe: %w", err)
	}
	defer reader.Close()

	command := exec.Command(
		executable,
		"__session-agent",
		scope.SocketPath,
		strconv.Itoa(scope.OwnerPID),
		strconv.FormatInt(int64(autoLock), 10),
	)
	command.ExtraFiles = []*os.File{reader}
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		writer.Close()
		return fmt.Errorf("open null device for agent: %w", err)
	}
	defer null.Close()
	command.Stdin = null
	command.Stdout = null
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		writer.Close()
		return fmt.Errorf("start session agent: %w", err)
	}
	reader.Close()

	encodeErr := json.NewEncoder(writer).Encode(material)
	closeErr := writer.Close()
	if encodeErr != nil || closeErr != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return errors.New("send unlocked material to session agent")
	}

	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	startupTimer := time.NewTimer(3 * time.Second)
	defer startupTimer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = command.Process.Kill()
			return ctx.Err()
		case err := <-exited:
			return fmt.Errorf("session agent exited during startup: %w", err)
		case <-startupTimer.C:
			_ = command.Process.Kill()
			return errors.New("session agent did not become ready")
		case <-ticker.C:
			probeCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
			info, err := Status(probeCtx, scope.SocketPath)
			cancel()
			if err == nil && info.AgentPID == command.Process.Pid {
				return nil
			}
		}
	}
}

// RunAgentProcess is the private subprocess entry point used by the client
// executable. startup must be the inherited anonymous pipe at file descriptor
// 3.
func RunAgentProcess(args []string, startup *os.File) error {
	if len(args) != 3 || startup == nil {
		return errors.New("invalid session agent startup")
	}
	ownerPID, err := strconv.Atoi(args[1])
	if err != nil || ownerPID <= 0 {
		return errors.New("invalid session owner PID")
	}
	autoLockValue, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil || autoLockValue < 0 {
		return errors.New("invalid session auto-lock duration")
	}
	if err := disableCoreDumps(); err != nil {
		return fmt.Errorf("disable agent core dumps: %w", err)
	}

	var material UnlockMaterial
	decoder := json.NewDecoder(io.LimitReader(startup, 1<<20))
	if err := decoder.Decode(&material); err != nil {
		return fmt.Errorf("read agent startup material: %w", err)
	}
	_ = startup.Close()
	defer clearBytes(material.VaultKey)
	defer clearBytes(material.AccessToken)

	agentConfig := AgentConfig{
		SocketPath:  args[0],
		OwnerUID:    uint32(os.Getuid()),
		OwnerPID:    ownerPID,
		AccountID:   material.AccountID,
		Email:       material.Email,
		VaultKey:    material.VaultKey,
		AccessToken: material.AccessToken,
		AutoLock:    time.Duration(autoLockValue),
	}
	if material.ServerURL != "" {
		cfg := client.Config{ServerURL: material.ServerURL, CACertFile: material.CACertFile}
		agentConfig.RevokeOnline = func(ctx context.Context, token []byte) error {
			return client.RevokeSession(ctx, cfg, string(token), "current")
		}
	}
	agent, err := NewAgent(agentConfig)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer agent.Close()
	return agent.Serve(ctx)
}

func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
