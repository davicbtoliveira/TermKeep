package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type AgentConfig struct {
	SocketPath   string
	OwnerUID     uint32
	OwnerPID     int
	AccountID    string
	Email        string
	VaultKey     []byte
	AccessToken  []byte
	AutoLock     time.Duration
	RevokeOnline func(context.Context, []byte) error
}

type Info struct {
	AccountID string `json:"account_id"`
	Email     string `json:"email"`
	AgentPID  int    `json:"agent_pid"`
}

type Agent struct {
	listener     *net.UnixListener
	socketPath   string
	ownerUID     uint32
	ownerPID     int
	ownerStart   string
	accountID    string
	email        string
	vaultKey     []byte
	accessToken  []byte
	revokeOnline func(context.Context, []byte) error
	memoryLocked bool
	autoLock     *time.Timer
	autoLockFor  time.Duration
	timerMu      sync.Mutex
	closed       bool
	closeOnce    sync.Once
	done         chan struct{}
}

type request struct {
	Action string `json:"action"`
}

type response struct {
	Info  *Info  `json:"info,omitempty"`
	Token []byte `json:"token,omitempty"`
	Error string `json:"error,omitempty"`
}

// NewAgent binds a terminal session socket and takes an in-memory copy of the
// unlocked material. Callers remain responsible for clearing their copy.
func NewAgent(cfg AgentConfig) (*Agent, error) {
	if cfg.SocketPath == "" {
		return nil, errors.New("session socket path is required")
	}
	var ownerStart string
	if cfg.OwnerPID > 0 {
		var err error
		ownerStart, err = processStartTime(cfg.OwnerPID)
		if err != nil {
			return nil, fmt.Errorf("inspect session owner: %w", err)
		}
	}
	address := &net.UnixAddr{Name: cfg.SocketPath, Net: "unix"}
	listener, err := net.ListenUnix("unix", address)
	if err != nil {
		return nil, fmt.Errorf("listen on session socket: %w", err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(cfg.SocketPath)
		return nil, fmt.Errorf("restrict session socket: %w", err)
	}
	agent := &Agent{
		listener:     listener,
		socketPath:   cfg.SocketPath,
		ownerUID:     cfg.OwnerUID,
		ownerPID:     cfg.OwnerPID,
		ownerStart:   ownerStart,
		accountID:    cfg.AccountID,
		email:        cfg.Email,
		vaultKey:     append([]byte(nil), cfg.VaultKey...),
		accessToken:  append([]byte(nil), cfg.AccessToken...),
		revokeOnline: cfg.RevokeOnline,
		autoLockFor:  cfg.AutoLock,
		done:         make(chan struct{}),
	}
	if len(agent.vaultKey) > 0 {
		agent.memoryLocked = unix.Mlock(agent.vaultKey) == nil
	}
	if cfg.AutoLock > 0 {
		agent.autoLock = time.NewTimer(cfg.AutoLock)
		go agent.monitorAutoLock()
	}
	if cfg.OwnerPID > 0 {
		go agent.monitorOwner()
	}
	return agent, nil
}

func (a *Agent) monitorAutoLock() {
	select {
	case <-a.autoLock.C:
		_ = a.Close()
	case <-a.done:
	}
}

func (a *Agent) monitorOwner() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			start, err := processStartTime(a.ownerPID)
			if err != nil || start != a.ownerStart {
				_ = a.Close()
				return
			}
		case <-a.done:
			return
		}
	}
}

func processStartTime(pid int) (string, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(stat), ')')
	if end < 0 {
		return "", errors.New("malformed process status")
	}
	fields := strings.Fields(string(stat[end+1:]))
	if len(fields) <= 19 {
		return "", errors.New("malformed process status")
	}
	return fields[19], nil
}

// Serve handles local session requests until the context is canceled or the
// agent is closed.
func (a *Agent) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = a.Close()
	}()
	for {
		conn, err := a.listener.AcceptUnix()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept session connection: %w", err)
		}
		a.handle(conn)
	}
}

func (a *Agent) handle(conn *net.UnixConn) {
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || uid != a.ownerUID {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	var req request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		return
	}
	a.touch()
	switch req.Action {
	case "status":
		_ = json.NewEncoder(conn).Encode(response{Info: &Info{
			AccountID: a.accountID,
			Email:     a.email,
			AgentPID:  os.Getpid(),
		}})
	case "logout":
		_ = json.NewEncoder(conn).Encode(response{})
		_ = a.Close()
	case "access-token":
		_ = json.NewEncoder(conn).Encode(response{Token: a.accessToken})
	default:
		_ = json.NewEncoder(conn).Encode(response{Error: "unknown session action"})
	}
}

func (a *Agent) touch() {
	a.timerMu.Lock()
	defer a.timerMu.Unlock()
	if !a.closed && a.autoLock != nil {
		a.autoLock.Reset(a.autoLockFor)
	}
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		uid      uint32
		innerErr error
	)
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			innerErr = err
			return
		}
		uid = credentials.Uid
	}); err != nil {
		return 0, err
	}
	return uid, innerErr
}

// Close clears unlocked material and removes the local socket.
func (a *Agent) Close() error {
	var closeErr error
	a.closeOnce.Do(func() {
		token := append([]byte(nil), a.accessToken...)
		close(a.done)
		a.timerMu.Lock()
		a.closed = true
		if a.autoLock != nil {
			a.autoLock.Stop()
		}
		a.timerMu.Unlock()
		clearBytes(a.vaultKey)
		if a.memoryLocked {
			_ = unix.Munlock(a.vaultKey)
		}
		a.vaultKey = nil
		clearBytes(a.accessToken)
		a.accessToken = nil
		closeErr = a.listener.Close()
		_ = os.Remove(a.socketPath)
		if a.revokeOnline != nil && len(token) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = a.revokeOnline(ctx, token)
			cancel()
		}
		clearBytes(token)
	})
	return closeErr
}

// Status reports whether the socket still owns an unlocked session.
func Status(ctx context.Context, socketPath string) (Info, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return Info{}, fmt.Errorf("connect to session agent: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request{Action: "status"}); err != nil {
		return Info{}, fmt.Errorf("request session status: %w", err)
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return Info{}, fmt.Errorf("read session status: %w", err)
	}
	if res.Error != "" {
		return Info{}, errors.New(res.Error)
	}
	if res.Info == nil {
		return Info{}, errors.New("session agent returned no status")
	}
	return *res.Info, nil
}

// AccessToken returns a copy of online authorization material to an
// owner-authenticated local client.
func AccessToken(ctx context.Context, socketPath string) ([]byte, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to session agent: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request{Action: "access-token"}); err != nil {
		return nil, fmt.Errorf("request online token: %w", err)
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return nil, fmt.Errorf("read online token: %w", err)
	}
	if res.Error != "" {
		return nil, errors.New(res.Error)
	}
	if len(res.Token) == 0 {
		return nil, errors.New("session agent returned no online token")
	}
	return res.Token, nil
}

// Logout clears unlocked material and ends the terminal session.
func Logout(ctx context.Context, socketPath string) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("connect to session agent: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	if err := json.NewEncoder(conn).Encode(request{Action: "logout"}); err != nil {
		return fmt.Errorf("request session logout: %w", err)
	}
	var res response
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		return fmt.Errorf("read session logout: %w", err)
	}
	if res.Error != "" {
		return errors.New(res.Error)
	}
	return nil
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
