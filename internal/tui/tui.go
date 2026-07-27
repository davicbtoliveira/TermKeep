// Package tui implements the minimal TermKeep terminal UI: the instance
// state shown when termkeep runs without a subcommand.
package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/davicbtoliveira/TermKeep/internal/client"
)

// statusMsg carries the classified instance state into the update loop.
type statusMsg client.Status

// errMsg reports a configuration-level failure (e.g. insecure URL).
type errMsg error
type sessionsMsg []client.OnlineSession
type sessionsErrMsg error
type sessionRevokedMsg struct{}
type activityMsg client.ActivityPage
type activityErrMsg error

// model is the single-screen state: the shared status lines plus keys.
type model struct {
	cfg             client.Config
	lines           []string
	err             error
	loaded          bool
	vaultOpen       bool
	accessToken     string
	showSessions    bool
	sessionsLoading bool
	sessions        []client.OnlineSession
	selectedSession int
	sessionsErr     error
	showActivity    bool
	activityAll     bool
	activityLoading bool
	activityPage    client.ActivityPage
	activityErr     error
}

// Run starts the Bubble Tea program on the controlling terminal.
func Run(cfg client.Config) error {
	m := model{cfg: cfg}
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

// RunVault opens the minimal vault screen after client-side unlock. The key
// stays with the caller; this package receives no secret material.
func RunVault(cfg client.Config, accessToken string) error {
	m := model{cfg: cfg, vaultOpen: true, accessToken: accessToken}
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	return checkStatus(m.cfg)
}

// checkStatus performs the one-shot instance query off the UI goroutine.
func checkStatus(cfg client.Config) tea.Cmd {
	return func() tea.Msg {
		st, err := client.CheckStatus(context.Background(), cfg)
		if err != nil {
			return errMsg(err)
		}
		return statusMsg(st)
	}
}

func loadSessions(cfg client.Config, accessToken string) tea.Cmd {
	return func() tea.Msg {
		sessions, err := client.ListSessions(context.Background(), cfg, accessToken)
		if err != nil {
			return sessionsErrMsg(err)
		}
		return sessionsMsg(sessions)
	}
}

func revokeSession(cfg client.Config, accessToken, sessionID string) tea.Cmd {
	return func() tea.Msg {
		if err := client.RevokeSession(context.Background(), cfg, accessToken, sessionID); err != nil {
			return sessionsErrMsg(err)
		}
		return sessionRevokedMsg{}
	}
}

func loadActivity(cfg client.Config, accessToken string, allAccounts bool, cursor string) tea.Cmd {
	return func() tea.Msg {
		page, err := client.ListActivity(
			context.Background(), cfg, accessToken, allAccounts, cursor)
		if err != nil {
			return activityErrMsg(err)
		}
		return activityMsg(page)
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "s":
			if m.vaultOpen && m.accessToken != "" {
				m.showActivity = false
				m.showSessions = true
				m.sessionsLoading = true
				m.sessionsErr = nil
				return m, loadSessions(m.cfg, m.accessToken)
			}
		case "a":
			if m.vaultOpen && m.accessToken != "" {
				m.showSessions = false
				m.showActivity = true
				m.activityAll = false
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(m.cfg, m.accessToken, false, "")
			}
		case "g":
			if m.showActivity && m.activityPage.CanViewAll {
				m.activityAll = !m.activityAll
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(
					m.cfg, m.accessToken, m.activityAll, "")
			}
		case "n":
			if m.showActivity && m.activityPage.NextCursor != "" {
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(
					m.cfg,
					m.accessToken,
					m.activityAll,
					m.activityPage.NextCursor,
				)
			}
		case "v":
			m.showSessions = false
			m.showActivity = false
			return m, nil
		case "j", "down":
			if m.showSessions && m.selectedSession+1 < len(m.sessions) {
				m.selectedSession++
			}
		case "k", "up":
			if m.showSessions && m.selectedSession > 0 {
				m.selectedSession--
			}
		case "x":
			if m.showSessions && m.selectedSession < len(m.sessions) {
				selected := m.sessions[m.selectedSession]
				if selected.Current {
					m.sessionsErr = fmt.Errorf("current session: use logout")
					return m, nil
				}
				return m, revokeSession(m.cfg, m.accessToken, selected.SessionID)
			}
		case "r":
			if m.showActivity {
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(m.cfg, m.accessToken, m.activityAll, "")
			}
			if m.showSessions {
				m.sessionsLoading = true
				m.sessionsErr = nil
				return m, loadSessions(m.cfg, m.accessToken)
			}
			m.loaded = false
			return m, checkStatus(m.cfg)
		}
	case statusMsg:
		m.loaded = true
		m.lines = client.Lines(m.cfg.ServerURL, client.Status(msg))
	case errMsg:
		m.loaded = true
		m.err = msg
		m.lines = []string{"Instance: " + m.cfg.ServerURL, "Status:   error — " + msg.Error()}
	case sessionsMsg:
		m.sessionsLoading = false
		m.sessions = []client.OnlineSession(msg)
		if m.selectedSession >= len(m.sessions) {
			m.selectedSession = 0
		}
	case sessionsErrMsg:
		m.sessionsLoading = false
		m.sessionsErr = msg
	case sessionRevokedMsg:
		m.sessionsLoading = true
		m.sessionsErr = nil
		return m, loadSessions(m.cfg, m.accessToken)
	case activityMsg:
		m.activityLoading = false
		m.activityPage = client.ActivityPage(msg)
	case activityErrMsg:
		m.activityLoading = false
		m.activityErr = msg
	}
	return m, nil
}

func (m model) View() string {
	if m.showActivity {
		return m.activityView()
	}
	if m.showSessions {
		return m.sessionsView()
	}
	var b strings.Builder
	b.WriteString("TermKeep\n\n")
	if !m.loaded {
		b.WriteString("Contacting instance…\n")
	} else {
		for _, line := range m.lines {
			b.WriteString(line + "\n")
		}
	}
	if m.vaultOpen {
		b.WriteString("Vault:    unlocked (empty)\n")
	}
	if m.vaultOpen && m.accessToken != "" {
		b.WriteString("\n[a] Activity  [s] Active Sessions  [r] refresh  [q] quit\n")
	} else {
		b.WriteString("\n[r] refresh  [q] quit\n")
	}
	return b.String()
}

func (m model) activityView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Activity\n\n")
	if m.activityAll {
		b.WriteString("Scope: all accounts\n\n")
	} else {
		b.WriteString("Scope: my account\n\n")
	}
	switch {
	case m.activityLoading:
		b.WriteString("Loading activity…\n")
	case m.activityErr != nil:
		b.WriteString("Error: " + m.activityErr.Error() + "\n")
	case len(m.activityPage.Events) == 0:
		b.WriteString("No activity.\n")
	default:
		for _, event := range m.activityPage.Events {
			fmt.Fprintf(&b, "%s  %s\n",
				event.OccurredAt.UTC().Format(time.RFC3339), event.Type)
			if event.AccountID != "" && m.activityAll {
				fmt.Fprintf(&b, "  Account: %s\n", event.AccountID)
			}
			if event.ActorID != "" {
				fmt.Fprintf(&b, "  Actor: %s\n", event.ActorID)
			} else {
				b.WriteString("  Actor: unauthenticated\n")
			}
			if event.SourceIP != "" {
				fmt.Fprintf(&b, "  Source: %s\n", event.SourceIP)
			}
			if event.SessionID != "" {
				fmt.Fprintf(&b, "  Session: %s\n", event.SessionID)
			}
			if event.InviteID != "" {
				fmt.Fprintf(&b, "  Invite: %s\n", event.InviteID)
			}
			b.WriteString("\n")
		}
	}
	if m.activityPage.CanViewAll {
		if m.activityAll {
			b.WriteString("[g] my account  ")
		} else {
			b.WriteString("[g] all accounts  ")
		}
	}
	if m.activityPage.NextCursor != "" {
		b.WriteString("[n] next page  ")
	}
	b.WriteString("[r] refresh  [v] vault  [q] quit\n")
	return b.String()
}

func (m model) sessionsView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Active Sessions\n\n")
	switch {
	case m.sessionsLoading:
		b.WriteString("Loading sessions…\n")
	case m.sessionsErr != nil:
		b.WriteString("Error: " + m.sessionsErr.Error() + "\n")
	case len(m.sessions) == 0:
		b.WriteString("No active sessions.\n")
	default:
		for index, session := range m.sessions {
			cursor := " "
			if index == m.selectedSession {
				cursor = ">"
			}
			current := ""
			if session.Current {
				current = " (current)"
			}
			fmt.Fprintf(&b, "%s %s%s\n", cursor, session.Host, current)
			fmt.Fprintf(&b, "  IP: %s\n", session.SourceIP)
			fmt.Fprintf(&b, "  Created: %s\n", session.CreatedAt.UTC().Format(time.RFC3339))
			fmt.Fprintf(&b, "  Last use: %s\n\n", session.LastUsed.UTC().Format(time.RFC3339))
		}
	}
	b.WriteString("[j/k] select  [x] revoke  [r] refresh  [v] vault  [q] quit\n")
	return b.String()
}
