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
	"github.com/davicbtoliveira/TermKeep/internal/session"
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
type loginRecord struct {
	Login    client.LoginItem
	Revision uint64
}
type loginsMsg []loginRecord
type loginsErrMsg error
type loginSaveErrMsg error

const loginFormFieldCount = 6

var loginFormLabels = [loginFormFieldCount]string{
	"Name",
	"Username",
	"Password",
	"URLs (comma-separated)",
	"Notes",
	"Custom fields (name=value, comma-separated)",
}

type loginForm struct {
	itemID   string
	revision uint64
	field    int
	values   [loginFormFieldCount]string
	editing  bool
}

type loginStore interface {
	List(ctx context.Context) ([]loginRecord, error)
	Save(ctx context.Context, record loginRecord) error
}

type remoteLoginStore struct {
	cfg         client.Config
	accessToken string
	socketPath  string
}

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
	loginsLoading   bool
	logins          []loginRecord
	selectedLogin   int
	loginsErr       error
	showLogin       bool
	revealPassword  bool
	loginStore      loginStore
	showLoginForm   bool
	loginForm       loginForm
	loginFormErr    error
	loginSaving     bool
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
func RunVault(cfg client.Config, accessToken, socketPath string) error {
	m := model{cfg: cfg, vaultOpen: true, accessToken: accessToken}
	if accessToken != "" && socketPath != "" {
		m.loginStore = remoteLoginStore{
			cfg:         cfg,
			accessToken: accessToken,
			socketPath:  socketPath,
		}
		m.loginsLoading = true
	}
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	if m.loginStore != nil {
		return tea.Batch(checkStatus(m.cfg), loadLogins(m.loginStore))
	}
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

func loadLogins(store loginStore) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		logins, err := store.List(ctx)
		if err != nil {
			return loginsErrMsg(err)
		}
		return loginsMsg(logins)
	}
}

func saveLogin(store loginStore, record loginRecord) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := store.Save(ctx, record); err != nil {
			return loginSaveErrMsg(err)
		}
		logins, err := store.List(ctx)
		if err != nil {
			return loginSaveErrMsg(err)
		}
		return loginsMsg(logins)
	}
}

func (s remoteLoginStore) List(ctx context.Context) ([]loginRecord, error) {
	encrypted, err := client.ListItems(ctx, s.cfg, s.accessToken)
	if err != nil {
		return nil, err
	}
	logins := make([]loginRecord, 0, len(encrypted))
	for _, item := range encrypted {
		login, err := session.OpenLogin(ctx, s.socketPath, item)
		if err != nil {
			return nil, err
		}
		logins = append(logins, loginRecord{
			Login:    login,
			Revision: item.Revision,
		})
	}
	return logins, nil
}

func (s remoteLoginStore) Save(ctx context.Context, record loginRecord) error {
	item, err := session.SealLogin(
		ctx, s.socketPath, record.Login, record.Revision)
	if err != nil {
		return err
	}
	return client.PutItem(ctx, s.cfg, s.accessToken, item)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.showLoginForm {
			return m.updateLoginForm(msg)
		}
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
		case "c":
			if m.vaultOpen && m.loginStore != nil &&
				!m.showSessions && !m.showActivity && !m.showLogin {
				itemID, err := client.NewItemID()
				if err != nil {
					m.loginsErr = err
					return m, nil
				}
				m.showLoginForm = true
				m.loginForm = loginForm{
					itemID:   itemID,
					revision: 1,
				}
				m.loginFormErr = nil
				m.loginSaving = false
			}
		case "e":
			if m.vaultOpen && m.loginStore != nil &&
				!m.showSessions && !m.showActivity &&
				m.selectedLogin < len(m.logins) {
				m.showLogin = false
				m.showLoginForm = true
				m.loginForm = formForLogin(m.logins[m.selectedLogin])
				m.loginFormErr = nil
				m.loginSaving = false
			}
		case "p":
			if m.showLogin && m.selectedLogin < len(m.logins) {
				m.revealPassword = !m.revealPassword
			}
		case "enter":
			if m.vaultOpen && !m.showSessions && !m.showActivity &&
				m.selectedLogin < len(m.logins) {
				m.showLogin = true
				m.revealPassword = false
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
			m.showLogin = false
			m.revealPassword = false
			return m, nil
		case "j", "down":
			if m.showSessions && m.selectedSession+1 < len(m.sessions) {
				m.selectedSession++
			} else if !m.showSessions && !m.showActivity && !m.showLogin &&
				m.selectedLogin+1 < len(m.logins) {
				m.selectedLogin++
			}
		case "k", "up":
			if m.showSessions && m.selectedSession > 0 {
				m.selectedSession--
			} else if !m.showSessions && !m.showActivity && !m.showLogin &&
				m.selectedLogin > 0 {
				m.selectedLogin--
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
			if m.vaultOpen && m.loginStore != nil {
				m.loginsLoading = true
				m.loginsErr = nil
				return m, loadLogins(m.loginStore)
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
	case loginsMsg:
		m.loginsLoading = false
		m.logins = []loginRecord(msg)
		m.showLoginForm = false
		m.loginFormErr = nil
		m.loginSaving = false
		if m.selectedLogin >= len(m.logins) {
			m.selectedLogin = 0
		}
	case loginsErrMsg:
		m.loginsLoading = false
		m.loginsErr = msg
	case loginSaveErrMsg:
		m.loginFormErr = msg
		m.loginSaving = false
	}
	return m, nil
}

func (m model) View() string {
	if m.showLoginForm {
		return m.loginFormView()
	}
	if m.showLogin {
		return m.loginView()
	}
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
		switch {
		case m.loginsLoading:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Logins:   loading…\n")
		case m.loginsErr != nil:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Logins:   error — " + m.loginsErr.Error() + "\n")
		case len(m.logins) == 0:
			b.WriteString("Vault:    unlocked (empty)\n")
		default:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Logins:\n")
			for index, record := range m.logins {
				cursor := " "
				if index == m.selectedLogin {
					cursor = ">"
				}
				fmt.Fprintf(&b, "%s %s — %s\n",
					cursor, record.Login.Name, record.Login.Username)
			}
		}
	}
	if m.vaultOpen && m.accessToken != "" {
		b.WriteString("\n[c] new Login  [enter] open  [a] Activity  [s] Active Sessions  [r] refresh  [q] quit\n")
	} else {
		b.WriteString("\n[r] refresh  [q] quit\n")
	}
	return b.String()
}

func (m model) updateLoginForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.loginSaving {
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.showLoginForm = false
		m.loginFormErr = nil
		return m, nil
	case "ctrl+u":
		m.loginForm.values[m.loginForm.field] = ""
	case "backspace":
		value := []rune(m.loginForm.values[m.loginForm.field])
		if len(value) > 0 {
			m.loginForm.values[m.loginForm.field] = string(value[:len(value)-1])
		}
	case "enter":
		if m.loginForm.field+1 < loginFormFieldCount {
			m.loginForm.field++
			m.loginFormErr = nil
			return m, nil
		}
		record, err := recordFromLoginForm(m.loginForm)
		if err != nil {
			m.loginFormErr = err
			return m, nil
		}
		m.loginSaving = true
		m.loginFormErr = nil
		return m, saveLogin(m.loginStore, record)
	default:
		if msg.Type == tea.KeyRunes {
			m.loginForm.values[m.loginForm.field] += string(msg.Runes)
		}
	}
	return m, nil
}

func recordFromLoginForm(form loginForm) (loginRecord, error) {
	name := strings.TrimSpace(form.values[0])
	if name == "" {
		return loginRecord{}, fmt.Errorf("name is required")
	}
	var urls []string
	for _, value := range strings.Split(form.values[3], ",") {
		if value = strings.TrimSpace(value); value != "" {
			urls = append(urls, value)
		}
	}
	var customFields []client.CustomField
	for _, value := range strings.Split(form.values[5], ",") {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		fieldName, fieldValue, ok := strings.Cut(value, "=")
		if !ok || strings.TrimSpace(fieldName) == "" {
			return loginRecord{}, fmt.Errorf("custom fields must use name=value")
		}
		customFields = append(customFields, client.CustomField{
			Name:  strings.TrimSpace(fieldName),
			Value: strings.TrimSpace(fieldValue),
		})
	}
	return loginRecord{
		Login: client.LoginItem{
			ItemID:       form.itemID,
			Name:         name,
			Username:     strings.TrimSpace(form.values[1]),
			Password:     form.values[2],
			URLs:         urls,
			Notes:        form.values[4],
			CustomFields: customFields,
		},
		Revision: form.revision,
	}, nil
}

func formForLogin(record loginRecord) loginForm {
	customFields := make([]string, 0, len(record.Login.CustomFields))
	for _, field := range record.Login.CustomFields {
		customFields = append(customFields, field.Name+"="+field.Value)
	}
	return loginForm{
		itemID:   record.Login.ItemID,
		revision: record.Revision + 1,
		editing:  true,
		values: [loginFormFieldCount]string{
			record.Login.Name,
			record.Login.Username,
			record.Login.Password,
			strings.Join(record.Login.URLs, ", "),
			record.Login.Notes,
			strings.Join(customFields, ", "),
		},
	}
}

func (m model) loginFormView() string {
	title := "New Login"
	if m.loginForm.editing {
		title = "Edit Login"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "TermKeep — %s\n\n", title)
	for index, label := range loginFormLabels {
		cursor := " "
		if index == m.loginForm.field {
			cursor = ">"
		}
		value := m.loginForm.values[index]
		if index == 2 && value != "" {
			value = "••••••••"
		}
		fmt.Fprintf(&b, "%s %s: %s\n", cursor, label, value)
	}
	if m.loginFormErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.loginFormErr)
	}
	if m.loginSaving {
		b.WriteString("\nSaving…  [ctrl+c] quit\n")
	} else {
		b.WriteString("\n[enter] next/save  [ctrl+u] clear field  [esc] cancel  [ctrl+c] quit\n")
	}
	return b.String()
}

func (m model) loginView() string {
	if m.selectedLogin >= len(m.logins) {
		return "TermKeep — Login\n\nLogin not found.\n\n[v] vault  [q] quit\n"
	}
	login := m.logins[m.selectedLogin].Login
	var b strings.Builder
	fmt.Fprintf(&b, "TermKeep — Login — %s\n\n", login.Name)
	fmt.Fprintf(&b, "Username: %s\n", login.Username)
	password := "••••••••"
	if m.revealPassword {
		password = login.Password
	}
	fmt.Fprintf(&b, "Password: %s\n", password)
	b.WriteString("URLs:\n")
	for _, value := range login.URLs {
		fmt.Fprintf(&b, "  - %s\n", value)
	}
	fmt.Fprintf(&b, "Notes: %s\n", login.Notes)
	b.WriteString("Custom fields:\n")
	for _, field := range login.CustomFields {
		fmt.Fprintf(&b, "  %s: %s\n", field.Name, field.Value)
	}
	b.WriteString("\n[p] reveal/hide password  [e] edit  [v] vault  [q] quit\n")
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
