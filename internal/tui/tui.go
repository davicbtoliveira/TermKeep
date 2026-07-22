// Package tui implements the minimal TermKeep terminal UI: the instance
// state shown when termkeep runs without a subcommand.
package tui

import (
	"context"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/davicbtoliveira/TermKeep/internal/client"
)

// statusMsg carries the classified instance state into the update loop.
type statusMsg client.Status

// errMsg reports a configuration-level failure (e.g. insecure URL).
type errMsg error

// model is the single-screen state: the shared status lines plus keys.
type model struct {
	cfg    client.Config
	lines  []string
	err    error
	loaded bool
}

// Run starts the Bubble Tea program on the controlling terminal.
func Run(cfg client.Config) error {
	m := model{cfg: cfg}
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

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "r":
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
	}
	return m, nil
}

func (m model) View() string {
	var b strings.Builder
	b.WriteString("TermKeep\n\n")
	if !m.loaded {
		b.WriteString("Contacting instance…\n")
	} else {
		for _, line := range m.lines {
			b.WriteString(line + "\n")
		}
	}
	b.WriteString("\n[r] refresh  [q] quit\n")
	return b.String()
}
