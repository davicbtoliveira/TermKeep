// Package tui implements the minimal TermKeep terminal UI: the instance
// state shown when termkeep runs without a subcommand.
package tui

import (
	"context"
	"errors"
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
type itemRecord struct {
	Login             client.LoginItem
	SecureNote        *client.SecureNoteItem
	Revision          uint64
	RevisionID        string
	ParentRevisionIDs []string
	ConflictVersions  []itemRecord
	Deleted           bool
	Purged            bool
}
type itemsMsg []itemRecord
type itemsErrMsg error
type trashMsg []itemRecord
type trashErrMsg error
type itemSaveErrMsg error
type itemSavedMsg struct {
	items   []itemRecord
	pending int
	syncErr error
}
type syncResultMsg struct {
	items   []itemRecord
	pending int
	err     error
}
type periodicSyncMsg struct{}

var periodicSyncInterval = 30 * time.Second
var itemOperationTimeout = 10 * time.Second

const loginFormFieldCount = 6
const secureNoteFormFieldCount = 2

var loginFormLabels = [loginFormFieldCount]string{
	"Name",
	"Username",
	"Password",
	"URLs (comma-separated)",
	"Notes",
	"Custom fields (name=value, comma-separated)",
}

type loginForm struct {
	itemID            string
	revision          uint64
	parentRevisionIDs []string
	field             int
	values            [loginFormFieldCount]string
	editing           bool
	manualMerge       bool
}

type secureNoteForm struct {
	itemID            string
	revision          uint64
	parentRevisionIDs []string
	field             int
	values            [secureNoteFormFieldCount]string
	editing           bool
	manualMerge       bool
}

type itemStore interface {
	List(ctx context.Context) ([]itemRecord, error)
	Save(ctx context.Context, record itemRecord) error
}

type syncItemStore interface {
	Sync(ctx context.Context) error
	Pending() (int, error)
	CanSync() bool
}

type trashItemStore interface {
	Trash(ctx context.Context) ([]itemRecord, error)
}

type cachedItemStore struct {
	cfg         client.Config
	accessToken string
	socketPath  string
	cache       *client.Cache
}

// model is the single-screen state: the shared status lines plus keys.
type model struct {
	cfg              client.Config
	lines            []string
	err              error
	loaded           bool
	vaultOpen        bool
	accessToken      string
	showSessions     bool
	sessionsLoading  bool
	sessions         []client.OnlineSession
	selectedSession  int
	sessionsErr      error
	showActivity     bool
	activityAll      bool
	activityLoading  bool
	activityPage     client.ActivityPage
	activityErr      error
	itemsLoading     bool
	items            []itemRecord
	selectedItem     int
	selectedConflict int
	itemsErr         error
	showTrash        bool
	trashLoading     bool
	trash            []itemRecord
	selectedTrash    int
	trashErr         error
	purgeConfirm     bool
	showItem         bool
	revealPassword   bool
	itemStore        itemStore
	showLoginForm    bool
	loginForm        loginForm
	showNoteForm     bool
	noteForm         secureNoteForm
	itemFormErr      error
	itemSaving       bool
	syncLoading      bool
	syncErr          error
	pendingMutations int
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
	if socketPath != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		info, err := session.Status(ctx, socketPath)
		cancel()
		if err != nil {
			return err
		}
		cache, err := client.OpenCache(cfg, info.Email)
		if err != nil {
			return err
		}
		m.itemStore = cachedItemStore{
			cfg:         cfg,
			accessToken: accessToken,
			socketPath:  socketPath,
			cache:       cache,
		}
		m.itemsLoading = true
	}
	p := tea.NewProgram(m)
	_, err := p.Run()
	return err
}

func (m model) Init() tea.Cmd {
	if m.itemStore != nil {
		if m.accessToken != "" {
			return tea.Batch(
				checkStatus(m.cfg),
				loadItems(m.itemStore),
				syncItems(m.itemStore),
				schedulePeriodicSync(),
			)
		}
		return tea.Batch(checkStatus(m.cfg), loadItems(m.itemStore))
	}
	return checkStatus(m.cfg)
}

func schedulePeriodicSync() tea.Cmd {
	return tea.Tick(periodicSyncInterval, func(time.Time) tea.Msg {
		return periodicSyncMsg{}
	})
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

func loadItems(store itemStore) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		defer cancel()
		items, err := store.List(ctx)
		if err != nil {
			return itemsErrMsg(err)
		}
		return itemsMsg(items)
	}
}

func loadTrash(store itemStore) tea.Cmd {
	return func() tea.Msg {
		trashStore, ok := store.(trashItemStore)
		if !ok {
			return trashErrMsg(errors.New("trash unavailable"))
		}
		ctx, cancel := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		defer cancel()
		records, err := trashStore.Trash(ctx)
		if err != nil {
			return trashErrMsg(err)
		}
		return trashMsg(records)
	}
}

func saveItem(store itemStore, record itemRecord) tea.Cmd {
	return func() tea.Msg {
		saveCtx, cancelSave := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		err := store.Save(saveCtx, record)
		cancelSave()
		if err != nil {
			return itemSaveErrMsg(err)
		}
		var (
			syncErr error
			pending int
		)
		if syncStore, ok := store.(syncItemStore); ok {
			if syncStore.CanSync() {
				syncCtx, cancelSync := context.WithTimeout(
					context.Background(), itemOperationTimeout)
				syncErr = syncStore.Sync(syncCtx)
				cancelSync()
			}
			var pendingErr error
			pending, pendingErr = syncStore.Pending()
			syncErr = errors.Join(syncErr, pendingErr)
		}
		listCtx, cancelList := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		items, listErr := store.List(listCtx)
		cancelList()
		syncErr = errors.Join(syncErr, listErr)
		return itemSavedMsg{
			items:   items,
			pending: pending,
			syncErr: syncErr,
		}
	}
}

func syncItems(store itemStore) tea.Cmd {
	return func() tea.Msg {
		syncStore, ok := store.(syncItemStore)
		if !ok {
			return syncResultMsg{err: errors.New("synchronization unavailable")}
		}
		syncCtx, cancelSync := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		syncErr := syncStore.Sync(syncCtx)
		cancelSync()
		listCtx, cancelList := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		items, listErr := store.List(listCtx)
		cancelList()
		pending, pendingErr := syncStore.Pending()
		return syncResultMsg{
			items:   items,
			pending: pending,
			err:     errors.Join(syncErr, listErr, pendingErr),
		}
	}
}

func (s cachedItemStore) List(ctx context.Context) ([]itemRecord, error) {
	groups, err := s.cache.ItemHeads()
	if err != nil {
		return nil, err
	}
	return s.openItemGroups(ctx, groups)
}

func (s cachedItemStore) Trash(ctx context.Context) ([]itemRecord, error) {
	groups, err := s.cache.TrashHeads()
	if err != nil {
		return nil, err
	}
	return s.openItemGroups(ctx, groups)
}

func (s cachedItemStore) openItemGroups(
	ctx context.Context,
	groups []client.ItemHead,
) ([]itemRecord, error) {
	items := make([]itemRecord, 0, len(groups))
	for _, group := range groups {
		versions := make([]itemRecord, 0, len(group.Revisions))
		for _, item := range group.Revisions {
			if item.Purged {
				versions = append(versions, itemRecord{
					Login: client.LoginItem{
						ItemID: item.ItemID,
						Name:   "Permanently deleted",
					},
					Revision:   item.Revision,
					RevisionID: item.RevisionID,
					ParentRevisionIDs: append(
						[]string(nil), item.ParentRevisionIDs...),
					Deleted: true,
					Purged:  true,
				})
				continue
			}
			opened, err := session.OpenNativeItem(
				ctx, s.socketPath, item)
			if err != nil {
				return nil, err
			}
			record := itemRecord{
				Revision:   item.Revision,
				RevisionID: item.RevisionID,
				ParentRevisionIDs: append(
					[]string(nil), item.ParentRevisionIDs...),
				Deleted: item.Deleted,
				Purged:  item.Purged,
			}
			switch opened.Type {
			case client.NativeItemTypeLogin:
				if opened.Login == nil {
					return nil, client.ErrInvalidItemEnvelope
				}
				record.Login = *opened.Login
			case client.NativeItemTypeSecureNote:
				if opened.SecureNote == nil {
					return nil, client.ErrInvalidItemEnvelope
				}
				note := *opened.SecureNote
				record.SecureNote = &note
			default:
				return nil, client.ErrInvalidItemEnvelope
			}
			versions = append(versions, record)
		}
		record := versions[0]
		for _, version := range versions {
			if !version.Purged {
				record = version
				break
			}
		}
		if len(versions) > 1 {
			record.ConflictVersions = versions
		}
		items = append(items, record)
	}
	return items, nil
}

func (s cachedItemStore) Save(ctx context.Context, record itemRecord) error {
	var (
		item client.EncryptedItem
		err  error
	)
	if record.SecureNote != nil {
		item, err = session.SealSecureNote(
			ctx, s.socketPath, *record.SecureNote, record.Revision)
	} else {
		item, err = session.SealLogin(
			ctx, s.socketPath, record.Login, record.Revision)
	}
	if err != nil {
		return err
	}
	revisionID, err := client.NewItemID()
	if err != nil {
		return err
	}
	item.RevisionID = revisionID
	item.ParentRevisionIDs = append(
		[]string(nil), record.ParentRevisionIDs...)
	item.Deleted = record.Deleted
	item.Purged = record.Purged
	if record.Purged {
		item.Envelope = nil
	}
	_, err = s.cache.QueueMutation(item, record.Revision-1)
	return err
}

func (s cachedItemStore) Sync(ctx context.Context) error {
	if s.accessToken == "" {
		return errors.New("online authentication required")
	}
	return client.SyncCache(ctx, s.cfg, s.accessToken, s.cache)
}

func (s cachedItemStore) Pending() (int, error) {
	snapshot, err := s.cache.SyncSnapshot()
	if err != nil {
		return 0, err
	}
	return len(snapshot.Mutations), nil
}

func (s cachedItemStore) CanSync() bool {
	return s.accessToken != ""
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case periodicSyncMsg:
		if m.vaultOpen && m.itemStore != nil &&
			m.accessToken != "" && !m.syncLoading {
			m.syncLoading = true
			return m, tea.Batch(
				syncItems(m.itemStore),
				checkStatus(m.cfg),
				schedulePeriodicSync(),
			)
		}
		return m, schedulePeriodicSync()
	case tea.KeyMsg:
		if m.showLoginForm {
			return m.updateLoginForm(msg)
		}
		if m.showNoteForm {
			return m.updateSecureNoteForm(msg)
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
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem && !m.showTrash {
				itemID, err := client.NewItemID()
				if err != nil {
					m.itemsErr = err
					return m, nil
				}
				m.showLoginForm = true
				m.loginForm = loginForm{
					itemID:   itemID,
					revision: 1,
				}
				m.itemFormErr = nil
				m.itemSaving = false
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
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem && !m.showTrash {
				itemID, err := client.NewItemID()
				if err != nil {
					m.itemsErr = err
					return m, nil
				}
				m.showNoteForm = true
				m.noteForm = secureNoteForm{
					itemID:   itemID,
					revision: 1,
				}
				m.itemFormErr = nil
				m.itemSaving = false
			}
		case "e":
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				m.selectedItem < len(m.items) &&
				len(m.items[m.selectedItem].ConflictVersions) == 0 {
				record := m.items[m.selectedItem]
				m.showItem = false
				if record.SecureNote != nil {
					m.showNoteForm = true
					m.noteForm = formForSecureNote(record)
				} else {
					m.showLoginForm = true
					m.loginForm = formForLogin(record)
				}
				m.itemFormErr = nil
				m.itemSaving = false
			}
		case "d":
			if m.showItem && m.itemStore != nil &&
				m.selectedItem < len(m.items) {
				record := m.items[m.selectedItem]
				if len(record.ConflictVersions) == 0 &&
					!record.Deleted {
					m.itemSaving = true
					return m, saveItem(
						m.itemStore,
						deleteItem(record),
					)
				}
			}
		case "p":
			if m.showItem && m.selectedItem < len(m.items) &&
				len(m.items[m.selectedItem].ConflictVersions) == 0 {
				m.revealPassword = !m.revealPassword
			}
		case "m":
			if m.showItem && m.selectedItem < len(m.items) {
				record := m.items[m.selectedItem]
				if len(record.ConflictVersions) > 1 {
					m.showItem = false
					if record.SecureNote != nil {
						m.showNoteForm = true
						m.noteForm = formForSecureNoteConflict(
							record.ConflictVersions,
							m.selectedConflict,
						)
					} else {
						m.showLoginForm = true
						m.loginForm = formForConflict(
							record.ConflictVersions,
							m.selectedConflict,
						)
					}
					m.itemFormErr = nil
					m.itemSaving = false
				}
			}
		case "t":
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem {
				m.showTrash = true
				m.trashLoading = true
				m.trashErr = nil
				m.purgeConfirm = false
				return m, loadTrash(m.itemStore)
			}
		case "enter":
			if m.showItem && m.selectedItem < len(m.items) {
				record := m.items[m.selectedItem]
				if len(record.ConflictVersions) > 1 {
					m.itemSaving = true
					return m, saveItem(
						m.itemStore,
						resolveConflict(
							record.ConflictVersions,
							m.selectedConflict,
						),
					)
				}
			} else if m.vaultOpen && !m.showSessions && !m.showActivity &&
				m.selectedItem < len(m.items) {
				m.showItem = true
				m.revealPassword = false
				m.selectedConflict = 0
			}
		case "g":
			if m.showActivity && m.activityPage.CanViewAll {
				m.activityAll = !m.activityAll
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(
					m.cfg, m.accessToken, m.activityAll, "")
			}
		case "v":
			m.showSessions = false
			m.showActivity = false
			m.showItem = false
			m.showTrash = false
			m.revealPassword = false
			m.selectedConflict = 0
			m.purgeConfirm = false
			m.showNoteForm = false
			return m, nil
		case "j", "down":
			if m.showSessions && m.selectedSession+1 < len(m.sessions) {
				m.selectedSession++
			} else if m.showItem && m.selectedItem < len(m.items) &&
				m.selectedConflict+1 <
					len(m.items[m.selectedItem].ConflictVersions) {
				m.selectedConflict++
			} else if m.showTrash &&
				m.selectedTrash+1 < len(m.trash) {
				m.selectedTrash++
				m.purgeConfirm = false
			} else if !m.showSessions && !m.showActivity && !m.showItem &&
				m.selectedItem+1 < len(m.items) {
				m.selectedItem++
			}
		case "k", "up":
			if m.showSessions && m.selectedSession > 0 {
				m.selectedSession--
			} else if m.showItem && m.selectedConflict > 0 {
				m.selectedConflict--
			} else if m.showTrash && m.selectedTrash > 0 {
				m.selectedTrash--
				m.purgeConfirm = false
			} else if !m.showSessions && !m.showActivity && !m.showItem &&
				m.selectedItem > 0 {
				m.selectedItem--
			}
		case "x":
			if m.showTrash && m.selectedTrash < len(m.trash) {
				if !m.purgeConfirm {
					m.purgeConfirm = true
					return m, nil
				}
				m.itemSaving = true
				return m, saveItem(
					m.itemStore,
					purgeItem(m.trash[m.selectedTrash]),
				)
			}
			if m.showSessions && m.selectedSession < len(m.sessions) {
				selected := m.sessions[m.selectedSession]
				if selected.Current {
					m.sessionsErr = fmt.Errorf("current session: use logout")
					return m, nil
				}
				return m, revokeSession(m.cfg, m.accessToken, selected.SessionID)
			}
		case "r":
			if m.showTrash && m.selectedTrash < len(m.trash) {
				m.itemSaving = true
				return m, saveItem(
					m.itemStore,
					restoreItem(m.trash[m.selectedTrash]),
				)
			}
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
			if m.vaultOpen && m.itemStore != nil {
				m.itemsLoading = true
				m.itemsErr = nil
				return m, loadItems(m.itemStore)
			}
			m.loaded = false
			return m, checkStatus(m.cfg)
		case "y":
			if m.vaultOpen && m.itemStore != nil &&
				m.accessToken != "" && !m.syncLoading {
				m.syncLoading = true
				m.syncErr = nil
				return m, syncItems(m.itemStore)
			}
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
	case itemsMsg:
		m.itemsLoading = false
		m.items = []itemRecord(msg)
		m.selectedConflict = 0
		m.showLoginForm = false
		m.showNoteForm = false
		m.itemFormErr = nil
		m.itemSaving = false
		if m.selectedItem >= len(m.items) {
			m.selectedItem = 0
		}
	case itemsErrMsg:
		m.itemsLoading = false
		m.itemsErr = msg
	case trashMsg:
		m.trashLoading = false
		m.trash = []itemRecord(msg)
		m.trashErr = nil
		m.purgeConfirm = false
		if m.selectedTrash >= len(m.trash) {
			m.selectedTrash = 0
		}
	case trashErrMsg:
		m.trashLoading = false
		m.trashErr = msg
	case itemSaveErrMsg:
		m.itemFormErr = msg
		m.itemSaving = false
	case itemSavedMsg:
		m.items = msg.items
		m.showItem = false
		m.showTrash = false
		m.selectedConflict = 0
		m.showLoginForm = false
		m.showNoteForm = false
		m.itemFormErr = nil
		m.itemSaving = false
		m.syncErr = msg.syncErr
		m.pendingMutations = msg.pending
		if m.selectedItem >= len(m.items) {
			m.selectedItem = 0
		}
		if msg.syncErr != nil {
			return m, checkStatus(m.cfg)
		}
	case syncResultMsg:
		m.syncLoading = false
		m.syncErr = msg.err
		m.pendingMutations = msg.pending
		m.items = msg.items
		m.selectedConflict = 0
		if m.selectedItem >= len(m.items) {
			m.selectedItem = 0
		}
		if msg.err != nil {
			return m, checkStatus(m.cfg)
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.showLoginForm {
		return m.loginFormView()
	}
	if m.showNoteForm {
		return m.secureNoteFormView()
	}
	if m.showTrash {
		return m.trashView()
	}
	if m.showItem {
		return m.itemView()
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
		case m.itemsLoading:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Items:    loading…\n")
		case m.itemsErr != nil:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Items:    error — " + m.itemsErr.Error() + "\n")
		case len(m.items) == 0:
			b.WriteString("Vault:    unlocked (empty)\n")
		default:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Items:\n")
			for index, record := range m.items {
				cursor := " "
				if index == m.selectedItem {
					cursor = ">"
				}
				if len(record.ConflictVersions) > 1 {
					fmt.Fprintf(
						&b,
						"%s ⚠ Conflict — %s (%d versions)\n",
						cursor,
						recordTitle(record),
						len(record.ConflictVersions),
					)
				} else if record.SecureNote != nil {
					fmt.Fprintf(
						&b,
						"%s [Secure Note] %s\n",
						cursor,
						record.SecureNote.Title,
					)
				} else {
					fmt.Fprintf(&b, "%s [Login] %s — %s\n",
						cursor, record.Login.Name, record.Login.Username)
				}
			}
		}
		switch {
		case m.syncLoading:
			b.WriteString("Sync:     syncing…\n")
		case m.syncErr != nil:
			b.WriteString("Sync:     error — " + m.syncErr.Error() + "\n")
		case m.pendingMutations > 0:
			fmt.Fprintf(&b, "Sync:     %d pending\n", m.pendingMutations)
		case m.accessToken != "":
			b.WriteString("Sync:     up to date\n")
		default:
			b.WriteString("Sync:     offline\n")
		}
	}
	if m.vaultOpen && m.itemStore != nil {
		b.WriteString(
			"\n[c] new Login  [n] new Secure Note  " +
				"[enter] open  [t] Trash  ",
		)
		if m.accessToken != "" {
			b.WriteString("[a] Activity  [s] Active Sessions  ")
			b.WriteString("[y] sync  ")
		}
		b.WriteString("[r] refresh  [q] quit\n")
	} else {
		b.WriteString("\n[r] refresh  [q] quit\n")
	}
	return b.String()
}

func (m model) updateSecureNoteForm(
	msg tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	if m.itemSaving {
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		return m, nil
	}
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.showNoteForm = false
		m.itemFormErr = nil
		return m, nil
	case "ctrl+u":
		m.noteForm.values[m.noteForm.field] = ""
	case "backspace":
		value := []rune(m.noteForm.values[m.noteForm.field])
		if len(value) > 0 {
			m.noteForm.values[m.noteForm.field] =
				string(value[:len(value)-1])
		}
	case "enter":
		if m.noteForm.field+1 < secureNoteFormFieldCount {
			m.noteForm.field++
			m.itemFormErr = nil
			return m, nil
		}
		record, err := recordFromSecureNoteForm(m.noteForm)
		if err != nil {
			m.itemFormErr = err
			return m, nil
		}
		m.itemSaving = true
		m.itemFormErr = nil
		return m, saveItem(m.itemStore, record)
	default:
		if msg.Type == tea.KeyRunes {
			m.noteForm.values[m.noteForm.field] += string(msg.Runes)
		}
	}
	return m, nil
}

func recordFromSecureNoteForm(
	form secureNoteForm,
) (itemRecord, error) {
	title := strings.TrimSpace(form.values[0])
	if title == "" {
		return itemRecord{}, fmt.Errorf("title is required")
	}
	return itemRecord{
		SecureNote: &client.SecureNoteItem{
			ItemID:  form.itemID,
			Title:   title,
			Content: form.values[1],
		},
		Revision: form.revision,
		ParentRevisionIDs: append(
			[]string(nil), form.parentRevisionIDs...),
	}, nil
}

func (m model) secureNoteFormView() string {
	title := "New Secure Note"
	if m.noteForm.manualMerge {
		title = "Manual Secure Note Conflict Merge"
	} else if m.noteForm.editing {
		title = "Edit Secure Note"
	}
	labels := [secureNoteFormFieldCount]string{"Title", "Content"}
	var b strings.Builder
	fmt.Fprintf(&b, "TermKeep — %s\n\n", title)
	for index, label := range labels {
		cursor := " "
		if index == m.noteForm.field {
			cursor = ">"
		}
		fmt.Fprintf(
			&b, "%s %s: %s\n",
			cursor, label, m.noteForm.values[index],
		)
	}
	if m.itemFormErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.itemFormErr)
	}
	if m.itemSaving {
		b.WriteString("\nSaving…  [ctrl+c] quit\n")
	} else {
		b.WriteString(
			"\n[enter] next/save  [ctrl+u] clear field  " +
				"[esc] cancel  [ctrl+c] quit\n",
		)
	}
	return b.String()
}

func (m model) updateLoginForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.itemSaving {
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
		m.itemFormErr = nil
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
			m.itemFormErr = nil
			return m, nil
		}
		record, err := recordFromLoginForm(m.loginForm)
		if err != nil {
			m.itemFormErr = err
			return m, nil
		}
		m.itemSaving = true
		m.itemFormErr = nil
		return m, saveItem(m.itemStore, record)
	default:
		if msg.Type == tea.KeyRunes {
			m.loginForm.values[m.loginForm.field] += string(msg.Runes)
		}
	}
	return m, nil
}

func recordFromLoginForm(form loginForm) (itemRecord, error) {
	name := strings.TrimSpace(form.values[0])
	if name == "" {
		return itemRecord{}, fmt.Errorf("name is required")
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
			return itemRecord{}, fmt.Errorf("custom fields must use name=value")
		}
		customFields = append(customFields, client.CustomField{
			Name:  strings.TrimSpace(fieldName),
			Value: strings.TrimSpace(fieldValue),
		})
	}
	return itemRecord{
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
		ParentRevisionIDs: append(
			[]string(nil), form.parentRevisionIDs...),
	}, nil
}

func formForLogin(record itemRecord) loginForm {
	customFields := make([]string, 0, len(record.Login.CustomFields))
	for _, field := range record.Login.CustomFields {
		customFields = append(customFields, field.Name+"="+field.Value)
	}
	var parentRevisionIDs []string
	if record.RevisionID != "" {
		parentRevisionIDs = []string{record.RevisionID}
	}
	return loginForm{
		itemID:            record.Login.ItemID,
		revision:          record.Revision + 1,
		parentRevisionIDs: parentRevisionIDs,
		editing:           true,
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

func formForSecureNote(record itemRecord) secureNoteForm {
	var parentRevisionIDs []string
	if record.RevisionID != "" {
		parentRevisionIDs = []string{record.RevisionID}
	}
	return secureNoteForm{
		itemID:            record.SecureNote.ItemID,
		revision:          record.Revision + 1,
		parentRevisionIDs: parentRevisionIDs,
		editing:           true,
		values: [secureNoteFormFieldCount]string{
			record.SecureNote.Title,
			record.SecureNote.Content,
		},
	}
}

func deleteItem(record itemRecord) itemRecord {
	record.Revision++
	record.ParentRevisionIDs = []string{record.RevisionID}
	record.RevisionID = ""
	record.ConflictVersions = nil
	record.Deleted = true
	record.Purged = false
	return record
}

func restoreItem(record itemRecord) itemRecord {
	record.Revision++
	record.ParentRevisionIDs = []string{record.RevisionID}
	record.RevisionID = ""
	record.ConflictVersions = nil
	record.Deleted = false
	record.Purged = false
	return record
}

func purgeItem(record itemRecord) itemRecord {
	record.Revision++
	record.ParentRevisionIDs = []string{record.RevisionID}
	record.RevisionID = ""
	record.ConflictVersions = nil
	record.Deleted = true
	record.Purged = true
	return record
}

func formForConflict(versions []itemRecord, selected int) loginForm {
	resolution := resolveConflict(versions, selected)
	form := formForLogin(itemRecord{
		Login:    resolution.Login,
		Revision: resolution.Revision - 1,
	})
	form.parentRevisionIDs = append(
		[]string(nil), resolution.ParentRevisionIDs...)
	form.manualMerge = true
	return form
}

func formForSecureNoteConflict(
	versions []itemRecord,
	selected int,
) secureNoteForm {
	if selected < 0 ||
		selected >= len(versions) ||
		versions[selected].SecureNote == nil {
		for index, version := range versions {
			if version.SecureNote != nil {
				selected = index
				break
			}
		}
	}
	resolution := resolveConflict(versions, selected)
	form := formForSecureNote(itemRecord{
		SecureNote: resolution.SecureNote,
		Revision:   resolution.Revision - 1,
	})
	form.parentRevisionIDs = append(
		[]string(nil), resolution.ParentRevisionIDs...)
	form.manualMerge = true
	return form
}

func resolveConflict(versions []itemRecord, selected int) itemRecord {
	if selected < 0 || selected >= len(versions) {
		selected = 0
	}
	resolution := versions[selected]
	resolution.ConflictVersions = nil
	resolution.RevisionID = ""
	resolution.ParentRevisionIDs = make([]string, 0, len(versions))
	var highestRevision uint64
	for _, version := range versions {
		resolution.ParentRevisionIDs = append(
			resolution.ParentRevisionIDs, version.RevisionID)
		highestRevision = max(highestRevision, version.Revision)
	}
	resolution.Revision = highestRevision + 1
	return resolution
}

func (m model) loginFormView() string {
	title := "New Login"
	if m.loginForm.manualMerge {
		title = "Manual Conflict Merge"
	} else if m.loginForm.editing {
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
	if m.itemFormErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.itemFormErr)
	}
	if m.itemSaving {
		b.WriteString("\nSaving…  [ctrl+c] quit\n")
	} else {
		b.WriteString("\n[enter] next/save  [ctrl+u] clear field  [esc] cancel  [ctrl+c] quit\n")
	}
	return b.String()
}

func (m model) trashView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Trash\n\n")
	switch {
	case m.trashLoading:
		b.WriteString("Loading trash…\n")
	case m.trashErr != nil:
		b.WriteString("Error: " + m.trashErr.Error() + "\n")
	case len(m.trash) == 0:
		b.WriteString("Trash is empty.\n")
	default:
		for index, record := range m.trash {
			cursor := " "
			if index == m.selectedTrash {
				cursor = ">"
			}
			if record.SecureNote != nil {
				fmt.Fprintf(
					&b, "%s [Secure Note] %s\n",
					cursor, record.SecureNote.Title,
				)
			} else {
				fmt.Fprintf(
					&b, "%s [Login] %s — %s\n",
					cursor, record.Login.Name, record.Login.Username,
				)
			}
		}
	}
	if m.purgeConfirm && m.selectedTrash < len(m.trash) {
		b.WriteString(
			"\nWarning: encrypted content cannot be recovered.\n" +
				"Press [x] again to permanently delete " +
				recordTitle(m.trash[m.selectedTrash]) + ".\n",
		)
	}
	b.WriteString(
		"\n[j/k] select  [r] restore  [x] permanently delete  " +
			"[v] vault  [q] quit\n",
	)
	return b.String()
}

func (m model) itemView() string {
	if m.selectedItem >= len(m.items) {
		return "TermKeep — Login\n\nLogin not found.\n\n[v] vault  [q] quit\n"
	}
	record := m.items[m.selectedItem]
	if len(record.ConflictVersions) > 1 {
		return m.conflictView(record.ConflictVersions)
	}
	if record.SecureNote != nil {
		var b strings.Builder
		fmt.Fprintf(
			&b,
			"TermKeep — Secure Note — %s\n\n",
			record.SecureNote.Title,
		)
		fmt.Fprintf(&b, "Content:\n%s\n", record.SecureNote.Content)
		b.WriteString(
			"\n[e] edit  [d] delete  [v] vault  [q] quit\n",
		)
		return b.String()
	}
	login := record.Login
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
	b.WriteString(
		"\n[p] reveal/hide password  [e] edit  [d] delete  " +
			"[v] vault  [q] quit\n",
	)
	return b.String()
}

func recordTitle(record itemRecord) string {
	if record.SecureNote != nil {
		return record.SecureNote.Title
	}
	return record.Login.Name
}

func recordItemID(record itemRecord) string {
	if record.SecureNote != nil {
		return record.SecureNote.ItemID
	}
	return record.Login.ItemID
}

func (m model) conflictView(versions []itemRecord) string {
	var b strings.Builder
	fmt.Fprintf(&b, "TermKeep — Conflict — %d versions\n\n", len(versions))
	for index, version := range versions {
		cursor := " "
		if index == m.selectedConflict {
			cursor = ">"
		}
		fmt.Fprintf(&b, "%s Version %d\n", cursor, index+1)
		if version.Purged {
			b.WriteString("  Permanently deleted\n\n")
			continue
		}
		if version.SecureNote != nil {
			fmt.Fprintf(
				&b, "  Title: %s\n", version.SecureNote.Title)
			fmt.Fprintf(
				&b, "  Content: %s\n\n",
				version.SecureNote.Content,
			)
			continue
		}
		fmt.Fprintf(&b, "  Name: %s\n", version.Login.Name)
		fmt.Fprintf(&b, "  Username: %s\n", version.Login.Username)
		b.WriteString("  Password: ••••••••\n")
		fmt.Fprintf(&b, "  URLs: %s\n",
			strings.Join(version.Login.URLs, ", "))
		fmt.Fprintf(&b, "  Notes: %s\n", version.Login.Notes)
		if len(version.Login.CustomFields) > 0 {
			b.WriteString("  Custom fields:\n")
			for _, field := range version.Login.CustomFields {
				fmt.Fprintf(&b, "    %s: %s\n", field.Name, field.Value)
			}
		}
		b.WriteString("\n")
	}
	b.WriteString(
		"[j/k] select version  [enter] keep selected  " +
			"[m] manual merge  [v] vault  [q] quit\n",
	)
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
