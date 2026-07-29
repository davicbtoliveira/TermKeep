// Package tui implements the minimal TermKeep terminal UI: the instance
// state shown when termkeep runs without a subcommand.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/clipboard"
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
	Folder            *client.FolderItem
	Generic           *client.GenericItem
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
type secretCopiedMsg struct {
	field string
	err   error
}
type breachCheckMsg struct {
	id     uint64
	result client.PwnedPasswordResult
}
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
type totpRefreshMsg struct{}

var periodicSyncInterval = 30 * time.Second
var itemOperationTimeout = 10 * time.Second

const loginFormFieldCount = 6
const secureNoteFormFieldCount = 2
const totpFormFieldCount = 7
const passwordGeneratorFieldCount = 8
const unfiledFolderFilter = "__termkeep_no_folder__"

var loginFormLabels = [loginFormFieldCount]string{
	"Name",
	"Username",
	"Password",
	"URLs (comma-separated)",
	"Notes",
	"Custom fields (name=value, comma-separated)",
}

var totpFormLabels = [totpFormFieldCount]string{
	"otpauth URI (optional)",
	"Secret (manual)",
	"Issuer",
	"Account",
	"Algorithm (SHA1/SHA256/SHA512)",
	"Digits (6/8)",
	"Period (seconds)",
}

var passwordGeneratorLabels = [passwordGeneratorFieldCount]string{
	"Length (5-128)",
	"Uppercase (yes/no)",
	"Lowercase (yes/no)",
	"Digits (yes/no)",
	"Special characters (yes/no)",
	"Minimum digits",
	"Minimum special characters",
	"Exclude ambiguous (yes/no)",
}

type loginForm struct {
	itemID            string
	revision          uint64
	parentRevisionIDs []string
	folderID          string
	favorite          bool
	previousPassword  string
	passwordHistory   []client.PasswordHistoryEntry
	totp              *client.TOTPConfig
	field             int
	values            [loginFormFieldCount]string
	editing           bool
	manualMerge       bool
}

type totpForm struct {
	record itemRecord
	field  int
	values [totpFormFieldCount]string
}

type passwordGeneratorForm struct {
	field     int
	values    [passwordGeneratorFieldCount]string
	generated string
	reveal    bool
}

type secureNoteForm struct {
	itemID            string
	revision          uint64
	parentRevisionIDs []string
	folderID          string
	favorite          bool
	field             int
	values            [secureNoteFormFieldCount]string
	editing           bool
	manualMerge       bool
}

type folderForm struct {
	itemID            string
	revision          uint64
	parentRevisionIDs []string
	name              string
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
	cfg                 client.Config
	lines               []string
	err                 error
	loaded              bool
	vaultOpen           bool
	accessToken         string
	showSessions        bool
	sessionsLoading     bool
	sessions            []client.OnlineSession
	selectedSession     int
	sessionsErr         error
	showActivity        bool
	activityAll         bool
	activityLoading     bool
	activityPage        client.ActivityPage
	activityErr         error
	itemsLoading        bool
	items               []itemRecord
	selectedItem        int
	searchIndex         client.SearchIndex
	searching           bool
	searchQuery         string
	searchMode          client.SearchMode
	selectedConflict    int
	itemsErr            error
	folders             []itemRecord
	selectedFolder      int
	showFolders         bool
	showFolderConflict  bool
	folderFilter        string
	favoritesOnly       bool
	folderDeleteConfirm bool
	folderActionErr     error
	showFolderForm      bool
	folderForm          folderForm
	showMoveFolder      bool
	selectedMoveFolder  int
	showTrash           bool
	trashLoading        bool
	trash               []itemRecord
	selectedTrash       int
	trashErr            error
	purgeConfirm        bool
	showItem            bool
	revealPassword      bool
	clipboard           clipboard.Backend
	copiedField         string
	clipboardErr        error
	breachLoading       bool
	breachResult        *client.PwnedPasswordResult
	breachCheckID       uint64
	showPasswordHistory bool
	selectedHistory     int
	revealHistory       bool
	historyClearConfirm bool
	itemStore           itemStore
	showLoginForm       bool
	loginForm           loginForm
	showTOTPForm        bool
	totpForm            totpForm
	showGenerator       bool
	passwordGenerator   passwordGeneratorForm
	generatorErr        error
	showNoteForm        bool
	noteForm            secureNoteForm
	itemFormErr         error
	itemSaving          bool
	syncLoading         bool
	syncErr             error
	pendingMutations    int
	now                 func() time.Time
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
	m.clipboard, _ = clipboard.Open()
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

func scheduleTOTPRefresh() tea.Cmd {
	return tea.Tick(time.Second, func(time.Time) tea.Msg {
		return totpRefreshMsg{}
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
	return saveItems(store, []itemRecord{record})
}

func saveItems(store itemStore, records []itemRecord) tea.Cmd {
	return func() tea.Msg {
		saveCtx, cancelSave := context.WithTimeout(
			context.Background(), itemOperationTimeout)
		var err error
		for _, record := range records {
			if err = store.Save(saveCtx, record); err != nil {
				break
			}
		}
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
			case client.NativeItemTypeFolder:
				if opened.Folder == nil {
					return nil, client.ErrInvalidItemEnvelope
				}
				folder := *opened.Folder
				record.Folder = &folder
			case client.NativeItemTypeGeneric:
				if opened.Generic == nil {
					return nil, client.ErrInvalidItemEnvelope
				}
				generic := *opened.Generic
				record.Generic = &generic
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
	if record.Folder != nil {
		item, err = session.SealFolder(
			ctx, s.socketPath, *record.Folder, record.Revision)
	} else if record.SecureNote != nil {
		item, err = session.SealSecureNote(
			ctx, s.socketPath, *record.SecureNote, record.Revision)
	} else if record.Generic != nil {
		item, err = session.SealGenericItem(
			ctx, s.socketPath, *record.Generic, record.Revision)
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

func splitRecords(records []itemRecord) ([]itemRecord, []itemRecord) {
	items := make([]itemRecord, 0, len(records))
	folders := make([]itemRecord, 0)
	for _, record := range records {
		if record.Folder != nil {
			folders = append(folders, record)
			continue
		}
		items = append(items, record)
	}
	return items, folders
}

func (m *model) setRecords(records []itemRecord) {
	m.items, m.folders = splitRecords(records)
	m.searchIndex = newSearchIndex(m.items, m.folders)
	if m.folderFilter != "" &&
		m.folderFilter != unfiledFolderFilter {
		var found bool
		for _, folder := range m.folders {
			if folder.Folder != nil &&
				folder.Folder.ItemID == m.folderFilter {
				found = true
				break
			}
		}
		if !found {
			m.folderFilter = unfiledFolderFilter
		}
	}
	if m.selectedItem >= len(m.visibleItems()) {
		m.selectedItem = 0
	}
	if m.selectedFolder >= len(m.folders) {
		m.selectedFolder = 0
	}
}

func newSearchIndex(
	items []itemRecord,
	folders []itemRecord,
) client.SearchIndex {
	nativeItems := make([]client.NativeItem, 0, len(items))
	for _, record := range items {
		if record.SecureNote != nil {
			nativeItems = append(nativeItems, client.NativeItem{
				Type:       client.NativeItemTypeSecureNote,
				SecureNote: record.SecureNote,
			})
			continue
		}
		if record.Generic != nil {
			continue
		}
		nativeItems = append(nativeItems, client.NativeItem{
			Type:  client.NativeItemTypeLogin,
			Login: &record.Login,
		})
	}
	folderItems := make([]client.FolderItem, 0, len(folders))
	for _, record := range folders {
		if record.Folder != nil {
			folderItems = append(folderItems, *record.Folder)
		}
	}
	return client.NewSearchIndex(nativeItems, folderItems)
}

func (m model) visibleItems() []itemRecord {
	items := m.items
	if strings.TrimSpace(m.searchQuery) != "" {
		recordsByID := make(map[string]itemRecord, len(m.items))
		for _, record := range m.items {
			recordsByID[recordItemID(record)] = record
		}
		results := m.searchIndex.Search(m.searchQuery, m.searchMode)
		items = make([]itemRecord, 0, len(results))
		for _, result := range results {
			record, found := recordsByID[result.ItemID]
			if found {
				items = append(items, record)
			}
		}
	}
	visible := make([]itemRecord, 0, len(items))
	for _, record := range items {
		if m.favoritesOnly && !recordIsFavorite(record) {
			continue
		}
		switch m.folderFilter {
		case "":
		case unfiledFolderFilter:
			if recordFolderID(record) != "" {
				continue
			}
		default:
			if recordFolderID(record) != m.folderFilter {
				continue
			}
		}
		visible = append(visible, record)
	}
	return visible
}

func (m model) selectedItemRecord() (itemRecord, bool) {
	items := m.visibleItems()
	if m.selectedItem < 0 || m.selectedItem >= len(items) {
		return itemRecord{}, false
	}
	return items[m.selectedItem], true
}

func recordFolderID(record itemRecord) string {
	if len(record.ConflictVersions) > 1 {
		for _, version := range record.ConflictVersions {
			if folderID := recordFolderID(version); folderID != "" {
				return folderID
			}
		}
		return ""
	}
	if record.SecureNote != nil {
		return record.SecureNote.FolderID
	}
	if record.Generic != nil {
		return record.Generic.FolderID
	}
	return record.Login.FolderID
}

func recordIsFavorite(record itemRecord) bool {
	if len(record.ConflictVersions) > 1 {
		for _, version := range record.ConflictVersions {
			if recordIsFavorite(version) {
				return true
			}
		}
		return false
	}
	if record.SecureNote != nil {
		return record.SecureNote.Favorite
	}
	if record.Generic != nil {
		return record.Generic.Favorite
	}
	return record.Login.Favorite
}

func favoriteMarker(record itemRecord) string {
	if recordIsFavorite(record) {
		return " ★"
	}
	return ""
}

func updateOrganization(
	record itemRecord,
	folderID string,
	favorite bool,
) itemRecord {
	if record.SecureNote != nil {
		note := *record.SecureNote
		note.FolderID = folderID
		note.Favorite = favorite
		record.SecureNote = &note
	} else if record.Generic != nil {
		generic := *record.Generic
		generic.FolderID = folderID
		generic.Favorite = favorite
		record.Generic = &generic
	} else {
		record.Login.FolderID = folderID
		record.Login.Favorite = favorite
	}
	record.Revision++
	record.ParentRevisionIDs = []string{record.RevisionID}
	record.RevisionID = ""
	record.ConflictVersions = nil
	return record
}

func recordsForFolderRemoval(
	folder itemRecord,
	items []itemRecord,
) ([]itemRecord, error) {
	records := make([]itemRecord, 0, len(items)+1)
	for _, record := range items {
		if recordFolderID(record) != folder.Folder.ItemID {
			continue
		}
		if len(record.ConflictVersions) > 1 {
			return nil, fmt.Errorf(
				"resolve Item conflicts before removing this Folder")
		}
		records = append(records, updateOrganization(
			record, "", recordIsFavorite(record)))
	}
	records = append(records, deleteItem(folder))
	return records, nil
}

func (m model) folderName(folderID string) string {
	if folderID == "" {
		return "No Folder"
	}
	for _, record := range m.folders {
		if record.Folder != nil && record.Folder.ItemID == folderID {
			return record.Folder.Name
		}
	}
	return "No Folder"
}

func (m model) itemsInFolder(folderID string) int {
	var count int
	for _, record := range m.items {
		if recordFolderID(record) == folderID {
			count++
		}
	}
	return count
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
	case totpRefreshMsg:
		if m.showTOTPForm &&
			m.totpForm.record.Login.TOTP != nil {
			return m, scheduleTOTPRefresh()
		}
		record, selected := m.selectedItemRecord()
		if m.showItem && selected &&
			len(record.ConflictVersions) == 0 &&
			record.SecureNote == nil &&
			record.Generic == nil &&
			record.Login.TOTP != nil {
			return m, scheduleTOTPRefresh()
		}
		return m, nil
	case tea.KeyMsg:
		if m.showGenerator {
			return m.updatePasswordGenerator(msg)
		}
		if m.showTOTPForm {
			return m.updateTOTPForm(msg)
		}
		if m.showLoginForm {
			return m.updateLoginForm(msg)
		}
		if m.showNoteForm {
			return m.updateSecureNoteForm(msg)
		}
		if m.showFolderForm {
			return m.updateFolderForm(msg)
		}
		if m.showMoveFolder {
			return m.updateMoveFolder(msg)
		}
		if m.showPasswordHistory {
			return m.updatePasswordHistory(msg)
		}
		if m.searching {
			return m.updateSearch(msg)
		}
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			return m, tea.Quit
		case "/", "ctrl+f":
			if m.vaultOpen && !m.showSessions && !m.showActivity &&
				!m.showItem && !m.showTrash && !m.showFolders &&
				!m.showFolderConflict {
				m.searching = true
				m.searchQuery = ""
				m.searchMode = client.SearchModeMetadata
				if msg.String() == "ctrl+f" {
					m.searchMode = client.SearchModeNoteContents
				}
				m.selectedItem = 0
			}
		case "s":
			if m.vaultOpen && m.accessToken != "" && !m.showFolders {
				m.showActivity = false
				m.showSessions = true
				m.sessionsLoading = true
				m.sessionsErr = nil
				return m, loadSessions(m.cfg, m.accessToken)
			}
		case "a":
			if m.showFolders {
				m.folderFilter = ""
				m.selectedItem = 0
				m.showFolders = false
				m.folderDeleteConfirm = false
				return m, nil
			}
			if m.vaultOpen && m.accessToken != "" {
				m.showSessions = false
				m.showActivity = true
				m.activityAll = false
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(m.cfg, m.accessToken, false, "")
			}
		case "b":
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 &&
				record.SecureNote == nil &&
				record.Generic == nil &&
				!m.breachLoading {
				m.breachCheckID++
				m.breachLoading = true
				m.breachResult = nil
				return m, checkPwnedPassword(
					m.cfg,
					record.Login.Password,
					m.breachCheckID,
				)
			}
		case "c":
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 {
				if record.SecureNote != nil {
					return m, copySecret(
						m.clipboard,
						"Secure Note content",
						record.SecureNote.Content,
					)
				}
				if record.Generic != nil {
					return m, nil
				}
				return m, copySecret(
					m.clipboard,
					"password",
					record.Login.Password,
				)
			}
			if m.showFolders && m.itemStore != nil {
				itemID, err := client.NewItemID()
				if err != nil {
					m.folderActionErr = err
					return m, nil
				}
				m.showFolderForm = true
				m.folderForm = folderForm{
					itemID:   itemID,
					revision: 1,
				}
				m.folderActionErr = nil
				m.itemSaving = false
				return m, nil
			}
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem && !m.showTrash && !m.showFolders {
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
				m.clearBreachCheck()
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
				!m.showItem && !m.showTrash && !m.showFolders {
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
			if m.showFolders && m.selectedFolder < len(m.folders) {
				record := m.folders[m.selectedFolder]
				if len(record.ConflictVersions) == 0 {
					m.showFolderForm = true
					m.folderForm = formForFolder(record)
					m.folderActionErr = nil
					m.itemSaving = false
				}
				return m, nil
			}
			record, selected := m.selectedItemRecord()
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				selected &&
				len(record.ConflictVersions) == 0 {
				if record.Generic != nil {
					return m, nil
				}
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
			if m.showFolders && m.itemStore != nil &&
				m.selectedFolder < len(m.folders) {
				folder := m.folders[m.selectedFolder]
				if len(folder.ConflictVersions) > 0 {
					return m, nil
				}
				if !m.folderDeleteConfirm {
					m.folderDeleteConfirm = true
					m.folderActionErr = nil
					return m, nil
				}
				records, err := recordsForFolderRemoval(
					folder, m.items)
				if err != nil {
					m.folderActionErr = err
					m.folderDeleteConfirm = false
					return m, nil
				}
				m.itemSaving = true
				return m, saveItems(m.itemStore, records)
			}
			record, selected := m.selectedItemRecord()
			if m.showItem && m.itemStore != nil && selected {
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
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 &&
				record.SecureNote == nil &&
				record.Generic == nil {
				m.revealPassword = !m.revealPassword
			}
		case "h":
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 &&
				record.SecureNote == nil &&
				record.Generic == nil {
				m.showPasswordHistory = true
				m.selectedHistory = 0
				m.revealHistory = false
				m.historyClearConfirm = false
			}
		case "f":
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 &&
				m.itemStore != nil {
				m.itemSaving = true
				return m, saveItem(m.itemStore, updateOrganization(
					record,
					recordFolderID(record),
					!recordIsFavorite(record),
				))
			}
			if !m.showFolders && !m.showSessions &&
				!m.showActivity && !m.showTrash &&
				!m.showFolderConflict {
				m.favoritesOnly = !m.favoritesOnly
				m.selectedItem = 0
			}
		case "o":
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 {
				m.showMoveFolder = true
				m.selectedMoveFolder = 0
				for index, folder := range m.folders {
					if folder.Folder != nil &&
						folder.Folder.ItemID == recordFolderID(record) {
						m.selectedMoveFolder = index + 1
						break
					}
				}
				return m, nil
			}
			if !m.showSessions && !m.showActivity &&
				!m.showTrash && !m.showFolderConflict {
				m.showFolders = true
				m.showItem = false
				m.folderDeleteConfirm = false
				m.folderActionErr = nil
			}
		case "u":
			if m.showFolders {
				m.folderFilter = unfiledFolderFilter
				m.selectedItem = 0
				m.showFolders = false
				m.folderDeleteConfirm = false
			}
		case "m":
			if m.showFolderConflict &&
				m.selectedFolder < len(m.folders) {
				record := m.folders[m.selectedFolder]
				if len(record.ConflictVersions) > 1 {
					m.showFolderConflict = false
					m.showFolderForm = true
					m.folderForm = formForFolderConflict(
						record.ConflictVersions,
						m.selectedConflict,
					)
					m.itemFormErr = nil
					m.itemSaving = false
				}
				return m, nil
			}
			record, selected := m.selectedItemRecord()
			if m.showItem && selected {
				if len(record.ConflictVersions) > 1 {
					if record.Generic != nil {
						return m, nil
					}
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
			record, selected := m.selectedItemRecord()
			if m.showItem && selected &&
				len(record.ConflictVersions) == 0 &&
				record.SecureNote == nil &&
				record.Generic == nil {
				m.showItem = false
				m.showTOTPForm = true
				m.totpForm = formForTOTP(record)
				m.itemFormErr = nil
				m.itemSaving = false
				return m, nil
			}
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem && !m.showFolders &&
				!m.showFolderConflict {
				m.showTrash = true
				m.trashLoading = true
				m.trashErr = nil
				m.purgeConfirm = false
				return m, loadTrash(m.itemStore)
			}
		case "enter":
			if m.showFolderConflict &&
				m.selectedFolder < len(m.folders) {
				record := m.folders[m.selectedFolder]
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
				return m, nil
			}
			if m.showFolders && m.selectedFolder < len(m.folders) {
				folder := m.folders[m.selectedFolder]
				if len(folder.ConflictVersions) > 1 {
					m.showFolders = false
					m.showFolderConflict = true
					m.selectedConflict = 0
				} else if folder.Folder != nil {
					m.folderFilter = folder.Folder.ItemID
					m.selectedItem = 0
					m.showFolders = false
					m.folderDeleteConfirm = false
				}
				return m, nil
			}
			record, selected := m.selectedItemRecord()
			if m.showItem && selected {
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
				!m.showTrash && selected {
				m.showItem = true
				m.revealPassword = false
				m.selectedConflict = 0
				m.copiedField = ""
				m.clipboardErr = nil
				m.clearBreachCheck()
				if record.SecureNote == nil &&
					record.Generic == nil &&
					record.Login.TOTP != nil {
					return m, scheduleTOTPRefresh()
				}
			}
		case "g":
			if m.showActivity && m.activityPage.CanViewAll {
				m.activityAll = !m.activityAll
				m.activityLoading = true
				m.activityErr = nil
				return m, loadActivity(
					m.cfg, m.accessToken, m.activityAll, "")
			}
			if m.vaultOpen && m.itemStore != nil &&
				!m.showSessions && !m.showActivity &&
				!m.showItem && !m.showTrash &&
				!m.showFolders && !m.showFolderConflict {
				m.showGenerator = true
				m.passwordGenerator =
					defaultPasswordGeneratorForm()
				m.generatorErr = nil
				m.copiedField = ""
				m.clipboardErr = nil
				m.clearBreachCheck()
				return m, nil
			}
		case "v":
			m.showSessions = false
			m.showActivity = false
			m.showItem = false
			m.showTrash = false
			m.showFolders = false
			m.showFolderConflict = false
			m.showMoveFolder = false
			m.showFolderForm = false
			m.showTOTPForm = false
			m.showGenerator = false
			m.showPasswordHistory = false
			m.historyClearConfirm = false
			m.revealPassword = false
			m.revealHistory = false
			m.selectedConflict = 0
			m.purgeConfirm = false
			m.folderDeleteConfirm = false
			m.showNoteForm = false
			m.searching = false
			m.searchQuery = ""
			m.copiedField = ""
			m.clipboardErr = nil
			m.clearBreachCheck()
			return m, nil
		case "j", "down":
			if m.showSessions && m.selectedSession+1 < len(m.sessions) {
				m.selectedSession++
			} else if m.showFolderConflict &&
				m.selectedFolder < len(m.folders) &&
				m.selectedConflict+1 <
					len(m.folders[m.selectedFolder].ConflictVersions) {
				m.selectedConflict++
			} else if m.showFolders &&
				m.selectedFolder+1 < len(m.folders) {
				m.selectedFolder++
				m.folderDeleteConfirm = false
				m.folderActionErr = nil
			} else if m.showItem {
				record, selected := m.selectedItemRecord()
				if selected && m.selectedConflict+1 <
					len(record.ConflictVersions) {
					m.selectedConflict++
				}
			} else if m.showTrash &&
				m.selectedTrash+1 < len(m.trash) {
				m.selectedTrash++
				m.purgeConfirm = false
			} else if !m.showSessions && !m.showActivity && !m.showItem &&
				!m.showFolders &&
				m.selectedItem+1 < len(m.visibleItems()) {
				m.selectedItem++
			}
		case "k", "up":
			if m.showSessions && m.selectedSession > 0 {
				m.selectedSession--
			} else if m.showFolderConflict && m.selectedConflict > 0 {
				m.selectedConflict--
			} else if m.showFolders && m.selectedFolder > 0 {
				m.selectedFolder--
				m.folderDeleteConfirm = false
				m.folderActionErr = nil
			} else if m.showItem && m.selectedConflict > 0 {
				m.selectedConflict--
			} else if m.showTrash && m.selectedTrash > 0 {
				m.selectedTrash--
				m.purgeConfirm = false
			} else if !m.showSessions && !m.showActivity && !m.showItem &&
				!m.showFolders &&
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
		m.setRecords([]itemRecord(msg))
		m.selectedConflict = 0
		m.showLoginForm = false
		m.showTOTPForm = false
		m.showNoteForm = false
		m.showFolderForm = false
		m.itemFormErr = nil
		m.itemSaving = false
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
	case secretCopiedMsg:
		m.copiedField = ""
		m.clipboardErr = nil
		if msg.err != nil {
			if errors.Is(msg.err, clipboard.ErrUnavailable) {
				m.clipboardErr = clipboard.ErrUnavailable
			} else {
				m.clipboardErr = errors.New(
					"clipboard operation failed")
			}
		} else {
			m.copiedField = msg.field
		}
	case breachCheckMsg:
		if msg.id != m.breachCheckID {
			break
		}
		result := msg.result
		m.breachLoading = false
		m.breachResult = &result
	case itemSavedMsg:
		m.setRecords(msg.items)
		m.showItem = false
		m.showTrash = false
		m.showMoveFolder = false
		m.showFolderConflict = false
		m.showPasswordHistory = false
		m.historyClearConfirm = false
		m.selectedConflict = 0
		m.clearBreachCheck()
		m.showLoginForm = false
		m.showNoteForm = false
		m.showFolderForm = false
		m.itemFormErr = nil
		m.folderActionErr = nil
		m.folderDeleteConfirm = false
		m.itemSaving = false
		m.syncErr = msg.syncErr
		m.pendingMutations = msg.pending
		if msg.syncErr != nil {
			return m, checkStatus(m.cfg)
		}
	case syncResultMsg:
		m.syncLoading = false
		m.syncErr = msg.err
		m.pendingMutations = msg.pending
		m.setRecords(msg.items)
		m.selectedConflict = 0
		if msg.err != nil {
			return m, checkStatus(m.cfg)
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.showGenerator {
		return m.passwordGeneratorView()
	}
	if m.showTOTPForm {
		return m.totpFormView()
	}
	if m.showLoginForm {
		return m.loginFormView()
	}
	if m.showNoteForm {
		return m.secureNoteFormView()
	}
	if m.showFolderForm {
		return m.folderFormView()
	}
	if m.showMoveFolder {
		return m.moveFolderView()
	}
	if m.showPasswordHistory {
		return m.passwordHistoryView()
	}
	if m.showFolderConflict {
		if m.selectedFolder >= len(m.folders) {
			return "TermKeep — Conflict\n\nFolder not found.\n\n[v] vault  [q] quit\n"
		}
		return m.conflictView(
			m.folders[m.selectedFolder].ConflictVersions)
	}
	if m.showTrash {
		return m.trashView()
	}
	if m.showItem {
		return m.itemView()
	}
	if m.showFolders {
		return m.foldersView()
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
		visibleItems := m.visibleItems()
		switch {
		case m.itemsLoading:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Items:    loading…\n")
		case m.itemsErr != nil:
			b.WriteString("Vault:    unlocked\n")
			b.WriteString("Items:    error — " + m.itemsErr.Error() + "\n")
		case len(m.items) == 0 && len(m.folders) == 0:
			b.WriteString("Vault:    unlocked (empty)\n")
		default:
			b.WriteString("Vault:    unlocked\n")
			if m.searching || m.searchQuery != "" {
				searchMode := "metadata"
				if m.searchMode == client.SearchModeNoteContents {
					searchMode = "Notes"
				}
				fmt.Fprintf(
					&b,
					"Search:   %s — %s\n",
					searchMode,
					m.searchQuery,
				)
			}
			if m.favoritesOnly {
				b.WriteString("View:     Favorites\n")
			}
			if m.folderFilter != "" {
				folderID := m.folderFilter
				if folderID == unfiledFolderFilter {
					folderID = ""
				}
				b.WriteString(
					"Folder:   " +
						m.folderName(folderID) +
						"\n",
				)
			}
			b.WriteString("Items:\n")
			if len(visibleItems) == 0 {
				b.WriteString("  No Items in this view.\n")
			}
			for index, record := range visibleItems {
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
						"%s%s [Secure Note] %s\n",
						cursor,
						favoriteMarker(record),
						record.SecureNote.Title,
					)
				} else if record.Generic != nil {
					fmt.Fprintf(
						&b,
						"%s%s [Generic] %s\n",
						cursor,
						favoriteMarker(record),
						record.Generic.Title,
					)
				} else {
					fmt.Fprintf(&b, "%s%s [Login] %s — %s\n",
						cursor, favoriteMarker(record),
						record.Login.Name, record.Login.Username)
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
		if m.searching {
			b.WriteString(
				"\n[type] search  [backspace] edit  " +
					"[enter] keep  [esc] clear  [ctrl+c] quit\n",
			)
			return b.String()
		}
		b.WriteString(
			"\n[c] new Login  [n] new Secure Note  " +
				"[g] generate password  " +
				"[f] Favorites  [/] search  [ctrl+f] Notes  " +
				"[enter] open  " +
				"[o] Folders  [t] Trash  ",
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

func (m model) updateSearch(
	msg tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.searching = false
		m.searchQuery = ""
		m.selectedItem = 0
	case "enter":
		m.searching = false
	case "backspace":
		query := []rune(m.searchQuery)
		if len(query) > 0 {
			m.searchQuery = string(query[:len(query)-1])
			m.selectedItem = 0
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.searchQuery += string(msg.Runes)
			m.selectedItem = 0
		}
	}
	return m, nil
}

func copySecret(
	board clipboard.Backend,
	field string,
	value string,
) tea.Cmd {
	return func() tea.Msg {
		if board == nil {
			return secretCopiedMsg{
				field: field,
				err:   clipboard.ErrUnavailable,
			}
		}
		_, err := clipboard.Copy(
			context.Background(),
			board,
			value,
			clipboard.ClearDelay,
		)
		return secretCopiedMsg{field: field, err: err}
	}
}

func (m model) clipboardFeedback() string {
	switch {
	case m.clipboardErr != nil:
		return "\nClipboard error: " + m.clipboardErr.Error() + "\n"
	case m.copiedField != "":
		return "\nCopied: " + m.copiedField +
			" (clears in 30 seconds)\n"
	default:
		return ""
	}
}

func checkPwnedPassword(
	cfg client.Config,
	password string,
	id uint64,
) tea.Cmd {
	return func() tea.Msg {
		return breachCheckMsg{
			id: id,
			result: client.CheckPwnedPassword(
				context.Background(),
				cfg,
				password,
			),
		}
	}
}

func (m *model) clearBreachCheck() {
	m.breachCheckID++
	m.breachLoading = false
	m.breachResult = nil
}

func (m model) breachFeedback() string {
	switch {
	case m.breachLoading:
		return "\nPwned Passwords: checking…\n"
	case m.breachResult == nil:
		return ""
	}
	switch m.breachResult.Status {
	case client.PwnedPasswordDisabled:
		return "\nPwned Passwords: disabled\n"
	case client.PwnedPasswordNotFound:
		return "\nPwned Passwords: not found\n"
	case client.PwnedPasswordFound:
		return fmt.Sprintf(
			"\nPwned Passwords: found — %d occurrences\n",
			m.breachResult.Count,
		)
	case client.PwnedPasswordUnavailable:
		return "\nPwned Passwords: unavailable\n"
	default:
		return "\nPwned Passwords: invalid response\n"
	}
}

func defaultPasswordGeneratorForm() passwordGeneratorForm {
	return passwordGeneratorForm{
		values: [passwordGeneratorFieldCount]string{
			"20",
			"yes",
			"yes",
			"yes",
			"yes",
			"1",
			"1",
			"no",
		},
	}
}

func (m model) updatePasswordGenerator(
	msg tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	if m.passwordGenerator.generated != "" {
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "esc":
			m.showGenerator = false
			m.passwordGenerator = passwordGeneratorForm{}
			m.generatorErr = nil
			m.copiedField = ""
			m.clipboardErr = nil
			m.clearBreachCheck()
		case "p":
			m.passwordGenerator.reveal =
				!m.passwordGenerator.reveal
		case "c":
			return m, copySecret(
				m.clipboard,
				"generated password",
				m.passwordGenerator.generated,
			)
		case "b":
			if !m.breachLoading {
				m.breachCheckID++
				m.breachLoading = true
				m.breachResult = nil
				return m, checkPwnedPassword(
					m.cfg,
					m.passwordGenerator.generated,
					m.breachCheckID,
				)
			}
		case "g":
			password, err := generatePasswordFromForm(
				m.passwordGenerator,
			)
			if err != nil {
				m.generatorErr = err
				return m, nil
			}
			m.passwordGenerator.generated = password
			m.passwordGenerator.reveal = false
			m.generatorErr = nil
			m.copiedField = ""
			m.clipboardErr = nil
			m.clearBreachCheck()
		}
		return m, nil
	}

	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.showGenerator = false
		m.passwordGenerator = passwordGeneratorForm{}
		m.generatorErr = nil
		m.clearBreachCheck()
		return m, nil
	case "ctrl+u":
		m.passwordGenerator.values[m.passwordGenerator.field] = ""
	case "backspace":
		value := []rune(
			m.passwordGenerator.values[m.passwordGenerator.field],
		)
		if len(value) > 0 {
			m.passwordGenerator.values[m.passwordGenerator.field] =
				string(value[:len(value)-1])
		}
	case "enter":
		if m.passwordGenerator.field+1 <
			passwordGeneratorFieldCount {
			m.passwordGenerator.field++
			m.generatorErr = nil
			return m, nil
		}
		password, err := generatePasswordFromForm(
			m.passwordGenerator,
		)
		if err != nil {
			m.generatorErr = err
			return m, nil
		}
		m.passwordGenerator.generated = password
		m.passwordGenerator.reveal = false
		m.generatorErr = nil
		m.clearBreachCheck()
	default:
		if msg.Type == tea.KeyRunes {
			m.passwordGenerator.values[m.passwordGenerator.field] +=
				string(msg.Runes)
		}
	}
	return m, nil
}

func generatePasswordFromForm(
	form passwordGeneratorForm,
) (string, error) {
	length, err := passwordGeneratorInt(form.values[0])
	if err != nil {
		return "", err
	}
	uppercase, err := passwordGeneratorBool(form.values[1])
	if err != nil {
		return "", err
	}
	lowercase, err := passwordGeneratorBool(form.values[2])
	if err != nil {
		return "", err
	}
	digits, err := passwordGeneratorBool(form.values[3])
	if err != nil {
		return "", err
	}
	special, err := passwordGeneratorBool(form.values[4])
	if err != nil {
		return "", err
	}
	minimumDigits, err := passwordGeneratorInt(form.values[5])
	if err != nil {
		return "", err
	}
	minimumSpecial, err := passwordGeneratorInt(form.values[6])
	if err != nil {
		return "", err
	}
	excludeAmbiguous, err := passwordGeneratorBool(form.values[7])
	if err != nil {
		return "", err
	}
	return client.GeneratePassword(client.PasswordGeneratorConfig{
		Length:           length,
		Uppercase:        uppercase,
		Lowercase:        lowercase,
		Digits:           digits,
		Special:          special,
		MinimumDigits:    minimumDigits,
		MinimumSpecial:   minimumSpecial,
		ExcludeAmbiguous: excludeAmbiguous,
	})
}

func passwordGeneratorInt(value string) (int, error) {
	parsed, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, client.ErrInvalidPasswordGeneratorConfig
	}
	return parsed, nil
}

func passwordGeneratorBool(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "yes", "y", "true", "on":
		return true, nil
	case "no", "n", "false", "off":
		return false, nil
	default:
		return false, client.ErrInvalidPasswordGeneratorConfig
	}
}

func (m model) passwordGeneratorView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Password Generator\n\n")
	if m.passwordGenerator.generated != "" {
		password := "••••••••••••"
		if m.passwordGenerator.reveal {
			password = m.passwordGenerator.generated
		}
		fmt.Fprintf(&b, "Generated password: %s\n", password)
		if m.generatorErr != nil {
			fmt.Fprintf(
				&b,
				"\nError: %s\n",
				m.generatorErr,
			)
		}
		b.WriteString(m.clipboardFeedback())
		b.WriteString(m.breachFeedback())
		b.WriteString(
			"\n[p] reveal/hide  [c] copy  [b] check Pwned  " +
				"[g] regenerate  " +
				"[esc] vault  [q] quit\n",
		)
		return b.String()
	}

	for index, label := range passwordGeneratorLabels {
		cursor := " "
		if index == m.passwordGenerator.field {
			cursor = ">"
		}
		fmt.Fprintf(
			&b,
			"%s %s: %s\n",
			cursor,
			label,
			m.passwordGenerator.values[index],
		)
	}
	if m.generatorErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.generatorErr)
	}
	b.WriteString(
		"\n[enter] next/generate  [ctrl+u] clear field  " +
			"[esc] cancel  [ctrl+c] quit\n",
	)
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
			ItemID:   form.itemID,
			Title:    title,
			Content:  form.values[1],
			FolderID: form.folderID,
			Favorite: form.favorite,
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

func (m model) updateFolderForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
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
		m.showFolderForm = false
		m.itemFormErr = nil
	case "ctrl+u":
		m.folderForm.name = ""
	case "backspace":
		value := []rune(m.folderForm.name)
		if len(value) > 0 {
			m.folderForm.name = string(value[:len(value)-1])
		}
	case "enter":
		name := strings.TrimSpace(m.folderForm.name)
		if name == "" {
			m.itemFormErr = fmt.Errorf("Folder name is required")
			return m, nil
		}
		m.itemSaving = true
		m.itemFormErr = nil
		return m, saveItem(m.itemStore, itemRecord{
			Folder: &client.FolderItem{
				ItemID: m.folderForm.itemID,
				Name:   name,
			},
			Revision: m.folderForm.revision,
			ParentRevisionIDs: append(
				[]string(nil),
				m.folderForm.parentRevisionIDs...,
			),
		})
	default:
		if msg.Type == tea.KeyRunes {
			m.folderForm.name += string(msg.Runes)
		}
	}
	return m, nil
}

func formForFolder(record itemRecord) folderForm {
	var parentRevisionIDs []string
	if record.RevisionID != "" {
		parentRevisionIDs = []string{record.RevisionID}
	}
	return folderForm{
		itemID:            record.Folder.ItemID,
		revision:          record.Revision + 1,
		parentRevisionIDs: parentRevisionIDs,
		name:              record.Folder.Name,
		editing:           true,
	}
}

func formForFolderConflict(
	versions []itemRecord,
	selected int,
) folderForm {
	if selected < 0 ||
		selected >= len(versions) ||
		versions[selected].Folder == nil {
		for index, version := range versions {
			if version.Folder != nil {
				selected = index
				break
			}
		}
	}
	resolution := resolveConflict(versions, selected)
	form := formForFolder(itemRecord{
		Folder:   resolution.Folder,
		Revision: resolution.Revision - 1,
	})
	form.parentRevisionIDs = append(
		[]string(nil), resolution.ParentRevisionIDs...)
	form.manualMerge = true
	return form
}

func (m model) folderFormView() string {
	title := "New Folder"
	if m.folderForm.manualMerge {
		title = "Manual Folder Conflict Merge"
	} else if m.folderForm.editing {
		title = "Rename Folder"
	}
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"TermKeep — %s\n\n> Name: %s\n",
		title,
		m.folderForm.name,
	)
	if m.itemFormErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.itemFormErr)
	}
	if m.itemSaving {
		b.WriteString("\nSaving…  [ctrl+c] quit\n")
	} else {
		b.WriteString(
			"\n[enter] save  [ctrl+u] clear field  " +
				"[esc] cancel  [ctrl+c] quit\n",
		)
	}
	return b.String()
}

func (m model) updateMoveFolder(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc", "v":
		m.showMoveFolder = false
		return m, nil
	case "j", "down":
		if m.selectedMoveFolder < len(m.folders) {
			m.selectedMoveFolder++
		}
	case "k", "up":
		if m.selectedMoveFolder > 0 {
			m.selectedMoveFolder--
		}
	case "enter":
		record, ok := m.selectedItemRecord()
		if !ok {
			m.showMoveFolder = false
			return m, nil
		}
		folderID := ""
		if m.selectedMoveFolder > 0 {
			folder := m.folders[m.selectedMoveFolder-1]
			if folder.Folder != nil {
				folderID = folder.Folder.ItemID
			}
		}
		if folderID == recordFolderID(record) {
			m.showMoveFolder = false
			return m, nil
		}
		m.itemSaving = true
		return m, saveItem(m.itemStore, updateOrganization(
			record, folderID, recordIsFavorite(record)))
	}
	return m, nil
}

func (m model) moveFolderView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Move Item\n\n")
	cursor := " "
	if m.selectedMoveFolder == 0 {
		cursor = ">"
	}
	fmt.Fprintf(&b, "%s No Folder\n", cursor)
	for index, record := range m.folders {
		if record.Folder == nil {
			continue
		}
		cursor = " "
		if m.selectedMoveFolder == index+1 {
			cursor = ">"
		}
		fmt.Fprintf(&b, "%s %s\n", cursor, record.Folder.Name)
	}
	b.WriteString(
		"\n[j/k] select  [enter] move  [esc] cancel  [q] quit\n",
	)
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
		record, err := recordFromLoginForm(
			m.loginForm,
			m.currentTime(),
		)
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

func (m model) currentTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func recordFromLoginForm(
	form loginForm,
	changedAt time.Time,
) (itemRecord, error) {
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
	login := client.RotateLoginPassword(client.LoginItem{
		ItemID:   form.itemID,
		Name:     name,
		Username: strings.TrimSpace(form.values[1]),
		Password: form.previousPassword,
		PasswordHistory: append(
			[]client.PasswordHistoryEntry(nil),
			form.passwordHistory...,
		),
		FolderID:     form.folderID,
		Favorite:     form.favorite,
		URLs:         urls,
		Notes:        form.values[4],
		CustomFields: customFields,
		TOTP:         cloneTOTPConfig(form.totp),
	}, form.values[2], changedAt)
	return itemRecord{
		Login:    login,
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
		folderID:          record.Login.FolderID,
		favorite:          record.Login.Favorite,
		previousPassword:  record.Login.Password,
		passwordHistory: append(
			[]client.PasswordHistoryEntry(nil),
			record.Login.PasswordHistory...,
		),
		totp:    cloneTOTPConfig(record.Login.TOTP),
		editing: true,
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

func (m model) updateTOTPForm(
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
		m.showTOTPForm = false
		m.showItem = true
		m.itemFormErr = nil
		return m, nil
	case "ctrl+u":
		m.totpForm.values[m.totpForm.field] = ""
	case "backspace":
		value := []rune(m.totpForm.values[m.totpForm.field])
		if len(value) > 0 {
			m.totpForm.values[m.totpForm.field] =
				string(value[:len(value)-1])
		}
	case "enter":
		if m.totpForm.field+1 < totpFormFieldCount {
			m.totpForm.field++
			m.itemFormErr = nil
			return m, nil
		}
		record, err := recordFromTOTPForm(m.totpForm)
		if err != nil {
			m.itemFormErr = err
			return m, nil
		}
		m.itemSaving = true
		m.itemFormErr = nil
		return m, saveItem(m.itemStore, record)
	default:
		if msg.Type == tea.KeyRunes {
			m.totpForm.values[m.totpForm.field] += string(msg.Runes)
		}
	}
	return m, nil
}

func recordFromTOTPForm(form totpForm) (itemRecord, error) {
	values := form.values
	var config *client.TOTPConfig
	if rawURI := strings.TrimSpace(values[0]); rawURI != "" {
		parsed, err := client.ParseTOTPURI(rawURI)
		if err != nil {
			return itemRecord{}, err
		}
		config = &parsed
	} else {
		allEmpty := true
		for _, value := range values[1:] {
			if value != "" {
				allEmpty = false
				break
			}
		}
		if !allEmpty {
			digits, err := optionalTOTPInt(values[5])
			if err != nil {
				return itemRecord{}, err
			}
			period, err := optionalTOTPInt(values[6])
			if err != nil {
				return itemRecord{}, err
			}
			parsed, err := client.NewTOTPConfig(
				values[1],
				values[2],
				values[3],
				strings.TrimSpace(values[4]),
				digits,
				period,
			)
			if err != nil {
				return itemRecord{}, err
			}
			config = &parsed
		}
	}

	record := form.record
	record.Login.TOTP = config
	record.Revision++
	if record.RevisionID != "" {
		record.ParentRevisionIDs = []string{record.RevisionID}
	} else {
		record.ParentRevisionIDs = nil
	}
	record.RevisionID = ""
	record.ConflictVersions = nil
	return record, nil
}

func optionalTOTPInt(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, client.ErrInvalidTOTP
	}
	return parsed, nil
}

func formForTOTP(record itemRecord) totpForm {
	form := totpForm{record: record}
	if record.Login.TOTP == nil {
		return form
	}
	config := record.Login.TOTP
	form.values[1] = config.Secret
	form.values[2] = config.Issuer
	form.values[3] = config.Account
	form.values[4] = string(config.Algorithm)
	form.values[5] = strconv.Itoa(config.Digits)
	form.values[6] = strconv.Itoa(config.Period)
	return form
}

func cloneTOTPConfig(config *client.TOTPConfig) *client.TOTPConfig {
	if config == nil {
		return nil
	}
	cloned := *config
	return &cloned
}

func (m model) totpFormView() string {
	var b strings.Builder
	b.WriteString("TermKeep — TOTP Setup\n\n")
	for index, label := range totpFormLabels {
		cursor := " "
		if index == m.totpForm.field {
			cursor = ">"
		}
		value := m.totpForm.values[index]
		if (index == 0 || index == 1) && value != "" {
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
		b.WriteString(
			"\n[enter] next/save  [ctrl+u] clear field  " +
				"[esc] cancel  [ctrl+c] quit\n",
		)
	}
	return b.String()
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
		folderID:          record.SecureNote.FolderID,
		favorite:          record.SecureNote.Favorite,
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

func (m model) foldersView() string {
	var b strings.Builder
	b.WriteString("TermKeep — Folders\n\n")
	if len(m.folders) == 0 {
		b.WriteString("No Folders.\n")
	} else {
		for index, record := range m.folders {
			cursor := " "
			if index == m.selectedFolder {
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
				continue
			}
			fmt.Fprintf(
				&b,
				"%s %s (%d Items)\n",
				cursor,
				record.Folder.Name,
				m.itemsInFolder(record.Folder.ItemID),
			)
		}
	}
	if m.folderDeleteConfirm &&
		m.selectedFolder < len(m.folders) {
		folder := m.folders[m.selectedFolder]
		count := m.itemsInFolder(folder.Folder.ItemID)
		fmt.Fprintf(
			&b,
			"\nWarning: removing this Folder moves %d %s to No Folder.\n"+
				"Press [d] again to remove %s.\n",
			count,
			itemCountLabel(count),
			folder.Folder.Name,
		)
	}
	if m.folderActionErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.folderActionErr)
	}
	b.WriteString(
		"\n[j/k] select  [enter] open  [a] All Items  " +
			"[u] No Folder  [c] create  [e] rename  [d] remove  " +
			"[v] vault  [q] quit\n",
	)
	return b.String()
}

func itemCountLabel(count int) string {
	if count == 1 {
		return "Item"
	}
	return "Items"
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
			if record.Folder != nil {
				fmt.Fprintf(
					&b, "%s [Folder] %s\n",
					cursor, record.Folder.Name,
				)
			} else if record.SecureNote != nil {
				fmt.Fprintf(
					&b, "%s [Secure Note] %s\n",
					cursor, record.SecureNote.Title,
				)
			} else if record.Generic != nil {
				fmt.Fprintf(
					&b, "%s [Generic] %s\n",
					cursor, record.Generic.Title,
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

func (m model) updatePasswordHistory(
	msg tea.KeyMsg,
) (tea.Model, tea.Cmd) {
	if m.itemSaving {
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		return m, nil
	}
	record, ok := m.selectedItemRecord()
	if !ok || record.SecureNote != nil {
		m.showPasswordHistory = false
		return m, nil
	}
	history := record.Login.PasswordHistory
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.showPasswordHistory = false
		m.revealHistory = false
		m.historyClearConfirm = false
	case "v":
		m.showPasswordHistory = false
		m.showItem = false
		m.revealHistory = false
		m.historyClearConfirm = false
	case "j", "down":
		if m.selectedHistory+1 < len(history) {
			m.selectedHistory++
			m.revealHistory = false
			m.historyClearConfirm = false
		}
	case "k", "up":
		if m.selectedHistory > 0 {
			m.selectedHistory--
			m.revealHistory = false
			m.historyClearConfirm = false
		}
	case "p":
		if m.selectedHistory < len(history) {
			m.revealHistory = !m.revealHistory
			m.historyClearConfirm = false
		}
	case "c":
		if m.selectedHistory < len(history) {
			entry := history[m.selectedHistory]
			return m, copySecret(
				m.clipboard,
				"historical password from "+
					entry.ChangedAt.UTC().Format(time.RFC3339),
				entry.Password,
			)
		}
	case "x":
		if len(history) == 0 {
			return m, nil
		}
		if !m.historyClearConfirm {
			m.historyClearConfirm = true
			m.revealHistory = false
			return m, nil
		}
		record.Login.PasswordHistory = nil
		record.Revision++
		record.ParentRevisionIDs = []string{record.RevisionID}
		record.RevisionID = ""
		record.ConflictVersions = nil
		m.itemSaving = true
		m.itemFormErr = nil
		return m, saveItem(m.itemStore, record)
	}
	return m, nil
}

func (m model) passwordHistoryView() string {
	record, ok := m.selectedItemRecord()
	if !ok || record.SecureNote != nil {
		return "TermKeep — Password History\n\nLogin not found.\n\n[v] vault  [q] quit\n"
	}
	var b strings.Builder
	fmt.Fprintf(
		&b,
		"TermKeep — Password History — %s\n\n",
		record.Login.Name,
	)
	if len(record.Login.PasswordHistory) == 0 {
		b.WriteString("Password history is empty.\n")
	} else {
		for index, entry := range record.Login.PasswordHistory {
			cursor := " "
			if index == m.selectedHistory {
				cursor = ">"
			}
			password := "••••••••"
			if index == m.selectedHistory && m.revealHistory {
				password = entry.Password
			}
			fmt.Fprintf(
				&b,
				"%s %s — %s\n",
				cursor,
				entry.ChangedAt.UTC().Format(time.RFC3339),
				password,
			)
		}
	}
	if m.historyClearConfirm {
		fmt.Fprintf(
			&b,
			"\nWarning: historical passwords cannot be recovered.\n"+
				"Press [x] again to clear all %d entries.\n",
			len(record.Login.PasswordHistory),
		)
	}
	if m.itemFormErr != nil {
		fmt.Fprintf(&b, "\nError: %s\n", m.itemFormErr)
	}
	b.WriteString(m.clipboardFeedback())
	if m.itemSaving {
		b.WriteString("\nSaving…  [ctrl+c] quit\n")
		return b.String()
	}
	b.WriteString(
		"\n[j/k] select  [p] reveal/hide selected  " +
			"[c] copy selected  [x] clear all  " +
			"[esc] Login  [v] vault  [q] quit\n",
	)
	return b.String()
}

func (m model) itemView() string {
	record, ok := m.selectedItemRecord()
	if !ok {
		return "TermKeep — Login\n\nLogin not found.\n\n[v] vault  [q] quit\n"
	}
	if len(record.ConflictVersions) > 1 {
		return m.conflictView(record.ConflictVersions)
	}
	if record.Generic != nil {
		var b strings.Builder
		fmt.Fprintf(
			&b,
			"TermKeep — Generic — %s\n\n",
			record.Generic.Title,
		)
		fmt.Fprintf(&b, "Source: %s\n", record.Generic.Source)
		fmt.Fprintf(&b, "Source type: %s\n", record.Generic.SourceType)
		fmt.Fprintf(
			&b,
			"Folder: %s\nFavorite: %s\n",
			m.folderName(record.Generic.FolderID),
			yesNo(record.Generic.Favorite),
		)
		fmt.Fprintf(&b, "Preserved data:\n%s\n", record.Generic.Data)
		b.WriteString(
			"\n[f] favorite/unfavorite  [o] move  [d] delete  " +
				"[v] vault  [q] quit\n",
		)
		return b.String()
	}
	if record.SecureNote != nil {
		var b strings.Builder
		fmt.Fprintf(
			&b,
			"TermKeep — Secure Note — %s\n\n",
			record.SecureNote.Title,
		)
		fmt.Fprintf(&b, "Content:\n%s\n", record.SecureNote.Content)
		fmt.Fprintf(
			&b,
			"\nFolder: %s\nFavorite: %s\n",
			m.folderName(record.SecureNote.FolderID),
			yesNo(record.SecureNote.Favorite),
		)
		b.WriteString(m.clipboardFeedback())
		b.WriteString(
			"\n[c] copy content  [e] edit  " +
				"[f] favorite/unfavorite  [o] move  " +
				"[d] delete  [v] vault  [q] quit\n",
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
	if login.TOTP != nil {
		now := m.currentTime()
		code, err := client.GenerateTOTP(*login.TOTP, now)
		if err != nil {
			b.WriteString("TOTP: unavailable\n")
		} else {
			remaining := code.ExpiresAt.Unix() - now.Unix()
			if remaining < 0 {
				remaining = 0
			}
			fmt.Fprintf(
				&b,
				"TOTP: %s (expires in %ds)\n",
				code.Value,
				remaining,
			)
		}
	} else {
		b.WriteString("TOTP: not configured\n")
	}
	b.WriteString("URLs:\n")
	for _, value := range login.URLs {
		fmt.Fprintf(&b, "  - %s\n", value)
	}
	fmt.Fprintf(&b, "Notes: %s\n", login.Notes)
	fmt.Fprintf(
		&b,
		"Folder: %s\nFavorite: %s\n",
		m.folderName(login.FolderID),
		yesNo(login.Favorite),
	)
	b.WriteString("Custom fields:\n")
	for _, field := range login.CustomFields {
		fmt.Fprintf(&b, "  %s: %s\n", field.Name, field.Value)
	}
	b.WriteString(m.clipboardFeedback())
	b.WriteString(m.breachFeedback())
	b.WriteString(
		"\n[p] reveal/hide password  [c] copy password  " +
			"[b] check Pwned  [e] edit  " +
			"[h] password history  [t] configure TOTP  " +
			"[f] favorite/unfavorite  [o] move  [d] delete  " +
			"[v] vault  [q] quit\n",
	)
	return b.String()
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func recordTitle(record itemRecord) string {
	if record.Folder != nil {
		return record.Folder.Name
	}
	if record.SecureNote != nil {
		return record.SecureNote.Title
	}
	if record.Generic != nil {
		return record.Generic.Title
	}
	return record.Login.Name
}

func recordItemID(record itemRecord) string {
	if record.Folder != nil {
		return record.Folder.ItemID
	}
	if record.SecureNote != nil {
		return record.SecureNote.ItemID
	}
	if record.Generic != nil {
		return record.Generic.ItemID
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
		if version.Folder != nil {
			fmt.Fprintf(&b, "  Folder name: %s\n\n", version.Folder.Name)
			continue
		}
		if version.SecureNote != nil {
			fmt.Fprintf(
				&b, "  Title: %s\n", version.SecureNote.Title)
			fmt.Fprintf(
				&b, "  Content: %s\n\n",
				version.SecureNote.Content,
			)
			fmt.Fprintf(
				&b,
				"  Folder: %s\n  Favorite: %s\n\n",
				m.folderName(version.SecureNote.FolderID),
				yesNo(version.SecureNote.Favorite),
			)
			continue
		}
		if version.Generic != nil {
			fmt.Fprintf(&b, "  Title: %s\n", version.Generic.Title)
			fmt.Fprintf(&b, "  Source: %s\n", version.Generic.Source)
			fmt.Fprintf(
				&b,
				"  Source type: %s\n",
				version.Generic.SourceType,
			)
			fmt.Fprintf(
				&b,
				"  Folder: %s\n  Favorite: %s\n\n",
				m.folderName(version.Generic.FolderID),
				yesNo(version.Generic.Favorite),
			)
			continue
		}
		fmt.Fprintf(&b, "  Name: %s\n", version.Login.Name)
		fmt.Fprintf(&b, "  Username: %s\n", version.Login.Username)
		b.WriteString("  Password: ••••••••\n")
		fmt.Fprintf(&b, "  URLs: %s\n",
			strings.Join(version.Login.URLs, ", "))
		fmt.Fprintf(&b, "  Notes: %s\n", version.Login.Notes)
		fmt.Fprintf(
			&b,
			"  Folder: %s\n  Favorite: %s\n",
			m.folderName(version.Login.FolderID),
			yesNo(version.Login.Favorite),
		)
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
