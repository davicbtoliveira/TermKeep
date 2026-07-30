package client

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ReadableExportVersion is the version of the deliberately human-readable
// export formats. It is independent from the encrypted cache and backup
// versions.
const ReadableExportVersion = 1

const (
	maxReadableExportSize  = 64 << 20
	maxReadableExportItems = 10_000
	// JSONExportFormat identifies the TermKeep-readable JSON document.
	JSONExportFormat = "termkeep-json"
)

var ErrInvalidJSONExport = errors.New("invalid TermKeep JSON export")
var ErrJSONExportTooLarge = errors.New("JSON export exceeds 64 MiB")
var ErrJSONExportTooManyItems = errors.New("JSON export exceeds 10000 items")
var ErrInvalidCSVReadableExport = errors.New("invalid TermKeep CSV export")
var ErrReadableExportTooLarge = errors.New("readable export exceeds 64 MiB")
var ErrReadableExportTooManyItems = errors.New(
	"readable export exceeds 10000 items",
)

// JSONExport is the documented plaintext JSON representation. Generic.Data
// is emitted as JSON, rather than encoding/json's base64 representation of a
// []byte, so a reader can inspect and round-trip the original Generic Item.
type JSONExport struct {
	Version int              `json:"version"`
	Format  string           `json:"format"`
	Items   []JSONExportItem `json:"items"`
}

type JSONExportItem struct {
	Type       NativeItemType         `json:"type"`
	Login      *LoginItem             `json:"login,omitempty"`
	SecureNote *SecureNoteItem        `json:"secure_note,omitempty"`
	Folder     *FolderItem            `json:"folder,omitempty"`
	Generic    *JSONExportGenericItem `json:"generic,omitempty"`
}

type JSONExportGenericItem struct {
	ItemID     string          `json:"item_id"`
	Title      string          `json:"title"`
	Source     string          `json:"source"`
	SourceType string          `json:"source_type"`
	FolderID   string          `json:"folder_id,omitempty"`
	Favorite   bool            `json:"favorite,omitempty"`
	Data       json.RawMessage `json:"data"`
}

// CSVExportOptions controls the readable CSV projection. An empty ItemType
// writes all native types in one file with a type column. Selecting a type is
// useful for spreadsheet tools that cannot represent a heterogeneous vault.
type CSVExportOptions struct {
	ItemType  NativeItemType
	Delimiter rune
}

var readableCSVColumns = []string{
	"type",
	"item_id",
	"name",
	"title",
	"username",
	"password",
	"password_history",
	"urls",
	"notes",
	"custom_fields",
	"totp",
	"content",
	"folder_id",
	"favorite",
	"source",
	"source_type",
	"data",
}

// CSVExportColumns returns the stable header order used by EncodeCSVExport.
// The returned slice is independent and can be used to build an explicit
// import mapping without exposing internal storage.
func CSVExportColumns() []string {
	return append([]string(nil), readableCSVColumns...)
}

// EncodeJSONExport writes a deterministic, indented JSON document to writer.
// It never contacts the Server. Call WriteJSONExportFile for atomic file
// replacement and mode-0600 permissions.
func EncodeJSONExport(writer io.Writer, items []NativeItem) error {
	return EncodeJSONExportContext(context.Background(), writer, items)
}

// ExportJSON is a concise alias for callers that treat the operation as an
// export rather than an encoder.
func ExportJSON(writer io.Writer, items []NativeItem) error {
	return EncodeJSONExport(writer, items)
}

func EncodeJSONExportContext(
	ctx context.Context,
	writer io.Writer,
	items []NativeItem,
) error {
	if writer == nil {
		return ErrInvalidJSONExport
	}
	document, err := jsonExportDocument(ctx, items)
	if err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON export: %w", err)
	}
	encoded = append(encoded, '\n')
	defer clearBytes(encoded)
	if len(encoded) > maxReadableExportSize {
		return ErrReadableExportTooLarge
	}
	written, err := writer.Write(encoded)
	if err != nil {
		return fmt.Errorf("write JSON export: %w", err)
	}
	if written != len(encoded) {
		return fmt.Errorf("write JSON export: %w", io.ErrShortWrite)
	}
	return nil
}

// ParseJSONExport validates and decodes a JSON export produced by this
// package. It is intentionally separate from Bitwarden import: accepting a
// TermKeep export is explicit and does not infer a foreign schema.
func ParseJSONExport(reader io.Reader) ([]NativeItem, error) {
	if reader == nil {
		return nil, ErrInvalidJSONExport
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxReadableExportSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read input", ErrInvalidJSONExport)
	}
	defer clearBytes(input)
	if len(input) > maxReadableExportSize {
		return nil, ErrJSONExportTooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var document JSONExport
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("%w: parse document", ErrInvalidJSONExport)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing JSON", ErrInvalidJSONExport)
	}
	if document.Version != ReadableExportVersion ||
		document.Format != JSONExportFormat {
		return nil, ErrInvalidJSONExport
	}
	if len(document.Items) > maxReadableExportItems {
		return nil, ErrJSONExportTooManyItems
	}
	items := make([]NativeItem, 0, len(document.Items))
	seen := make(map[string]struct{}, len(document.Items))
	for _, exported := range document.Items {
		item, err := nativeItemFromJSONExport(exported)
		if err != nil {
			return nil, err
		}
		if itemID := exportNativeItemID(item); itemID != "" {
			if _, exists := seen[itemID]; exists {
				return nil, fmt.Errorf("%w: duplicate Item ID", ErrInvalidJSONExport)
			}
			seen[itemID] = struct{}{}
		}
		items = append(items, item)
	}
	return items, nil
}

// ReadJSONExportFile is the file-oriented counterpart to ParseJSONExport.
func ReadJSONExportFile(path string) ([]NativeItem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open JSON export: %w", err)
	}
	defer file.Close()
	return ParseJSONExport(file)
}

// PreviewJSONImport parses a TermKeep JSON export and applies the same
// duplicate naming and count reporting used by the other local import paths.
func PreviewJSONImport(
	reader io.Reader,
	existing []NativeItem,
) (ImportPreview, error) {
	items, err := ParseJSONExport(reader)
	if err != nil {
		return ImportPreview{}, err
	}
	preview := ImportPreview{}
	duplicateCounts := importDuplicateCounts(existing)
	remapped, err := freshImportIDs(items)
	if err != nil {
		return ImportPreview{}, err
	}
	for index, item := range remapped {
		nameImportDuplicate(&item, duplicateCounts)
		preview.Items = append(preview.Items, item)
		switch item.Type {
		case NativeItemTypeLogin:
			preview.Counts.Logins++
		case NativeItemTypeSecureNote:
			preview.Counts.SecureNotes++
		case NativeItemTypeFolder:
			preview.Counts.Folders++
		case NativeItemTypeGeneric:
			preview.Counts.Generic++
		default:
			preview.Errors = append(preview.Errors, ImportIssue{
				Item:    index + 1,
				Field:   "type",
				Message: "unsupported Item type",
			})
		}
	}
	return preview, nil
}

func freshImportIDs(items []NativeItem) ([]NativeItem, error) {
	ids := make(map[string]string, len(items))
	for _, item := range items {
		if item.Type != NativeItemTypeFolder {
			continue
		}
		oldID := exportNativeItemID(item)
		newID, err := NewItemID()
		if err != nil {
			return nil, err
		}
		ids[oldID] = newID
	}
	remapped := make([]NativeItem, 0, len(items))
	for _, item := range items {
		newID, err := NewItemID()
		if err != nil {
			return nil, err
		}
		clone := item
		switch clone.Type {
		case NativeItemTypeLogin:
			value := *clone.Login
			value.ItemID = newID
			if folderID, ok := ids[value.FolderID]; ok {
				value.FolderID = folderID
			} else if value.FolderID != "" {
				value.FolderID = ""
			}
			clone.Login = &value
		case NativeItemTypeSecureNote:
			value := *clone.SecureNote
			value.ItemID = newID
			if folderID, ok := ids[value.FolderID]; ok {
				value.FolderID = folderID
			} else if value.FolderID != "" {
				value.FolderID = ""
			}
			clone.SecureNote = &value
		case NativeItemTypeFolder:
			value := *clone.Folder
			if mapped, ok := ids[value.ItemID]; ok {
				value.ItemID = mapped
			} else {
				value.ItemID = newID
			}
			clone.Folder = &value
		case NativeItemTypeGeneric:
			value := *clone.Generic
			value.ItemID = newID
			if folderID, ok := ids[value.FolderID]; ok {
				value.FolderID = folderID
			} else if value.FolderID != "" {
				value.FolderID = ""
			}
			clone.Generic = &value
		}
		remapped = append(remapped, clone)
	}
	return remapped, nil
}

// EncodeCSVExport writes a UTF-8 CSV projection. Complex fields are encoded
// as JSON strings in their own columns; this limitation is documented by the
// CLI and keeps Generic Item data lossless instead of silently flattening it.
func EncodeCSVExport(
	writer io.Writer,
	items []NativeItem,
	options CSVExportOptions,
) error {
	return EncodeCSVExportContext(
		context.Background(), writer, items, options)
}

// ExportCSV is a concise alias for callers that treat the operation as an
// export rather than an encoder.
func ExportCSV(
	writer io.Writer,
	items []NativeItem,
	options CSVExportOptions,
) error {
	return EncodeCSVExport(writer, items, options)
}

func EncodeCSVExportContext(
	ctx context.Context,
	writer io.Writer,
	items []NativeItem,
	options CSVExportOptions,
) error {
	if writer == nil {
		return ErrInvalidCSVReadableExport
	}
	delimiter := options.Delimiter
	if delimiter == 0 {
		delimiter = ','
	}
	if !validCSVDelimiter(delimiter) {
		return fmt.Errorf("%w: unsupported delimiter", ErrInvalidCSVReadableExport)
	}
	if options.ItemType != "" && !validNativeItemType(options.ItemType) {
		return fmt.Errorf("%w: unsupported Item type", ErrInvalidCSVReadableExport)
	}
	selected := make([]NativeItem, 0, len(items))
	for _, item := range items {
		if err := contextErr(ctx); err != nil {
			return err
		}
		if err := validateNativeItem(item); err != nil {
			return fmt.Errorf("%w: invalid Item", ErrInvalidCSVReadableExport)
		}
		if options.ItemType == "" || item.Type == options.ItemType {
			selected = append(selected, item)
		}
	}
	if len(selected) > maxReadableExportItems {
		return ErrReadableExportTooManyItems
	}
	limited := &readableExportWriter{writer: writer}
	parser := csv.NewWriter(limited)
	parser.Comma = delimiter
	if err := parser.Write(readableCSVColumns); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}
	for _, item := range selected {
		if err := contextErr(ctx); err != nil {
			return err
		}
		row, err := csvExportRow(item)
		if err != nil {
			return err
		}
		if err := parser.Write(row); err != nil {
			return fmt.Errorf("write CSV export: %w", err)
		}
	}
	parser.Flush()
	if err := parser.Error(); err != nil {
		return fmt.Errorf("write CSV export: %w", err)
	}
	return nil
}

type readableExportWriter struct {
	writer io.Writer
	count  int
}

func (w *readableExportWriter) Write(value []byte) (int, error) {
	if len(value) > maxReadableExportSize-w.count {
		return 0, ErrReadableExportTooLarge
	}
	written, err := w.writer.Write(value)
	w.count += written
	return written, err
}

// ParseCSVExport parses the lossless CSV projection emitted by
// EncodeCSVExport. Generic data and other non-tabular values remain JSON
// strings and are restored without flattening.
func ParseCSVExport(reader io.Reader) ([]NativeItem, error) {
	if reader == nil {
		return nil, ErrInvalidCSVReadableExport
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxReadableExportSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read input", ErrInvalidCSVReadableExport)
	}
	defer clearBytes(input)
	if len(input) > maxReadableExportSize {
		return nil, ErrReadableExportTooLarge
	}
	delimiter, err := csvImportDelimiter(input, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCSVReadableExport, err)
	}
	parser := newCSVReader(input, delimiter)
	header, err := parser.Read()
	if err != nil || !sameCSVHeader(header) {
		return nil, fmt.Errorf("%w: unexpected header", ErrInvalidCSVReadableExport)
	}
	items := make([]NativeItem, 0)
	seen := make(map[string]struct{})
	for index := 1; ; index++ {
		row, readErr := parser.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("%w: row %d", ErrInvalidCSVReadableExport, index)
		}
		if len(items) >= maxReadableExportItems {
			return nil, ErrReadableExportTooManyItems
		}
		item, itemErr := csvExportItem(row)
		if itemErr != nil {
			return nil, fmt.Errorf("%w: row %d", ErrInvalidCSVReadableExport, index)
		}
		itemID := exportNativeItemID(item)
		if _, exists := seen[itemID]; exists {
			return nil, fmt.Errorf("%w: duplicate Item ID", ErrInvalidCSVReadableExport)
		}
		seen[itemID] = struct{}{}
		items = append(items, item)
	}
	return items, nil
}

// ReadCSVExportFile is the file-oriented counterpart to ParseCSVExport.
func ReadCSVExportFile(path string) ([]NativeItem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open CSV export: %w", err)
	}
	defer file.Close()
	return ParseCSVExport(file)
}

func PreviewCSVExport(
	reader io.Reader,
	existing []NativeItem,
) (ImportPreview, error) {
	items, err := ParseCSVExport(reader)
	if err != nil {
		return ImportPreview{}, err
	}
	preview := ImportPreview{}
	duplicateCounts := importDuplicateCounts(existing)
	remapped, err := freshImportIDs(items)
	if err != nil {
		return ImportPreview{}, err
	}
	for _, item := range remapped {
		nameImportDuplicate(&item, duplicateCounts)
		preview.Items = append(preview.Items, item)
		switch item.Type {
		case NativeItemTypeLogin:
			preview.Counts.Logins++
		case NativeItemTypeSecureNote:
			preview.Counts.SecureNotes++
		case NativeItemTypeFolder:
			preview.Counts.Folders++
		case NativeItemTypeGeneric:
			preview.Counts.Generic++
		}
	}
	return preview, nil
}

// WriteJSONExportFile writes a plaintext JSON export atomically with mode
// 0600. A failed encode, cancellation, or rename leaves the previous final
// file untouched.
func WriteJSONExportFile(path string, items []NativeItem) error {
	return WriteJSONExportFileContext(context.Background(), path, items)
}

func ExportJSONFile(path string, items []NativeItem) error {
	return WriteJSONExportFile(path, items)
}

func WriteJSONExportFileContext(
	ctx context.Context,
	path string,
	items []NativeItem,
) error {
	if strings.TrimSpace(path) == "" {
		return ErrInvalidJSONExport
	}
	return writeReadableExportFile(ctx, path, func(writer io.Writer) error {
		return EncodeJSONExportContext(ctx, writer, items)
	})
}

func WriteCSVExportFile(
	path string,
	items []NativeItem,
	options CSVExportOptions,
) error {
	return WriteCSVExportFileContext(
		context.Background(), path, items, options)
}

func ExportCSVFile(
	path string,
	items []NativeItem,
	options CSVExportOptions,
) error {
	return WriteCSVExportFile(path, items, options)
}

func WriteCSVExportFileContext(
	ctx context.Context,
	path string,
	items []NativeItem,
	options CSVExportOptions,
) error {
	if strings.TrimSpace(path) == "" {
		return ErrInvalidCSVReadableExport
	}
	return writeReadableExportFile(ctx, path, func(writer io.Writer) error {
		return EncodeCSVExportContext(ctx, writer, items, options)
	})
}

func writeReadableExportFile(
	ctx context.Context,
	path string,
	encode func(io.Writer) error,
) error {
	if strings.TrimSpace(path) == "" {
		return ErrInvalidJSONExport
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".termkeep-export-*")
	if err != nil {
		return fmt.Errorf("create export: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("restrict export: %w", err)
	}
	if err := encode(file); err != nil {
		_ = file.Close()
		return err
	}
	if err := contextErr(ctx); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("flush export: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close export: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace export: %w", err)
	}
	directoryFile, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open export directory: %w", err)
	}
	defer directoryFile.Close()
	if err := directoryFile.Sync(); err != nil {
		return fmt.Errorf("flush export directory: %w", err)
	}
	return nil
}

func jsonExportDocument(
	ctx context.Context,
	items []NativeItem,
) (JSONExport, error) {
	if len(items) > maxReadableExportItems {
		return JSONExport{}, ErrJSONExportTooManyItems
	}
	document := JSONExport{
		Version: ReadableExportVersion,
		Format:  JSONExportFormat,
		Items:   make([]JSONExportItem, 0, len(items)),
	}
	for _, item := range items {
		if err := contextErr(ctx); err != nil {
			return JSONExport{}, err
		}
		if err := validateNativeItem(item); err != nil {
			return JSONExport{}, fmt.Errorf("%w: invalid Item", ErrInvalidJSONExport)
		}
		exported, err := jsonExportItem(item)
		if err != nil {
			return JSONExport{}, err
		}
		document.Items = append(document.Items, exported)
	}
	return document, nil
}

func jsonExportItem(item NativeItem) (JSONExportItem, error) {
	exported := JSONExportItem{Type: item.Type}
	switch item.Type {
	case NativeItemTypeLogin:
		login := *item.Login
		login.URLs = append([]string(nil), login.URLs...)
		login.CustomFields = append([]CustomField(nil), login.CustomFields...)
		login.PasswordHistory = append(
			[]PasswordHistoryEntry(nil), login.PasswordHistory...)
		exported.Login = &login
	case NativeItemTypeSecureNote:
		note := *item.SecureNote
		exported.SecureNote = &note
	case NativeItemTypeFolder:
		folder := *item.Folder
		exported.Folder = &folder
	case NativeItemTypeGeneric:
		generic := *item.Generic
		exported.Generic = &JSONExportGenericItem{
			ItemID:     generic.ItemID,
			Title:      generic.Title,
			Source:     generic.Source,
			SourceType: generic.SourceType,
			FolderID:   generic.FolderID,
			Favorite:   generic.Favorite,
			Data:       append(json.RawMessage(nil), generic.Data...),
		}
	default:
		return JSONExportItem{}, ErrInvalidJSONExport
	}
	return exported, nil
}

func nativeItemFromJSONExport(exported JSONExportItem) (NativeItem, error) {
	item := NativeItem{Type: exported.Type}
	switch exported.Type {
	case NativeItemTypeLogin:
		item.Login = exported.Login
	case NativeItemTypeSecureNote:
		item.SecureNote = exported.SecureNote
	case NativeItemTypeFolder:
		item.Folder = exported.Folder
	case NativeItemTypeGeneric:
		if exported.Generic != nil {
			item.Generic = &GenericItem{
				ItemID:     exported.Generic.ItemID,
				Title:      exported.Generic.Title,
				Source:     exported.Generic.Source,
				SourceType: exported.Generic.SourceType,
				FolderID:   exported.Generic.FolderID,
				Favorite:   exported.Generic.Favorite,
				Data:       append([]byte(nil), exported.Generic.Data...),
			}
		}
	default:
		return NativeItem{}, fmt.Errorf("%w: unsupported Item type", ErrInvalidJSONExport)
	}
	if err := validateNativeItem(item); err != nil {
		return NativeItem{}, fmt.Errorf("%w: invalid Item", ErrInvalidJSONExport)
	}
	return item, nil
}

func csvExportRow(item NativeItem) ([]string, error) {
	row := make([]string, len(readableCSVColumns))
	row[0] = string(item.Type)
	switch item.Type {
	case NativeItemTypeLogin:
		login := item.Login
		row[1] = login.ItemID
		row[2] = login.Name
		row[4] = login.Username
		row[5] = login.Password
		row[6], _ = jsonString(login.PasswordHistory)
		row[7], _ = jsonString(login.URLs)
		row[8] = login.Notes
		row[9], _ = jsonString(login.CustomFields)
		if login.TOTP != nil {
			row[10], _ = jsonString(login.TOTP)
		}
		row[12] = login.FolderID
		row[13] = strconv.FormatBool(login.Favorite)
	case NativeItemTypeSecureNote:
		note := item.SecureNote
		row[1] = note.ItemID
		row[3] = note.Title
		row[11] = note.Content
		row[12] = note.FolderID
		row[13] = strconv.FormatBool(note.Favorite)
	case NativeItemTypeFolder:
		folder := item.Folder
		row[1] = folder.ItemID
		row[2] = folder.Name
	case NativeItemTypeGeneric:
		generic := item.Generic
		row[1] = generic.ItemID
		row[3] = generic.Title
		row[12] = generic.FolderID
		row[13] = strconv.FormatBool(generic.Favorite)
		row[14] = generic.Source
		row[15] = generic.SourceType
		row[16] = string(generic.Data)
	default:
		return nil, ErrInvalidCSVReadableExport
	}
	return row, nil
}

func csvExportItem(row []string) (NativeItem, error) {
	if len(row) != len(readableCSVColumns) || row[1] == "" {
		return NativeItem{}, ErrInvalidCSVReadableExport
	}
	favorite := false
	if row[13] != "" {
		parsed, err := strconv.ParseBool(row[13])
		if err != nil {
			return NativeItem{}, ErrInvalidCSVReadableExport
		}
		favorite = parsed
	}
	itemID := row[1]
	switch NativeItemType(row[0]) {
	case NativeItemTypeLogin:
		var history []PasswordHistoryEntry
		if err := parseJSONCell(row[6], &history); err != nil {
			return NativeItem{}, err
		}
		var urls []string
		if err := parseJSONCell(row[7], &urls); err != nil {
			return NativeItem{}, err
		}
		var fields []CustomField
		if err := parseJSONCell(row[9], &fields); err != nil {
			return NativeItem{}, err
		}
		var totp *TOTPConfig
		if strings.TrimSpace(row[10]) != "" {
			var parsed TOTPConfig
			if err := parseJSONCell(row[10], &parsed); err != nil ||
				ValidateTOTPConfig(parsed) != nil {
				return NativeItem{}, ErrInvalidCSVReadableExport
			}
			totp = &parsed
		}
		item := NativeItem{Type: NativeItemTypeLogin, Login: &LoginItem{
			ItemID: itemID, Name: row[2], Username: row[4], Password: row[5],
			PasswordHistory: history, URLs: urls, Notes: row[8],
			CustomFields: fields, TOTP: totp, FolderID: row[12],
			Favorite: favorite,
		}}
		return validCSVNativeItem(item)
	case NativeItemTypeSecureNote:
		return validCSVNativeItem(NativeItem{
			Type: NativeItemTypeSecureNote,
			SecureNote: &SecureNoteItem{
				ItemID: itemID, Title: row[3], Content: row[11],
				FolderID: row[12], Favorite: favorite,
			},
		})
	case NativeItemTypeFolder:
		return validCSVNativeItem(NativeItem{
			Type:   NativeItemTypeFolder,
			Folder: &FolderItem{ItemID: itemID, Name: row[2]},
		})
	case NativeItemTypeGeneric:
		if !json.Valid([]byte(row[16])) {
			return NativeItem{}, ErrInvalidCSVReadableExport
		}
		return validCSVNativeItem(NativeItem{
			Type: NativeItemTypeGeneric,
			Generic: &GenericItem{
				ItemID: itemID, Title: row[3], Source: row[14],
				SourceType: row[15], FolderID: row[12],
				Favorite: favorite, Data: []byte(row[16]),
			},
		})
	default:
		return NativeItem{}, ErrInvalidCSVReadableExport
	}
}

func validCSVNativeItem(item NativeItem) (NativeItem, error) {
	if err := validateNativeItem(item); err != nil {
		return NativeItem{}, ErrInvalidCSVReadableExport
	}
	return item, nil
}

func sameCSVHeader(header []string) bool {
	if len(header) != len(readableCSVColumns) {
		return false
	}
	for index := range header {
		if strings.TrimSpace(header[index]) != readableCSVColumns[index] {
			return false
		}
	}
	return true
}

func jsonString(value any) (string, error) {
	if value == nil {
		return "", nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func parseJSONCell(raw string, output any) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), output); err != nil {
		return ErrInvalidCSVReadableExport
	}
	return nil
}

func exportNativeItemID(item NativeItem) string {
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login != nil {
			return item.Login.ItemID
		}
	case NativeItemTypeSecureNote:
		if item.SecureNote != nil {
			return item.SecureNote.ItemID
		}
	case NativeItemTypeFolder:
		if item.Folder != nil {
			return item.Folder.ItemID
		}
	case NativeItemTypeGeneric:
		if item.Generic != nil {
			return item.Generic.ItemID
		}
	}
	return ""
}

func validateNativeItem(item NativeItem) error {
	if !validNativeItemType(item.Type) || exportNativeItemID(item) == "" {
		return ErrInvalidItemEnvelope
	}
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login == nil || item.SecureNote != nil ||
			item.Folder != nil || item.Generic != nil {
			return ErrInvalidItemEnvelope
		}
		if item.Login.Name == "" ||
			(item.Login.TOTP != nil && ValidateTOTPConfig(*item.Login.TOTP) != nil) {
			return ErrInvalidItemEnvelope
		}
	case NativeItemTypeSecureNote:
		if item.SecureNote == nil || item.Login != nil ||
			item.Folder != nil || item.Generic != nil {
			return ErrInvalidItemEnvelope
		}
		if item.SecureNote.Title == "" {
			return ErrInvalidItemEnvelope
		}
	case NativeItemTypeFolder:
		if item.Folder == nil || item.Login != nil ||
			item.SecureNote != nil || item.Generic != nil ||
			item.Folder.Name == "" {
			return ErrInvalidItemEnvelope
		}
	case NativeItemTypeGeneric:
		if item.Generic == nil || item.Login != nil ||
			item.SecureNote != nil || item.Folder != nil ||
			item.Generic.Title == "" ||
			item.Generic.Source == "" || item.Generic.SourceType == "" ||
			!json.Valid(item.Generic.Data) {
			return ErrInvalidItemEnvelope
		}
	}
	return nil
}

func validNativeItemType(itemType NativeItemType) bool {
	switch itemType {
	case NativeItemTypeLogin, NativeItemTypeSecureNote,
		NativeItemTypeFolder, NativeItemTypeGeneric:
		return true
	default:
		return false
	}
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
