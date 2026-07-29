package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxBitwardenExportSize = 16 << 20
const maxBitwardenImportRecords = 10_000

var ErrInvalidBitwardenExport = errors.New(
	"invalid Bitwarden export",
)
var ErrBitwardenExportTooLarge = errors.New(
	"Bitwarden export exceeds 16 MiB",
)
var ErrBitwardenExportTooManyRecords = errors.New(
	"Bitwarden export exceeds 10000 records",
)

type BitwardenImportCounts struct {
	Logins      int
	SecureNotes int
	Folders     int
	Generic     int
}

type BitwardenImportIssue struct {
	Item    int
	Field   string
	Message string
}

type BitwardenImportPreview struct {
	Items          []NativeItem
	Counts         BitwardenImportCounts
	UnmappedFields []BitwardenImportIssue
	Errors         []BitwardenImportIssue
}

type bitwardenExport struct {
	Encrypted bool              `json:"encrypted"`
	Folders   []bitwardenFolder `json:"folders"`
	Items     []json.RawMessage `json:"items"`
}

type bitwardenFolder struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type bitwardenItem struct {
	FolderID        string                     `json:"folderId"`
	Type            int                        `json:"type"`
	Name            string                     `json:"name"`
	Notes           string                     `json:"notes"`
	Favorite        bool                       `json:"favorite"`
	Reprompt        int                        `json:"reprompt"`
	Fields          []bitwardenField           `json:"fields"`
	Login           bitwardenLogin             `json:"login"`
	SecureNote      bitwardenSecureNote        `json:"secureNote"`
	PasswordHistory []bitwardenPasswordHistory `json:"passwordHistory"`
}

type bitwardenLogin struct {
	Username string              `json:"username"`
	Password string              `json:"password"`
	URIs     []bitwardenLoginURI `json:"uris"`
	TOTP     string              `json:"totp"`
	FIDO2    json.RawMessage     `json:"fido2Credentials"`
}

type bitwardenLoginURI struct {
	URI   string `json:"uri"`
	Match *int   `json:"match"`
}

type bitwardenSecureNote struct {
	Type int `json:"type"`
}

type bitwardenField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     int    `json:"type"`
	LinkedID *int   `json:"linkedId"`
}

type bitwardenPasswordHistory struct {
	LastUsedDate string `json:"lastUsedDate"`
	Password     string `json:"password"`
}

func PreviewBitwardenImport(
	reader io.Reader,
	existing []NativeItem,
) (BitwardenImportPreview, error) {
	if reader == nil {
		return BitwardenImportPreview{}, ErrInvalidBitwardenExport
	}
	input, err := io.ReadAll(io.LimitReader(
		reader,
		maxBitwardenExportSize+1,
	))
	if err != nil {
		return BitwardenImportPreview{},
			fmt.Errorf("%w: read input", ErrInvalidBitwardenExport)
	}
	defer clearBytes(input)
	if len(input) > maxBitwardenExportSize {
		return BitwardenImportPreview{}, ErrBitwardenExportTooLarge
	}

	var source bitwardenExport
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(&source); err != nil {
		return BitwardenImportPreview{},
			fmt.Errorf("%w: parse JSON", ErrInvalidBitwardenExport)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return BitwardenImportPreview{},
			fmt.Errorf("%w: trailing JSON", ErrInvalidBitwardenExport)
	}
	if source.Encrypted {
		return BitwardenImportPreview{},
			fmt.Errorf(
				"%w: encrypted exports are unsupported",
				ErrInvalidBitwardenExport,
			)
	}
	if len(source.Folders) > maxBitwardenImportRecords ||
		len(source.Items) >
			maxBitwardenImportRecords-len(source.Folders) {
		return BitwardenImportPreview{},
			ErrBitwardenExportTooManyRecords
	}

	preview := BitwardenImportPreview{}
	duplicateCounts := make(map[[sha256.Size]byte]int)
	for _, item := range existing {
		if key, ok := bitwardenSemanticKey(item); ok {
			duplicateCounts[key]++
		}
	}
	folderIDs := make(map[string]string, len(source.Folders))
	for index, folder := range source.Folders {
		folder.ID = strings.TrimSpace(folder.ID)
		folder.Name = strings.TrimSpace(folder.Name)
		if folder.ID == "" || folder.Name == "" {
			field := fmt.Sprintf("folders[%d].id", index)
			if folder.ID != "" {
				field = fmt.Sprintf("folders[%d].name", index)
			}
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Field:   field,
					Message: "Folder ID and name are required",
				},
			)
			continue
		}
		if _, exists := folderIDs[folder.ID]; exists {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Field: fmt.Sprintf(
						"folders[%d].id",
						index,
					),
					Message: "duplicate Bitwarden Folder ID",
				},
			)
			continue
		}
		itemID, err := NewItemID()
		if err != nil {
			return BitwardenImportPreview{}, err
		}
		folderIDs[folder.ID] = itemID
		normalized := FolderItem{
			ItemID: itemID,
			Name:   strings.TrimSpace(folder.Name),
		}
		preview.Items = append(preview.Items, NativeItem{
			Type:   NativeItemTypeFolder,
			Folder: &normalized,
		})
		preview.Counts.Folders++
	}
	for index, rawItem := range source.Items {
		var item bitwardenItem
		if err := json.Unmarshal(rawItem, &item); err != nil {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Item:    index + 1,
					Message: "invalid Bitwarden Item",
				},
			)
			continue
		}
		item.Name = strings.TrimSpace(item.Name)
		if item.Name == "" {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Item:    index + 1,
					Field:   "name",
					Message: "Item name is required",
				},
			)
			continue
		}
		folderID := ""
		if item.FolderID != "" {
			var found bool
			folderID, found = folderIDs[item.FolderID]
			if !found {
				preview.Errors = append(
					preview.Errors,
					BitwardenImportIssue{
						Item:    index + 1,
						Field:   "folderId",
						Message: "unknown Bitwarden Folder",
					},
				)
				continue
			}
		}
		if item.Type < 1 {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Item:    index + 1,
					Field:   "type",
					Message: "invalid Bitwarden Item type",
				},
			)
			continue
		}
		itemID, err := NewItemID()
		if err != nil {
			return BitwardenImportPreview{}, err
		}
		if item.Type == 2 {
			preview.UnmappedFields = append(
				preview.UnmappedFields,
				bitwardenUnmappedSecureNoteFields(index+1, item)...,
			)
			note := SecureNoteItem{
				ItemID:   itemID,
				Title:    item.Name,
				Content:  item.Notes,
				FolderID: folderID,
				Favorite: item.Favorite,
			}
			normalizedItem := NativeItem{
				Type:       NativeItemTypeSecureNote,
				SecureNote: &note,
			}
			nameBitwardenDuplicate(&normalizedItem, duplicateCounts)
			preview.Items = append(preview.Items, normalizedItem)
			preview.Counts.SecureNotes++
			continue
		}
		if item.Type != 1 {
			generic := GenericItem{
				ItemID:     itemID,
				Title:      item.Name,
				Source:     "bitwarden",
				SourceType: bitwardenSourceType(item.Type),
				FolderID:   folderID,
				Favorite:   item.Favorite,
				Data:       append([]byte(nil), rawItem...),
			}
			normalizedItem := NativeItem{
				Type:    NativeItemTypeGeneric,
				Generic: &generic,
			}
			nameBitwardenDuplicate(&normalizedItem, duplicateCounts)
			preview.Items = append(preview.Items, normalizedItem)
			preview.Counts.Generic++
			continue
		}
		preview.UnmappedFields = append(
			preview.UnmappedFields,
			bitwardenUnmappedLoginFields(index+1, item)...,
		)
		urls := make([]string, 0, len(item.Login.URIs))
		for _, uri := range item.Login.URIs {
			if value := strings.TrimSpace(uri.URI); value != "" {
				urls = append(urls, value)
			}
		}
		customFields := make([]CustomField, 0, len(item.Fields))
		for _, field := range item.Fields {
			if field.Type == 0 {
				customFields = append(customFields, CustomField{
					Name:  strings.TrimSpace(field.Name),
					Value: field.Value,
				})
			}
		}
		passwordHistory, invalidHistoryIndex, err :=
			bitwardenPasswordHistoryEntries(item.PasswordHistory)
		if err != nil {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Item: index + 1,
					Field: fmt.Sprintf(
						"passwordHistory[%d].lastUsedDate",
						invalidHistoryIndex,
					),
					Message: "invalid password history timestamp",
				},
			)
			continue
		}
		var totp *TOTPConfig
		if strings.TrimSpace(item.Login.TOTP) != "" {
			config, err := bitwardenTOTP(
				item.Login.TOTP,
				item.Login.Username,
			)
			if err != nil {
				preview.Errors = append(
					preview.Errors,
					BitwardenImportIssue{
						Item:    index + 1,
						Field:   "login.totp",
						Message: "invalid TOTP configuration",
					},
				)
				continue
			}
			totp = &config
		}
		login := LoginItem{
			ItemID:          itemID,
			Name:            item.Name,
			Username:        strings.TrimSpace(item.Login.Username),
			Password:        item.Login.Password,
			PasswordHistory: passwordHistory,
			FolderID:        folderID,
			Favorite:        item.Favorite,
			URLs:            urls,
			Notes:           item.Notes,
			CustomFields:    customFields,
			TOTP:            totp,
		}
		normalizedItem := NativeItem{
			Type:  NativeItemTypeLogin,
			Login: &login,
		}
		nameBitwardenDuplicate(&normalizedItem, duplicateCounts)
		preview.Items = append(preview.Items, normalizedItem)
		preview.Counts.Logins++
	}
	return preview, nil
}

func bitwardenUnmappedSecureNoteFields(
	itemNumber int,
	item bitwardenItem,
) []BitwardenImportIssue {
	var issues []BitwardenImportIssue
	add := func(field string) {
		issues = append(issues, BitwardenImportIssue{
			Item:    itemNumber,
			Field:   field,
			Message: "not mapped to native Secure Note",
		})
	}
	if item.Reprompt != 0 {
		add("reprompt")
	}
	for index := range item.Fields {
		add(fmt.Sprintf("fields[%d]", index))
	}
	if item.SecureNote.Type != 0 {
		add("secureNote.type")
	}
	if len(item.PasswordHistory) != 0 {
		add("passwordHistory")
	}
	return issues
}

func bitwardenPasswordHistoryEntries(
	source []bitwardenPasswordHistory,
) ([]PasswordHistoryEntry, int, error) {
	count := min(len(source), maxPasswordHistoryEntries)
	history := make([]PasswordHistoryEntry, 0, count)
	for index := 0; index < count; index++ {
		changedAt, err := time.Parse(
			time.RFC3339,
			strings.TrimSpace(source[index].LastUsedDate),
		)
		if err != nil {
			return nil, index, err
		}
		history = append(history, PasswordHistoryEntry{
			Password:  source[index].Password,
			ChangedAt: changedAt.UTC(),
		})
	}
	return history, 0, nil
}

func bitwardenTOTP(raw string, username string) (TOTPConfig, error) {
	raw = strings.TrimSpace(raw)
	if strings.HasPrefix(strings.ToLower(raw), "otpauth://") {
		return ParseTOTPURI(raw)
	}
	return NewTOTPConfig(raw, "", strings.TrimSpace(username), "", 0, 0)
}

func bitwardenSourceType(itemType int) string {
	switch itemType {
	case 3:
		return "card"
	case 4:
		return "identity"
	case 5:
		return "ssh_key"
	default:
		return fmt.Sprintf("type_%d", itemType)
	}
}

func bitwardenUnmappedLoginFields(
	itemNumber int,
	item bitwardenItem,
) []BitwardenImportIssue {
	var issues []BitwardenImportIssue
	add := func(field string) {
		issues = append(issues, BitwardenImportIssue{
			Item:    itemNumber,
			Field:   field,
			Message: "not mapped to native Login",
		})
	}
	if item.Reprompt != 0 {
		add("reprompt")
	}
	for index := maxPasswordHistoryEntries; index < len(item.PasswordHistory); index++ {
		add(fmt.Sprintf("passwordHistory[%d]", index))
	}
	for index, field := range item.Fields {
		if field.Type != 0 {
			add(fmt.Sprintf("fields[%d].type", index))
		}
		if field.LinkedID != nil {
			add(fmt.Sprintf("fields[%d].linkedId", index))
		}
	}
	for index, uri := range item.Login.URIs {
		if uri.Match != nil {
			add(fmt.Sprintf("login.uris[%d].match", index))
		}
	}
	if len(item.Login.FIDO2) > 0 &&
		string(item.Login.FIDO2) != "null" &&
		string(item.Login.FIDO2) != "[]" {
		add("login.fido2Credentials")
	}
	return issues
}

func nameBitwardenDuplicate(
	item *NativeItem,
	counts map[[sha256.Size]byte]int,
) {
	key, ok := bitwardenSemanticKey(*item)
	if !ok {
		return
	}
	duplicateNumber := counts[key]
	if duplicateNumber > 0 {
		suffix := " (Duplicada)"
		if duplicateNumber > 1 {
			suffix += fmt.Sprintf(" - %d", duplicateNumber)
		}
		switch item.Type {
		case NativeItemTypeLogin:
			item.Login.Name += suffix
		case NativeItemTypeSecureNote:
			item.SecureNote.Title += suffix
		case NativeItemTypeGeneric:
			item.Generic.Title += suffix
		}
	}
	counts[key]++
}

func bitwardenSemanticKey(
	item NativeItem,
) ([sha256.Size]byte, bool) {
	var semantic any
	switch item.Type {
	case NativeItemTypeLogin:
		if item.Login == nil {
			return [sha256.Size]byte{}, false
		}
		urls := make([]string, 0, len(item.Login.URLs))
		for _, value := range item.Login.URLs {
			urls = append(urls, normalizeBitwardenURL(value))
		}
		sort.Strings(urls)
		fields := append([]CustomField(nil), item.Login.CustomFields...)
		for index := range fields {
			fields[index].Name = strings.ToLower(
				strings.TrimSpace(fields[index].Name),
			)
			fields[index].Value = normalizeBitwardenText(
				fields[index].Value,
			)
		}
		sort.Slice(fields, func(left, right int) bool {
			if fields[left].Name == fields[right].Name {
				return fields[left].Value < fields[right].Value
			}
			return fields[left].Name < fields[right].Name
		})
		var totp *TOTPConfig
		if item.Login.TOTP != nil {
			normalized := *item.Login.TOTP
			normalized.Secret = strings.ToUpper(strings.Join(
				strings.Fields(normalized.Secret),
				"",
			))
			normalized.Issuer = strings.TrimSpace(normalized.Issuer)
			normalized.Account = strings.TrimSpace(normalized.Account)
			totp = &normalized
		}
		history := append(
			[]PasswordHistoryEntry(nil),
			item.Login.PasswordHistory...,
		)
		for index := range history {
			history[index].ChangedAt = history[index].ChangedAt.UTC()
		}
		semantic = struct {
			Type            NativeItemType
			Username        string
			Password        string
			PasswordHistory []PasswordHistoryEntry
			URLs            []string
			Notes           string
			CustomFields    []CustomField
			TOTP            *TOTPConfig
		}{
			Type: NativeItemTypeLogin,
			Username: strings.ToLower(strings.TrimSpace(
				item.Login.Username,
			)),
			Password:        item.Login.Password,
			PasswordHistory: history,
			URLs:            urls,
			Notes:           normalizeBitwardenText(item.Login.Notes),
			CustomFields:    fields,
			TOTP:            totp,
		}
	case NativeItemTypeSecureNote:
		if item.SecureNote == nil {
			return [sha256.Size]byte{}, false
		}
		semantic = struct {
			Type    NativeItemType
			Content string
		}{
			Type: NativeItemTypeSecureNote,
			Content: normalizeBitwardenText(
				item.SecureNote.Content,
			),
		}
	case NativeItemTypeGeneric:
		if item.Generic == nil {
			return [sha256.Size]byte{}, false
		}
		var data map[string]any
		if json.Unmarshal(item.Generic.Data, &data) != nil {
			return [sha256.Size]byte{}, false
		}
		delete(data, "id")
		delete(data, "name")
		delete(data, "folderId")
		delete(data, "favorite")
		semantic = struct {
			Type       NativeItemType
			Source     string
			SourceType string
			Data       map[string]any
		}{
			Type:       NativeItemTypeGeneric,
			Source:     item.Generic.Source,
			SourceType: item.Generic.SourceType,
			Data:       data,
		}
	default:
		return [sha256.Size]byte{}, false
	}
	encoded, err := json.Marshal(semantic)
	if err != nil {
		return [sha256.Size]byte{}, false
	}
	defer clearBytes(encoded)
	return sha256.Sum256(encoded), true
}

func normalizeBitwardenURL(value string) string {
	value = strings.TrimSpace(value)
	parsed, err := url.Parse(value)
	if err != nil {
		return value
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	parsed.Host = strings.ToLower(parsed.Host)
	if parsed.Path == "/" {
		parsed.Path = ""
	}
	return parsed.String()
}

func normalizeBitwardenText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.TrimSpace(value)
}
