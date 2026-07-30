package client

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const maxOnePasswordExportAttributesSize = 64 << 10
const maxOnePasswordExportDataSize = 16 << 20
const maxOnePasswordImportRecords = 10_000

var ErrInvalidOnePasswordExport = errors.New(
	"invalid 1Password export",
)
var ErrOnePasswordExportTooLarge = errors.New(
	"1Password export data exceeds 16 MiB",
)
var ErrOnePasswordExportTooManyRecords = errors.New(
	"1Password export exceeds 10000 records",
)

type onePasswordExportAttributes struct {
	Version     int    `json:"version"`
	Description string `json:"description"`
}

type onePasswordExport struct {
	Accounts []onePasswordAccount `json:"accounts"`
}

type onePasswordAccount struct {
	Vaults []onePasswordVault `json:"vaults"`
}

type onePasswordVault struct {
	Attrs onePasswordVaultAttributes `json:"attrs"`
	Items []json.RawMessage          `json:"items"`
}

type onePasswordVaultAttributes struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type onePasswordItem struct {
	UUID         string                  `json:"uuid"`
	Favorite     int                     `json:"favIndex"`
	State        string                  `json:"state"`
	CategoryUUID string                  `json:"categoryUuid"`
	Overview     onePasswordItemOverview `json:"overview"`
	Details      onePasswordItemDetails  `json:"details"`
	File         json.RawMessage         `json:"file"`
}

type onePasswordItemOverview struct {
	Title string               `json:"title"`
	URL   string               `json:"url"`
	URLs  []onePasswordItemURL `json:"urls"`
	Tags  []string             `json:"tags"`
}

type onePasswordItemURL struct {
	URL string `json:"url"`
}

type onePasswordItemDetails struct {
	LoginFields        []onePasswordLoginField      `json:"loginFields"`
	Notes              string                       `json:"notesPlain"`
	Sections           []onePasswordSection         `json:"sections"`
	PasswordHistory    []onePasswordPasswordHistory `json:"passwordHistory"`
	DocumentAttributes json.RawMessage              `json:"documentAttributes"`
}

type onePasswordLoginField struct {
	Name        string `json:"name"`
	Value       string `json:"value"`
	Designation string `json:"designation"`
}

type onePasswordSection struct {
	Fields []onePasswordSectionField `json:"fields"`
}

type onePasswordSectionField struct {
	Title string          `json:"title"`
	Value json.RawMessage `json:"value"`
}

type onePasswordPasswordHistory struct {
	Value string `json:"value"`
	Time  int64  `json:"time"`
}

type onePasswordImportState struct {
	preview         ImportPreview
	duplicateCounts map[[sha256.Size]byte]int
	vaultIDs        map[string]struct{}
}

func (state *onePasswordImportState) add(item NativeItem) {
	nameImportDuplicate(&item, state.duplicateCounts)
	state.preview.Items = append(state.preview.Items, item)
	switch item.Type {
	case NativeItemTypeLogin:
		state.preview.Counts.Logins++
	case NativeItemTypeSecureNote:
		state.preview.Counts.SecureNotes++
	case NativeItemTypeFolder:
		state.preview.Counts.Folders++
	case NativeItemTypeGeneric:
		state.preview.Counts.Generic++
	}
}

func (state *onePasswordImportState) addGeneric(
	rawItem json.RawMessage,
	item onePasswordItem,
	folderID string,
) error {
	generic, err := onePasswordGenericItem(rawItem, item, folderID)
	if err != nil {
		return err
	}
	state.add(generic)
	return nil
}

func (state *onePasswordImportState) addError(
	item int,
	field string,
	message string,
) {
	state.preview.Errors = append(state.preview.Errors, ImportIssue{
		Item:    item,
		Field:   field,
		Message: message,
	})
}

func (state *onePasswordImportState) parseItem(
	rawItem json.RawMessage,
	itemNumber int,
) (onePasswordItem, bool) {
	var item onePasswordItem
	if json.Unmarshal(rawItem, &item) != nil {
		state.addError(itemNumber, "", "invalid 1Password Item")
		return onePasswordItem{}, false
	}
	item.UUID = strings.TrimSpace(item.UUID)
	item.CategoryUUID = strings.TrimSpace(item.CategoryUUID)
	item.Overview.Title = strings.TrimSpace(item.Overview.Title)
	switch {
	case item.UUID == "":
		state.addError(itemNumber, "uuid", "Item UUID is required")
	case item.Overview.Title == "":
		state.addError(
			itemNumber,
			"overview.title",
			"Item title is required",
		)
	case item.CategoryUUID == "":
		state.addError(
			itemNumber,
			"categoryUuid",
			"Item category is required",
		)
	default:
		return item, true
	}
	return onePasswordItem{}, false
}

func (state *onePasswordImportState) addVault(
	attributes onePasswordVaultAttributes,
	vaultIndex int,
) (string, bool, error) {
	attributes.UUID = strings.TrimSpace(attributes.UUID)
	attributes.Name = strings.TrimSpace(attributes.Name)
	if attributes.UUID == "" || attributes.Name == "" {
		field := fmt.Sprintf("vaults[%d].attrs.uuid", vaultIndex)
		if attributes.UUID != "" {
			field = fmt.Sprintf("vaults[%d].attrs.name", vaultIndex)
		}
		state.addError(0, field, "Vault UUID and name are required")
		return "", false, nil
	}
	if _, exists := state.vaultIDs[attributes.UUID]; exists {
		state.addError(
			0,
			fmt.Sprintf("vaults[%d].attrs.uuid", vaultIndex),
			"duplicate 1Password Vault UUID",
		)
		return "", false, nil
	}
	state.vaultIDs[attributes.UUID] = struct{}{}
	folderID, err := NewItemID()
	if err != nil {
		return "", false, err
	}
	folder := FolderItem{ItemID: folderID, Name: attributes.Name}
	state.add(NativeItem{
		Type:   NativeItemTypeFolder,
		Folder: &folder,
	})
	return folderID, true, nil
}

func PreviewOnePasswordImport(
	reader io.ReaderAt,
	size int64,
	existing []NativeItem,
) (ImportPreview, error) {
	archive, source, err := readOnePasswordArchive(reader, size)
	if err != nil {
		return ImportPreview{}, err
	}
	return normalizeOnePasswordExport(archive, source, existing)
}

func normalizeOnePasswordExport(
	archive *zip.Reader,
	source onePasswordExport,
	existing []NativeItem,
) (ImportPreview, error) {
	state := onePasswordImportState{
		duplicateCounts: importDuplicateCounts(existing),
		vaultIDs:        make(map[string]struct{}),
	}
	preview := &state.preview
	for _, file := range archive.File {
		if strings.HasPrefix(file.Name, "files/") &&
			!strings.HasSuffix(file.Name, "/") {
			preview.UnmappedFields = append(
				preview.UnmappedFields,
				ImportIssue{
					Field:   file.Name,
					Message: "attachment binary is not imported",
				},
			)
		}
	}
	for _, account := range source.Accounts {
		for vaultIndex, vault := range account.Vaults {
			folderID, valid, err := state.addVault(
				vault.Attrs,
				vaultIndex,
			)
			if err != nil {
				return ImportPreview{}, err
			}
			if !valid {
				continue
			}

			for itemIndex, rawItem := range vault.Items {
				item, valid := state.parseItem(
					rawItem,
					itemIndex+1,
				)
				if !valid {
					continue
				}
				if onePasswordJSONValuePresent(
					item.Details.DocumentAttributes,
				) || onePasswordJSONValuePresent(item.File) ||
					len(item.Overview.Tags) != 0 {
					if err := state.addGeneric(
						rawItem,
						item,
						folderID,
					); err != nil {
						return ImportPreview{}, err
					}
					continue
				}
				if item.CategoryUUID == "003" {
					if len(item.Details.Sections) != 0 {
						if err := state.addGeneric(
							rawItem,
							item,
							folderID,
						); err != nil {
							return ImportPreview{}, err
						}
						continue
					}
					itemID, err := NewItemID()
					if err != nil {
						return ImportPreview{}, err
					}
					note := SecureNoteItem{
						ItemID: itemID,
						Title: strings.TrimSpace(
							item.Overview.Title,
						),
						Content:  item.Details.Notes,
						FolderID: folderID,
						Favorite: item.Favorite > 0,
					}
					normalizedItem := NativeItem{
						Type:       NativeItemTypeSecureNote,
						SecureNote: &note,
					}
					state.add(normalizedItem)
					continue
				}
				if item.CategoryUUID != "001" {
					if err := state.addGeneric(
						rawItem,
						item,
						folderID,
					); err != nil {
						return ImportPreview{}, err
					}
					continue
				}
				customFields, totp, unmapped, fieldIssue :=
					onePasswordLoginFields(item, itemIndex+1)
				if fieldIssue != nil {
					state.addError(
						fieldIssue.Item,
						fieldIssue.Field,
						fieldIssue.Message,
					)
					continue
				}
				if unmapped {
					if err := state.addGeneric(
						rawItem,
						item,
						folderID,
					); err != nil {
						return ImportPreview{}, err
					}
					continue
				}
				itemID, err := NewItemID()
				if err != nil {
					return ImportPreview{}, err
				}
				username, password := onePasswordLoginCredentials(item)
				login := LoginItem{
					ItemID:          itemID,
					Name:            strings.TrimSpace(item.Overview.Title),
					Username:        username,
					Password:        password,
					PasswordHistory: normalizeOnePasswordPasswordHistory(item),
					FolderID:        folderID,
					Favorite:        item.Favorite > 0,
					URLs:            onePasswordURLs(item),
					Notes:           item.Details.Notes,
					CustomFields:    customFields,
					TOTP:            totp,
				}
				normalizedItem := NativeItem{
					Type:  NativeItemTypeLogin,
					Login: &login,
				}
				state.add(normalizedItem)
			}
		}
	}
	return *preview, nil
}

func readOnePasswordArchive(
	reader io.ReaderAt,
	size int64,
) (*zip.Reader, onePasswordExport, error) {
	if reader == nil || size <= 0 {
		return nil, onePasswordExport{}, ErrInvalidOnePasswordExport
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, onePasswordExport{},
			fmt.Errorf("%w: open archive", ErrInvalidOnePasswordExport)
	}
	attributesFile := onePasswordArchiveFile(
		archive,
		"export.attributes",
	)
	dataFile := onePasswordArchiveFile(archive, "export.data")
	if attributesFile == nil || dataFile == nil {
		return nil, onePasswordExport{},
			fmt.Errorf("%w: missing export files", ErrInvalidOnePasswordExport)
	}

	var attributes onePasswordExportAttributes
	if err := decodeOnePasswordJSON(
		attributesFile,
		maxOnePasswordExportAttributesSize,
		ErrInvalidOnePasswordExport,
		&attributes,
	); err != nil {
		return nil, onePasswordExport{}, err
	}
	if attributes.Version != 3 ||
		attributes.Description != "1Password Unencrypted Export" {
		return nil, onePasswordExport{},
			fmt.Errorf("%w: unsupported format", ErrInvalidOnePasswordExport)
	}

	var source onePasswordExport
	if err := decodeOnePasswordJSON(
		dataFile,
		maxOnePasswordExportDataSize,
		ErrOnePasswordExportTooLarge,
		&source,
	); err != nil {
		return nil, onePasswordExport{}, err
	}
	recordCount := 0
	for _, account := range source.Accounts {
		for _, vault := range account.Vaults {
			if recordCount >= maxOnePasswordImportRecords ||
				len(vault.Items) >
					maxOnePasswordImportRecords-recordCount-1 {
				return nil, onePasswordExport{},
					ErrOnePasswordExportTooManyRecords
			}
			recordCount += 1 + len(vault.Items)
		}
	}
	return archive, source, nil
}

func onePasswordJSONValuePresent(raw json.RawMessage) bool {
	value := strings.TrimSpace(string(raw))
	return value != "" &&
		value != "null" &&
		value != "{}" &&
		value != "[]"
}

func onePasswordLoginCredentials(
	item onePasswordItem,
) (string, string) {
	var username, password string
	for _, field := range item.Details.LoginFields {
		switch field.Designation {
		case "username":
			username = strings.TrimSpace(field.Value)
		case "password":
			password = field.Value
		}
	}
	return username, password
}

func onePasswordLoginFields(
	item onePasswordItem,
	itemNumber int,
) ([]CustomField, *TOTPConfig, bool, *ImportIssue) {
	var (
		customFields []CustomField
		totp         *TOTPConfig
		unmapped     bool
	)
	for _, field := range item.Details.LoginFields {
		if field.Designation != "" || field.Value == "" {
			continue
		}
		name := strings.TrimSpace(field.Name)
		if name == "" {
			unmapped = true
			continue
		}
		customFields = append(customFields, CustomField{
			Name:  name,
			Value: field.Value,
		})
	}
	for sectionIndex, section := range item.Details.Sections {
		for fieldIndex, field := range section.Fields {
			if value, ok := onePasswordFieldValue(
				field.Value,
				"totp",
			); ok {
				config, err := ParseTOTPURI(value)
				if err != nil {
					return nil, nil, false, &ImportIssue{
						Item: itemNumber,
						Field: fmt.Sprintf(
							"details.sections[%d].fields[%d].value",
							sectionIndex,
							fieldIndex,
						),
						Message: "invalid TOTP configuration",
					}
				}
				totp = &config
				continue
			}
			if value, ok := onePasswordCustomFieldValue(
				field.Value,
			); ok {
				customFields = append(customFields, CustomField{
					Name:  strings.TrimSpace(field.Title),
					Value: value,
				})
				continue
			}
			unmapped = true
		}
	}
	return customFields, totp, unmapped, nil
}

func onePasswordURLs(item onePasswordItem) []string {
	urls := make(
		[]string,
		0,
		len(item.Overview.URLs)+1,
	)
	seen := make(map[string]struct{})
	if value := strings.TrimSpace(item.Overview.URL); value != "" {
		urls = append(urls, value)
		seen[value] = struct{}{}
	}
	for _, sourceURL := range item.Overview.URLs {
		value := strings.TrimSpace(sourceURL.URL)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		urls = append(urls, value)
		seen[value] = struct{}{}
	}
	return urls
}

func normalizeOnePasswordPasswordHistory(
	item onePasswordItem,
) []PasswordHistoryEntry {
	count := min(
		len(item.Details.PasswordHistory),
		maxPasswordHistoryEntries,
	)
	history := make([]PasswordHistoryEntry, 0, count)
	for index := 0; index < count; index++ {
		entry := item.Details.PasswordHistory[index]
		history = append(history, PasswordHistoryEntry{
			Password:  entry.Value,
			ChangedAt: time.Unix(entry.Time, 0).UTC(),
		})
	}
	return history
}

func onePasswordCustomFieldValue(
	raw json.RawMessage,
) (string, bool) {
	for _, name := range []string{
		"string",
		"concealed",
		"email",
		"url",
		"phone",
		"menu",
		"creditCardNumber",
		"creditCardType",
		"gender",
		"reference",
	} {
		if value, ok := onePasswordFieldValue(raw, name); ok {
			return value, true
		}
	}
	return "", false
}

func onePasswordGenericItem(
	rawItem json.RawMessage,
	item onePasswordItem,
	folderID string,
) (NativeItem, error) {
	itemID, err := NewItemID()
	if err != nil {
		return NativeItem{}, err
	}
	generic := GenericItem{
		ItemID: itemID,
		Title: strings.TrimSpace(
			item.Overview.Title,
		),
		Source: "1password",
		SourceType: onePasswordSourceType(
			item.CategoryUUID,
		),
		FolderID: folderID,
		Favorite: item.Favorite > 0,
		Data: append(
			[]byte(nil),
			rawItem...,
		),
	}
	return NativeItem{
		Type:    NativeItemTypeGeneric,
		Generic: &generic,
	}, nil
}

func onePasswordSourceType(categoryUUID string) string {
	switch categoryUUID {
	case "001":
		return "login"
	case "002":
		return "credit_card"
	case "003":
		return "secure_note"
	default:
		return "category_" + categoryUUID
	}
}

func onePasswordFieldValue(
	raw json.RawMessage,
	name string,
) (string, bool) {
	var values map[string]json.RawMessage
	if json.Unmarshal(raw, &values) != nil {
		return "", false
	}
	value, ok := values[name]
	if !ok {
		return "", false
	}
	var text string
	if json.Unmarshal(value, &text) != nil {
		return "", false
	}
	return text, true
}

func onePasswordArchiveFile(
	archive *zip.Reader,
	name string,
) *zip.File {
	for _, file := range archive.File {
		if file.Name == name {
			return file
		}
	}
	return nil
}

func decodeOnePasswordJSON(
	file *zip.File,
	maxSize int64,
	tooLarge error,
	destination any,
) error {
	if file.UncompressedSize64 > uint64(maxSize) {
		return tooLarge
	}
	reader, err := file.Open()
	if err != nil {
		return fmt.Errorf(
			"%w: open %s",
			ErrInvalidOnePasswordExport,
			file.Name,
		)
	}
	defer reader.Close()
	input, err := io.ReadAll(io.LimitReader(reader, maxSize+1))
	if err != nil {
		return fmt.Errorf(
			"%w: read %s",
			ErrInvalidOnePasswordExport,
			file.Name,
		)
	}
	defer clearBytes(input)
	if int64(len(input)) > maxSize {
		return tooLarge
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf(
			"%w: parse %s",
			ErrInvalidOnePasswordExport,
			file.Name,
		)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf(
			"%w: trailing JSON in %s",
			ErrInvalidOnePasswordExport,
			file.Name,
		)
	}
	return nil
}
