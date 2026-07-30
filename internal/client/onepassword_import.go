package client

import (
	"archive/zip"
	"bytes"
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

func PreviewOnePasswordImport(
	reader io.ReaderAt,
	size int64,
	existing []NativeItem,
) (ImportPreview, error) {
	if reader == nil || size <= 0 {
		return ImportPreview{}, ErrInvalidOnePasswordExport
	}
	archive, err := zip.NewReader(reader, size)
	if err != nil {
		return ImportPreview{},
			fmt.Errorf("%w: open archive", ErrInvalidOnePasswordExport)
	}
	attributesFile := onePasswordArchiveFile(
		archive,
		"export.attributes",
	)
	dataFile := onePasswordArchiveFile(archive, "export.data")
	if attributesFile == nil || dataFile == nil {
		return ImportPreview{},
			fmt.Errorf("%w: missing export files", ErrInvalidOnePasswordExport)
	}

	var attributes onePasswordExportAttributes
	if err := decodeOnePasswordJSON(
		attributesFile,
		maxOnePasswordExportAttributesSize,
		ErrInvalidOnePasswordExport,
		&attributes,
	); err != nil {
		return ImportPreview{}, err
	}
	if attributes.Version != 3 ||
		attributes.Description != "1Password Unencrypted Export" {
		return ImportPreview{},
			fmt.Errorf("%w: unsupported format", ErrInvalidOnePasswordExport)
	}

	var source onePasswordExport
	if err := decodeOnePasswordJSON(
		dataFile,
		maxOnePasswordExportDataSize,
		ErrOnePasswordExportTooLarge,
		&source,
	); err != nil {
		return ImportPreview{}, err
	}
	recordCount := 0
	for _, account := range source.Accounts {
		for _, vault := range account.Vaults {
			if recordCount >= maxOnePasswordImportRecords ||
				len(vault.Items) >
					maxOnePasswordImportRecords-recordCount-1 {
				return ImportPreview{},
					ErrOnePasswordExportTooManyRecords
			}
			recordCount += 1 + len(vault.Items)
		}
	}

	preview := ImportPreview{}
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
	duplicateCounts := importDuplicateCounts(existing)
	vaultIDs := make(map[string]struct{})
	for _, account := range source.Accounts {
		for vaultIndex, vault := range account.Vaults {
			vault.Attrs.UUID = strings.TrimSpace(vault.Attrs.UUID)
			vault.Attrs.Name = strings.TrimSpace(vault.Attrs.Name)
			if vault.Attrs.UUID == "" || vault.Attrs.Name == "" {
				field := fmt.Sprintf(
					"vaults[%d].attrs.uuid",
					vaultIndex,
				)
				if vault.Attrs.UUID != "" {
					field = fmt.Sprintf(
						"vaults[%d].attrs.name",
						vaultIndex,
					)
				}
				preview.Errors = append(
					preview.Errors,
					ImportIssue{
						Field:   field,
						Message: "Vault UUID and name are required",
					},
				)
				continue
			}
			if _, exists := vaultIDs[vault.Attrs.UUID]; exists {
				preview.Errors = append(
					preview.Errors,
					ImportIssue{
						Field: fmt.Sprintf(
							"vaults[%d].attrs.uuid",
							vaultIndex,
						),
						Message: "duplicate 1Password Vault UUID",
					},
				)
				continue
			}
			vaultIDs[vault.Attrs.UUID] = struct{}{}
			folderID, err := NewItemID()
			if err != nil {
				return ImportPreview{}, err
			}
			folder := FolderItem{
				ItemID: folderID,
				Name:   vault.Attrs.Name,
			}
			preview.Items = append(preview.Items, NativeItem{
				Type:   NativeItemTypeFolder,
				Folder: &folder,
			})
			preview.Counts.Folders++

			for itemIndex, rawItem := range vault.Items {
				var item onePasswordItem
				if err := json.Unmarshal(rawItem, &item); err != nil {
					preview.Errors = append(
						preview.Errors,
						ImportIssue{
							Item:    itemIndex + 1,
							Message: "invalid 1Password Item",
						},
					)
					continue
				}
				item.UUID = strings.TrimSpace(item.UUID)
				item.CategoryUUID = strings.TrimSpace(
					item.CategoryUUID,
				)
				item.Overview.Title = strings.TrimSpace(
					item.Overview.Title,
				)
				if item.UUID == "" {
					preview.Errors = append(
						preview.Errors,
						ImportIssue{
							Item:    itemIndex + 1,
							Field:   "uuid",
							Message: "Item UUID is required",
						},
					)
					continue
				}
				if item.Overview.Title == "" {
					preview.Errors = append(
						preview.Errors,
						ImportIssue{
							Item:    itemIndex + 1,
							Field:   "overview.title",
							Message: "Item title is required",
						},
					)
					continue
				}
				if item.CategoryUUID == "" {
					preview.Errors = append(
						preview.Errors,
						ImportIssue{
							Item:    itemIndex + 1,
							Field:   "categoryUuid",
							Message: "Item category is required",
						},
					)
					continue
				}
				if onePasswordJSONValuePresent(
					item.Details.DocumentAttributes,
				) || onePasswordJSONValuePresent(item.File) {
					generic, err := onePasswordGenericItem(
						rawItem,
						item,
						folderID,
					)
					if err != nil {
						return ImportPreview{}, err
					}
					nameImportDuplicate(&generic, duplicateCounts)
					preview.Items = append(preview.Items, generic)
					preview.Counts.Generic++
					continue
				}
				if item.CategoryUUID == "003" {
					if len(item.Details.Sections) != 0 {
						generic, err := onePasswordGenericItem(
							rawItem,
							item,
							folderID,
						)
						if err != nil {
							return ImportPreview{}, err
						}
						nameImportDuplicate(
							&generic,
							duplicateCounts,
						)
						preview.Items = append(
							preview.Items,
							generic,
						)
						preview.Counts.Generic++
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
					nameImportDuplicate(
						&normalizedItem,
						duplicateCounts,
					)
					preview.Items = append(
						preview.Items,
						normalizedItem,
					)
					preview.Counts.SecureNotes++
					continue
				}
				if item.CategoryUUID != "001" {
					generic, err := onePasswordGenericItem(
						rawItem,
						item,
						folderID,
					)
					if err != nil {
						return ImportPreview{}, err
					}
					nameImportDuplicate(&generic, duplicateCounts)
					preview.Items = append(preview.Items, generic)
					preview.Counts.Generic++
					continue
				}
				var username, password string
				for _, field := range item.Details.LoginFields {
					switch field.Designation {
					case "username":
						username = strings.TrimSpace(field.Value)
					case "password":
						password = field.Value
					}
				}
				var (
					customFields []CustomField
					totp         *TOTPConfig
					unmapped     bool
					invalidTOTP  bool
				)
				for sectionIndex, section := range item.Details.Sections {
					for fieldIndex, field := range section.Fields {
						if value, ok := onePasswordFieldValue(
							field.Value,
							"totp",
						); ok {
							config, err := ParseTOTPURI(value)
							if err != nil {
								preview.Errors = append(
									preview.Errors,
									ImportIssue{
										Item: itemIndex + 1,
										Field: fmt.Sprintf(
											"details.sections[%d].fields[%d].value",
											sectionIndex,
											fieldIndex,
										),
										Message: "invalid TOTP configuration",
									},
								)
								invalidTOTP = true
								break
							}
							totp = &config
							continue
						}
						if value, ok :=
							onePasswordCustomFieldValue(
								field.Value,
							); ok {
							customFields = append(
								customFields,
								CustomField{
									Name: strings.TrimSpace(
										field.Title,
									),
									Value: value,
								},
							)
							continue
						}
						unmapped = true
					}
					if invalidTOTP {
						break
					}
				}
				if invalidTOTP {
					continue
				}
				if unmapped {
					generic, err := onePasswordGenericItem(
						rawItem,
						item,
						folderID,
					)
					if err != nil {
						return ImportPreview{}, err
					}
					nameImportDuplicate(&generic, duplicateCounts)
					preview.Items = append(preview.Items, generic)
					preview.Counts.Generic++
					continue
				}
				itemID, err := NewItemID()
				if err != nil {
					return ImportPreview{}, err
				}
				urls := make(
					[]string,
					0,
					len(item.Overview.URLs)+1,
				)
				seenURLs := make(map[string]struct{})
				if value := strings.TrimSpace(
					item.Overview.URL,
				); value != "" {
					urls = append(urls, value)
					seenURLs[value] = struct{}{}
				}
				for _, sourceURL := range item.Overview.URLs {
					if value := strings.TrimSpace(sourceURL.URL); value != "" {
						if _, exists := seenURLs[value]; exists {
							continue
						}
						urls = append(urls, value)
						seenURLs[value] = struct{}{}
					}
				}
				historyCount := min(
					len(item.Details.PasswordHistory),
					maxPasswordHistoryEntries,
				)
				passwordHistory := make(
					[]PasswordHistoryEntry,
					0,
					historyCount,
				)
				for index := 0; index < historyCount; index++ {
					entry := item.Details.PasswordHistory[index]
					passwordHistory = append(
						passwordHistory,
						PasswordHistoryEntry{
							Password: entry.Value,
							ChangedAt: time.Unix(
								entry.Time,
								0,
							).UTC(),
						},
					)
				}
				login := LoginItem{
					ItemID:          itemID,
					Name:            strings.TrimSpace(item.Overview.Title),
					Username:        username,
					Password:        password,
					PasswordHistory: passwordHistory,
					FolderID:        folderID,
					Favorite:        item.Favorite > 0,
					URLs:            urls,
					Notes:           item.Details.Notes,
					CustomFields:    customFields,
					TOTP:            totp,
				}
				normalizedItem := NativeItem{
					Type:  NativeItemTypeLogin,
					Login: &login,
				}
				nameImportDuplicate(
					&normalizedItem,
					duplicateCounts,
				)
				preview.Items = append(
					preview.Items,
					normalizedItem,
				)
				preview.Counts.Logins++
			}
		}
	}
	return preview, nil
}

func onePasswordJSONValuePresent(raw json.RawMessage) bool {
	value := strings.TrimSpace(string(raw))
	return value != "" &&
		value != "null" &&
		value != "{}" &&
		value != "[]"
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
