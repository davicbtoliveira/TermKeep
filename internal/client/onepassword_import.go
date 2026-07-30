package client

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
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
}

type onePasswordItemOverview struct {
	Title string               `json:"title"`
	URLs  []onePasswordItemURL `json:"urls"`
}

type onePasswordItemURL struct {
	URL string `json:"url"`
}

type onePasswordItemDetails struct {
	LoginFields []onePasswordLoginField `json:"loginFields"`
	Notes       string                  `json:"notesPlain"`
	Sections    []onePasswordSection    `json:"sections"`
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
	duplicateCounts := importDuplicateCounts(existing)
	for _, account := range source.Accounts {
		for _, vault := range account.Vaults {
			folderID, err := NewItemID()
			if err != nil {
				return ImportPreview{}, err
			}
			folder := FolderItem{
				ItemID: folderID,
				Name:   strings.TrimSpace(vault.Attrs.Name),
			}
			preview.Items = append(preview.Items, NativeItem{
				Type:   NativeItemTypeFolder,
				Folder: &folder,
			})
			preview.Counts.Folders++

			for _, rawItem := range vault.Items {
				var item onePasswordItem
				if err := json.Unmarshal(rawItem, &item); err != nil {
					return ImportPreview{},
						fmt.Errorf(
							"%w: parse Item",
							ErrInvalidOnePasswordExport,
						)
				}
				if item.CategoryUUID == "003" {
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
				)
				for _, section := range item.Details.Sections {
					for _, field := range section.Fields {
						if value, ok := onePasswordFieldValue(
							field.Value,
							"totp",
						); ok {
							config, err := ParseTOTPURI(value)
							if err != nil {
								return ImportPreview{},
									fmt.Errorf(
										"%w: invalid TOTP",
										ErrInvalidOnePasswordExport,
									)
							}
							totp = &config
							continue
						}
						if value, ok := onePasswordFieldValue(
							field.Value,
							"string",
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
				urls := make([]string, 0, len(item.Overview.URLs))
				for _, sourceURL := range item.Overview.URLs {
					if value := strings.TrimSpace(sourceURL.URL); value != "" {
						urls = append(urls, value)
					}
				}
				login := LoginItem{
					ItemID:       itemID,
					Name:         strings.TrimSpace(item.Overview.Title),
					Username:     username,
					Password:     password,
					FolderID:     folderID,
					Favorite:     item.Favorite > 0,
					URLs:         urls,
					Notes:        item.Details.Notes,
					CustomFields: customFields,
					TOTP:         totp,
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
