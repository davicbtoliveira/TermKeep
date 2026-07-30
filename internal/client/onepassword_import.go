package client

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrInvalidOnePasswordExport = errors.New(
	"invalid 1Password export",
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
	if err := decodeOnePasswordJSON(attributesFile, &attributes); err != nil {
		return ImportPreview{}, err
	}
	if attributes.Version != 3 ||
		attributes.Description != "1Password Unencrypted Export" {
		return ImportPreview{},
			fmt.Errorf("%w: unsupported format", ErrInvalidOnePasswordExport)
	}

	var source onePasswordExport
	if err := decodeOnePasswordJSON(dataFile, &source); err != nil {
		return ImportPreview{}, err
	}

	preview := ImportPreview{}
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
					preview.Items = append(preview.Items, NativeItem{
						Type:       NativeItemTypeSecureNote,
						SecureNote: &note,
					})
					preview.Counts.SecureNotes++
					continue
				}
				if item.CategoryUUID != "001" {
					itemID, err := NewItemID()
					if err != nil {
						return ImportPreview{}, err
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
					preview.Items = append(preview.Items, NativeItem{
						Type:    NativeItemTypeGeneric,
						Generic: &generic,
					})
					preview.Counts.Generic++
					continue
				}
				itemID, err := NewItemID()
				if err != nil {
					return ImportPreview{}, err
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
						}
					}
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
				preview.Items = append(preview.Items, NativeItem{
					Type:  NativeItemTypeLogin,
					Login: &login,
				})
				preview.Counts.Logins++
			}
		}
	}
	return preview, nil
}

func onePasswordSourceType(categoryUUID string) string {
	switch categoryUUID {
	case "002":
		return "credit_card"
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

func decodeOnePasswordJSON(file *zip.File, destination any) error {
	reader, err := file.Open()
	if err != nil {
		return fmt.Errorf(
			"%w: open %s",
			ErrInvalidOnePasswordExport,
			file.Name,
		)
	}
	defer reader.Close()
	decoder := json.NewDecoder(reader)
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
