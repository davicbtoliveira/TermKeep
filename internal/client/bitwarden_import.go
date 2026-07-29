package client

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
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
	FolderID string           `json:"folderId"`
	Type     int              `json:"type"`
	Name     string           `json:"name"`
	Notes    string           `json:"notes"`
	Favorite bool             `json:"favorite"`
	Reprompt int              `json:"reprompt"`
	Fields   []bitwardenField `json:"fields"`
	Login    bitwardenLogin   `json:"login"`
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

type bitwardenField struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Type     int    `json:"type"`
	LinkedID *int   `json:"linkedId"`
}

func PreviewBitwardenImport(
	reader io.Reader,
	_ []NativeItem,
) (BitwardenImportPreview, error) {
	var source bitwardenExport
	if err := json.NewDecoder(reader).Decode(&source); err != nil {
		return BitwardenImportPreview{},
			fmt.Errorf("parse Bitwarden export: %w", err)
	}
	if source.Encrypted {
		return BitwardenImportPreview{},
			fmt.Errorf("encrypted Bitwarden exports are unsupported")
	}

	preview := BitwardenImportPreview{}
	folderIDs := make(map[string]string, len(source.Folders))
	for _, folder := range source.Folders {
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
			note := SecureNoteItem{
				ItemID:   itemID,
				Title:    strings.TrimSpace(item.Name),
				Content:  item.Notes,
				FolderID: folderID,
				Favorite: item.Favorite,
			}
			preview.Items = append(preview.Items, NativeItem{
				Type:       NativeItemTypeSecureNote,
				SecureNote: &note,
			})
			preview.Counts.SecureNotes++
			continue
		}
		if item.Type != 1 {
			generic := GenericItem{
				ItemID:     itemID,
				Title:      strings.TrimSpace(item.Name),
				Source:     "bitwarden",
				SourceType: bitwardenSourceType(item.Type),
				FolderID:   folderID,
				Favorite:   item.Favorite,
				Data:       append([]byte(nil), rawItem...),
			}
			preview.Items = append(preview.Items, NativeItem{
				Type:    NativeItemTypeGeneric,
				Generic: &generic,
			})
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
			ItemID:       itemID,
			Name:         strings.TrimSpace(item.Name),
			Username:     strings.TrimSpace(item.Login.Username),
			Password:     item.Login.Password,
			FolderID:     folderID,
			Favorite:     item.Favorite,
			URLs:         urls,
			Notes:        item.Notes,
			CustomFields: customFields,
			TOTP:         totp,
		}
		preview.Items = append(preview.Items, NativeItem{
			Type:  NativeItemTypeLogin,
			Login: &login,
		})
		preview.Counts.Logins++
	}
	return preview, nil
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
