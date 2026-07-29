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
	Encrypted bool            `json:"encrypted"`
	Items     []bitwardenItem `json:"items"`
}

type bitwardenItem struct {
	Type     int            `json:"type"`
	Name     string         `json:"name"`
	Notes    string         `json:"notes"`
	Favorite bool           `json:"favorite"`
	Login    bitwardenLogin `json:"login"`
}

type bitwardenLogin struct {
	Username string              `json:"username"`
	Password string              `json:"password"`
	URIs     []bitwardenLoginURI `json:"uris"`
}

type bitwardenLoginURI struct {
	URI string `json:"uri"`
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
	for index, item := range source.Items {
		if item.Type != 1 {
			preview.Errors = append(
				preview.Errors,
				BitwardenImportIssue{
					Item:    index + 1,
					Field:   "type",
					Message: "unsupported Bitwarden Item type",
				},
			)
			continue
		}
		itemID, err := NewItemID()
		if err != nil {
			return BitwardenImportPreview{}, err
		}
		urls := make([]string, 0, len(item.Login.URIs))
		for _, uri := range item.Login.URIs {
			if value := strings.TrimSpace(uri.URI); value != "" {
				urls = append(urls, value)
			}
		}
		login := LoginItem{
			ItemID:   itemID,
			Name:     strings.TrimSpace(item.Name),
			Username: strings.TrimSpace(item.Login.Username),
			Password: item.Login.Password,
			Favorite: item.Favorite,
			URLs:     urls,
			Notes:    item.Notes,
		}
		preview.Items = append(preview.Items, NativeItem{
			Type:  NativeItemTypeLogin,
			Login: &login,
		})
		preview.Counts.Logins++
	}
	return preview, nil
}
