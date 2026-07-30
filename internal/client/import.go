package client

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

type ImportCounts struct {
	Logins      int
	SecureNotes int
	Folders     int
	Generic     int
}

type ImportIssue struct {
	Item    int
	Field   string
	Message string
}

type ImportPreview struct {
	Items          []NativeItem
	Counts         ImportCounts
	UnmappedFields []ImportIssue
	Errors         []ImportIssue
}

func importDuplicateCounts(
	existing []NativeItem,
) map[[sha256.Size]byte]int {
	counts := make(map[[sha256.Size]byte]int)
	for _, item := range existing {
		if key, ok := importSemanticKey(item); ok {
			counts[key]++
		}
	}
	return counts
}

func nameImportDuplicate(
	item *NativeItem,
	counts map[[sha256.Size]byte]int,
) {
	key, ok := importSemanticKey(*item)
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

func importSemanticKey(
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
			urls = append(urls, normalizeImportURL(value))
		}
		sort.Strings(urls)
		fields := append([]CustomField(nil), item.Login.CustomFields...)
		for index := range fields {
			fields[index].Name = strings.ToLower(
				strings.TrimSpace(fields[index].Name),
			)
			fields[index].Value = normalizeImportText(
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
			Notes:           normalizeImportText(item.Login.Notes),
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
			Content: normalizeImportText(
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
		for _, field := range []string{
			"id",
			"name",
			"folderId",
			"favorite",
			"organizationId",
			"collectionIds",
			"creationDate",
			"revisionDate",
			"deletedDate",
		} {
			delete(data, field)
		}
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

func normalizeImportURL(value string) string {
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

func normalizeImportText(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	return strings.TrimSpace(value)
}
