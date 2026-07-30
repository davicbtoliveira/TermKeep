package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestJSONExportRoundTripPreservesNativeAndGenericItems(t *testing.T) {
	items := readableExportTestItems(t)
	var encoded bytes.Buffer
	if err := EncodeJSONExport(&encoded, items); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(encoded.String(), `"data": {`) ||
		strings.Contains(encoded.String(), "eyJ") {
		t.Fatalf("Generic data was not human-readable JSON: %s", encoded.String())
	}
	parsed, err := ParseJSONExport(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqualNativeItems(items, parsed) {
		t.Fatalf("JSON round trip differs:\nwant=%+v\ngot=%+v", items, parsed)
	}
}

func TestCSVExportRoundTripPreservesNonTabularFields(t *testing.T) {
	items := readableExportTestItems(t)
	items[1].Login.TOTP = nil
	var encoded bytes.Buffer
	if err := EncodeCSVExport(&encoded, items, CSVExportOptions{}); err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseCSVExport(bytes.NewReader(encoded.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqualNativeItems(items, parsed) {
		t.Fatalf("CSV round trip differs:\nwant=%+v\ngot=%+v", items, parsed)
	}
}

func TestReadableExportFileIsAtomicAndMode0600(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "vault.json")
	if err := os.WriteFile(path, []byte("old-content"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := WriteJSONExportFileContext(
		ctx, path, readableExportTestItems(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled export error: %v", err)
	}
	unchanged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != "old-content" {
		t.Fatalf("canceled export replaced final file: %q", unchanged)
	}
	if err := WriteJSONExportFile(path, readableExportTestItems(t)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("export mode = %o, want 600", info.Mode().Perm())
	}
	if _, err := ReadJSONExportFile(path); err != nil {
		t.Fatal(err)
	}
}

func TestReadableExportRejectsMalformedGenericData(t *testing.T) {
	item := NativeItem{
		Type: NativeItemTypeGeneric,
		Generic: &GenericItem{
			ItemID:     "44444444-4444-4444-8444-444444444444",
			Title:      "Malformed",
			Source:     "test",
			SourceType: "fixture",
			Data:       []byte("not-json"),
		},
	}
	if err := EncodeJSONExport(&bytes.Buffer{}, []NativeItem{item}); !errors.Is(err, ErrInvalidJSONExport) {
		t.Fatalf("malformed JSON data error = %v", err)
	}
	if err := EncodeCSVExport(&bytes.Buffer{}, []NativeItem{item}, CSVExportOptions{}); !errors.Is(err, ErrInvalidCSVReadableExport) {
		t.Fatalf("malformed CSV data error = %v", err)
	}
}

func TestPreviewJSONImportFreshensIDsAndRemapsFolders(t *testing.T) {
	items := readableExportTestItems(t)
	var encoded bytes.Buffer
	if err := EncodeJSONExport(&encoded, items); err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewJSONImport(bytes.NewReader(encoded.Bytes()), nil)
	if err != nil {
		t.Fatal(err)
	}
	originalIDs := map[string]bool{
		"11111111-1111-4111-8111-111111111111": true,
		"22222222-2222-4222-8222-222222222222": true,
		"33333333-3333-4333-8333-333333333333": true,
		"44444444-4444-4444-8444-444444444444": true,
	}
	var folderID string
	for _, item := range preview.Items {
		if originalIDs[exportNativeItemID(item)] {
			t.Fatalf("import retained source Item ID %q", exportNativeItemID(item))
		}
		if item.Folder != nil {
			folderID = item.Folder.ItemID
		}
	}
	if folderID == "" {
		t.Fatal("import did not retain Folder")
	}
	for _, item := range preview.Items {
		if item.Login != nil && item.Login.FolderID != folderID {
			t.Fatalf("Login FolderID = %q, want %q", item.Login.FolderID, folderID)
		}
	}
}

func FuzzParseJSONExportNeverPanics(f *testing.F) {
	f.Add([]byte(`{"version":1,"format":"termkeep-json","items":[]}`))
	f.Add([]byte("not json"))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = ParseJSONExport(bytes.NewReader(input))
	})
}

func FuzzParseCSVExportNeverPanics(f *testing.F) {
	f.Add([]byte("type,item_id,name\n"))
	f.Add([]byte("not,csv"))
	f.Fuzz(func(_ *testing.T, input []byte) {
		_, _ = ParseCSVExport(bytes.NewReader(input))
	})
}

func readableExportTestItems(t *testing.T) []NativeItem {
	t.Helper()
	totp, err := NewTOTPConfig(
		"JBSWY3DPEHPK3PXP", "Example", "user@example.com", "SHA256", 8, 45)
	if err != nil {
		t.Fatal(err)
	}
	return []NativeItem{
		{
			Type: NativeItemTypeFolder,
			Folder: &FolderItem{
				ItemID: "11111111-1111-4111-8111-111111111111",
				Name:   "Production",
			},
		},
		{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID:   "22222222-2222-4222-8222-222222222222",
				Name:     "Example",
				Username: "user@example.com",
				Password: "secret",
				PasswordHistory: []PasswordHistoryEntry{{
					Password: "old-secret",
				}},
				FolderID:     "11111111-1111-4111-8111-111111111111",
				Favorite:     true,
				URLs:         []string{"https://example.com", "https://admin.example.com"},
				Notes:        "keep locally",
				CustomFields: []CustomField{{Name: "token", Value: "value"}},
				TOTP:         &totp,
			},
		},
		{
			Type: NativeItemTypeSecureNote,
			SecureNote: &SecureNoteItem{
				ItemID:   "33333333-3333-4333-8333-333333333333",
				Title:    "Recovery",
				Content:  "note content",
				FolderID: "11111111-1111-4111-8111-111111111111",
			},
		},
		{
			Type: NativeItemTypeGeneric,
			Generic: &GenericItem{
				ItemID:     "44444444-4444-4444-8444-444444444444",
				Title:      "Imported card",
				Source:     "fixture",
				SourceType: "opaque",
				Data:       []byte(`{"nested":{"secret":"value"},"array":[1,true]}`),
			},
		},
	}
}

func jsonEqualNativeItems(left, right []NativeItem) bool {
	left = normalizeNativeItemData(left)
	right = normalizeNativeItemData(right)
	return reflect.DeepEqual(left, right)
}

func normalizeNativeItemData(items []NativeItem) []NativeItem {
	cloned := append([]NativeItem(nil), items...)
	for index := range cloned {
		if cloned[index].Generic == nil {
			continue
		}
		generic := *cloned[index].Generic
		compact := new(bytes.Buffer)
		if json.Compact(compact, generic.Data) == nil {
			generic.Data = append([]byte(nil), compact.Bytes()...)
		}
		cloned[index].Generic = &generic
	}
	return cloned
}
