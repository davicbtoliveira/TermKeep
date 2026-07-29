package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"testing/quick"
	"time"
)

func TestPreviewBitwardenImportNormalizesLogin(t *testing.T) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"id": "source-login-id",
			"type": 1,
			"name": "Production database",
			"notes": "Primary credentials",
			"favorite": true,
			"login": {
				"username": "operator@example.com",
				"password": "Password-Sentinel",
				"uris": [
					{"uri": "https://db.example.com"},
					{"uri": "postgres://db.internal"}
				]
			}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (BitwardenImportCounts{Logins: 1}) ||
		len(preview.Items) != 1 ||
		len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	login := preview.Items[0].Login
	if login == nil ||
		login.ItemID == "" ||
		login.Name != "Production database" ||
		login.Username != "operator@example.com" ||
		login.Password != "Password-Sentinel" ||
		login.Notes != "Primary credentials" ||
		!login.Favorite ||
		!reflect.DeepEqual(login.URLs, []string{
			"https://db.example.com",
			"postgres://db.internal",
		}) {
		t.Fatalf("normalized Login: %+v", login)
	}
}

func TestPreviewBitwardenImportPreservesNativeItems(t *testing.T) {
	export := `{
		"encrypted": false,
		"folders": [{
			"id": "source-folder-id",
			"name": "Infrastructure"
		}],
		"items": [{
			"id": "source-login-id",
			"folderId": "source-folder-id",
			"type": 1,
			"name": "Production database",
			"notes": "Primary credentials",
			"favorite": true,
			"fields": [{
				"name": "region",
				"value": "us-east-1",
				"type": 0
			}],
			"login": {
				"username": "operator@example.com",
				"password": "Password-Sentinel",
				"uris": [{"uri": "https://db.example.com"}],
				"totp": "otpauth://totp/Example:operator@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45"
			}
		}, {
			"id": "source-note-id",
			"folderId": "source-folder-id",
			"type": 2,
			"name": "Recovery procedure",
			"notes": "Sensitive recovery steps",
			"favorite": true,
			"secureNote": {"type": 0}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (BitwardenImportCounts{
		Logins:      1,
		SecureNotes: 1,
		Folders:     1,
	}) || len(preview.Items) != 3 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	folder := preview.Items[0].Folder
	login := preview.Items[1].Login
	note := preview.Items[2].SecureNote
	if folder == nil || folder.ItemID == "" ||
		folder.Name != "Infrastructure" {
		t.Fatalf("normalized Folder: %+v", folder)
	}
	wantTOTP := &TOTPConfig{
		Secret:    "JBSWY3DPEHPK3PXP",
		Issuer:    "Example",
		Account:   "operator@example.com",
		Algorithm: TOTPAlgorithmSHA256,
		Digits:    8,
		Period:    45,
	}
	if login == nil ||
		login.FolderID != folder.ItemID ||
		!reflect.DeepEqual(login.CustomFields, []CustomField{{
			Name:  "region",
			Value: "us-east-1",
		}}) ||
		!reflect.DeepEqual(login.TOTP, wantTOTP) {
		t.Fatalf("normalized Login fields: %+v", login)
	}
	if note == nil ||
		note.ItemID == "" ||
		note.Title != "Recovery procedure" ||
		note.Content != "Sensitive recovery steps" ||
		note.FolderID != folder.ItemID ||
		!note.Favorite {
		t.Fatalf("normalized Secure Note: %+v", note)
	}
}

func TestPreviewBitwardenImportPreservesPasswordHistory(t *testing.T) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"type": 1,
			"name": "Production database",
			"passwordHistory": [{
				"lastUsedDate": "2026-07-28T12:30:00Z",
				"password": "Previous-Password-Sentinel"
			}],
			"login": {
				"password": "Current-Password-Sentinel"
			}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []PasswordHistoryEntry{{
		Password: "Previous-Password-Sentinel",
		ChangedAt: time.Date(
			2026, time.July, 28, 12, 30, 0, 0, time.UTC,
		),
	}}
	if len(preview.Items) != 1 ||
		preview.Items[0].Login == nil ||
		!reflect.DeepEqual(
			preview.Items[0].Login.PasswordHistory,
			want,
		) {
		t.Fatalf("password history differs: %+v", preview)
	}
}

func TestPreviewBitwardenImportPreservesUnsupportedItemAsGeneric(
	t *testing.T,
) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"id": "source-card-id",
			"type": 3,
			"name": "Corporate card",
			"notes": "Travel only",
			"favorite": true,
			"reprompt": 1,
			"fields": [{
				"name": "cost center",
				"value": "platform",
				"type": 0
			}],
			"card": {
				"cardholderName": "Operator",
				"number": "4111111111111111",
				"code": "Security-Code-Sentinel",
				"expMonth": "12",
				"expYear": "2030"
			}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (BitwardenImportCounts{Generic: 1}) ||
		len(preview.Items) != 1 ||
		len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	generic := preview.Items[0].Generic
	if generic == nil ||
		generic.ItemID == "" ||
		generic.Title != "Corporate card" ||
		generic.Source != "bitwarden" ||
		generic.SourceType != "card" ||
		!generic.Favorite {
		t.Fatalf("normalized Generic Item: %+v", generic)
	}
	var preserved map[string]any
	if err := json.Unmarshal(generic.Data, &preserved); err != nil {
		t.Fatal(err)
	}
	card, ok := preserved["card"].(map[string]any)
	if !ok ||
		card["number"] != "4111111111111111" ||
		card["code"] != "Security-Code-Sentinel" ||
		preserved["reprompt"] != float64(1) {
		t.Fatalf("Generic Item lost source fields: %+v", preserved)
	}
}

func TestPreviewBitwardenImportReportsUnmappedNativeFields(
	t *testing.T,
) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"type": 1,
			"name": "Production database",
			"reprompt": 1,
			"fields": [{
				"name": "hidden token",
				"value": "Token-Sentinel",
				"type": 1
			}],
			"login": {
				"username": "operator@example.com",
				"password": "Password-Sentinel",
				"uris": [{
					"uri": "https://db.example.com",
					"match": 2
				}],
				"fido2Credentials": [{
					"credentialId": "Credential-Sentinel"
				}]
			}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 1 || len(preview.Errors) != 0 {
		t.Fatalf("preview did not retain valid Login: %+v", preview)
	}
	var fields []string
	for _, issue := range preview.UnmappedFields {
		fields = append(fields, issue.Field)
	}
	want := []string{
		"reprompt",
		"fields[0].type",
		"login.uris[0].match",
		"login.fido2Credentials",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("unmapped fields:\nwant: %v\ngot:  %v",
			want, fields)
	}
}

func TestPreviewBitwardenImportReportsUnmappedSecureNoteFields(
	t *testing.T,
) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"type": 2,
			"name": "Recovery procedure",
			"notes": "Sensitive recovery steps",
			"reprompt": 1,
			"fields": [{
				"name": "owner",
				"value": "platform",
				"type": 0
			}],
			"secureNote": {"type": 1}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 1 ||
		preview.Items[0].SecureNote == nil ||
		len(preview.Errors) != 0 {
		t.Fatalf("preview did not retain Secure Note: %+v", preview)
	}
	var fields []string
	for _, issue := range preview.UnmappedFields {
		fields = append(fields, issue.Field)
	}
	want := []string{"reprompt", "fields[0]", "secureNote.type"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf(
			"unmapped Secure Note fields:\nwant: %v\ngot:  %v",
			want,
			fields,
		)
	}
}

func TestPreviewBitwardenImportRenamesOnlySemanticDuplicates(
	t *testing.T,
) {
	existing := []NativeItem{{
		Type: NativeItemTypeLogin,
		Login: &LoginItem{
			ItemID:   "11111111-1111-4111-8111-111111111111",
			Name:     "Existing database",
			Username: "operator@example.com",
			Password: "Password-Sentinel",
			URLs:     []string{"https://db.example.com/"},
			Notes:    "Primary credentials",
			CustomFields: []CustomField{{
				Name:  "region",
				Value: "us-east-1",
			}},
		},
	}}
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"type": 1,
			"name": "Production database",
			"notes": " Primary credentials ",
			"fields": [{
				"name": "region",
				"value": "us-east-1",
				"type": 0
			}],
			"login": {
				"username": " OPERATOR@example.com ",
				"password": "Password-Sentinel",
				"uris": [{"uri": "https://DB.example.com"}]
			}
		}, {
			"type": 1,
			"name": "Production database",
			"notes": "Primary credentials",
			"fields": [{
				"name": "region",
				"value": "us-east-1",
				"type": 0
			}],
			"login": {
				"username": "operator@example.com",
				"password": "Password-Sentinel",
				"uris": [{"uri": "https://db.example.com/"}]
			}
		}, {
			"type": 1,
			"name": "Production database",
			"notes": "Primary credentials",
			"login": {
				"username": "different@example.com",
				"password": "Different-Password-Sentinel",
				"uris": [{"uri": "https://db.example.com/"}]
			}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		existing,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 3 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	var names []string
	for _, item := range preview.Items {
		names = append(names, item.Login.Name)
	}
	want := []string{
		"Production database (Duplicada)",
		"Production database (Duplicada) - 2",
		"Production database",
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("duplicate names:\nwant: %v\ngot:  %v",
			want, names)
	}
}

func TestPreviewBitwardenImportIgnoresGenericSourceMetadataForDuplicates(
	t *testing.T,
) {
	export := `{
		"encrypted": false,
		"folders": [],
		"items": [{
			"id": "first-source-id",
			"organizationId": "first-organization-id",
			"collectionIds": ["first-collection-id"],
			"creationDate": "2026-07-28T10:00:00Z",
			"revisionDate": "2026-07-28T11:00:00Z",
			"type": 3,
			"name": "Corporate card",
			"favorite": false,
			"card": {"number": "4111111111111111"}
		}, {
			"id": "second-source-id",
			"organizationId": "second-organization-id",
			"collectionIds": ["second-collection-id"],
			"creationDate": "2026-07-29T10:00:00Z",
			"revisionDate": "2026-07-29T11:00:00Z",
			"deletedDate": "2026-07-29T12:00:00Z",
			"type": 3,
			"name": "Backup card",
			"favorite": true,
			"card": {"number": "4111111111111111"}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 2 ||
		preview.Items[1].Generic == nil ||
		preview.Items[1].Generic.Title !=
			"Backup card (Duplicada)" {
		t.Fatalf("Generic duplicate names differ: %+v", preview)
	}
}

func TestPreviewBitwardenImportRejectsUnsafeInput(t *testing.T) {
	tests := []struct {
		name    string
		reader  io.Reader
		wantErr error
	}{
		{
			name:    "malformed JSON",
			reader:  strings.NewReader(`{"encrypted":false`),
			wantErr: ErrInvalidBitwardenExport,
		},
		{
			name: "encrypted export",
			reader: strings.NewReader(
				`{"encrypted":true,"folders":[],"items":[]}`,
			),
			wantErr: ErrInvalidBitwardenExport,
		},
		{
			name: "trailing JSON",
			reader: strings.NewReader(
				`{"encrypted":false,"items":[]} {}`,
			),
			wantErr: ErrInvalidBitwardenExport,
		},
		{
			name: "oversized export",
			reader: io.MultiReader(
				strings.NewReader(
					`{"encrypted":false,"items":[]}`,
				),
				io.LimitReader(
					repeatedByteReader{' '},
					maxBitwardenExportSize,
				),
			),
			wantErr: ErrBitwardenExportTooLarge,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := PreviewBitwardenImport(test.reader, nil)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("want %v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestPreviewBitwardenImportRejectsTooManyRecords(t *testing.T) {
	var export strings.Builder
	export.WriteString(`{"encrypted":false,"folders":[],"items":[`)
	for index := 0; index <= maxBitwardenImportRecords; index++ {
		if index > 0 {
			export.WriteByte(',')
		}
		export.WriteString(`{"type":1,"name":"x","login":{}}`)
	}
	export.WriteString(`]}`)

	_, err := PreviewBitwardenImport(
		strings.NewReader(export.String()),
		nil,
	)
	if !errors.Is(err, ErrBitwardenExportTooManyRecords) {
		t.Fatalf(
			"want %v, got %v",
			ErrBitwardenExportTooManyRecords,
			err,
		)
	}
}

func TestPreviewBitwardenImportReportsInvalidRecords(t *testing.T) {
	export := `{
		"encrypted": false,
		"folders": [{
			"id": "duplicate-folder-id",
			"name": "Infrastructure"
		}, {
			"id": "duplicate-folder-id",
			"name": "Duplicate source Folder"
		}],
		"items": [{
			"type": 1,
			"name": "   ",
			"login": {}
		}, {
			"type": 1,
			"name": "Unknown Folder",
			"folderId": "missing-folder-id",
			"login": {}
		}, {
			"type": 1,
			"name": "Invalid TOTP",
			"login": {"totp": "not-base32!"}
		}]
	}`

	preview, err := PreviewBitwardenImport(
		strings.NewReader(export),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (BitwardenImportCounts{Folders: 1}) ||
		len(preview.Items) != 1 {
		t.Fatalf("invalid records changed preview: %+v", preview)
	}
	var fields []string
	for _, issue := range preview.Errors {
		fields = append(fields, issue.Field)
	}
	want := []string{
		"folders[1].id",
		"name",
		"folderId",
		"login.totp",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("error fields:\nwant: %v\ngot:  %v",
			want, fields)
	}
}

type repeatedByteReader struct {
	value byte
}

func (reader repeatedByteReader) Read(buffer []byte) (int, error) {
	for index := range buffer {
		buffer[index] = reader.value
	}
	return len(buffer), nil
}

func TestPreviewBitwardenImportFixture(t *testing.T) {
	file, err := os.Open("testdata/bitwarden-export.json")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	preview, err := PreviewBitwardenImport(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (BitwardenImportCounts{
		Logins:      1,
		SecureNotes: 1,
		Folders:     1,
		Generic:     1,
	}) || len(preview.Items) != 4 || len(preview.Errors) != 0 {
		t.Fatalf("fixture preview: %+v", preview)
	}
}

func FuzzPreviewBitwardenImport(f *testing.F) {
	fixture, err := os.ReadFile("testdata/bitwarden-export.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	f.Add([]byte(`{"encrypted":false,"folders":[],"items":[]}`))
	f.Add([]byte(`{"encrypted":true,"items":[]}`))
	f.Add([]byte(`{"encrypted":false,"items":[{"type":99,"name":"x"}]}`))
	f.Add([]byte(`{"encrypted":false`))

	f.Fuzz(func(t *testing.T, input []byte) {
		preview, err := PreviewBitwardenImport(
			bytes.NewReader(input),
			nil,
		)
		if err != nil {
			return
		}
		for _, item := range preview.Items {
			valid := 0
			if item.Login != nil {
				valid++
			}
			if item.SecureNote != nil {
				valid++
			}
			if item.Folder != nil {
				valid++
			}
			if item.Generic != nil {
				valid++
			}
			if valid != 1 {
				t.Fatalf("invalid normalized Item: %+v", item)
			}
		}
	})
}

func TestBitwardenDuplicateNamingProperty(t *testing.T) {
	property := func(generated uint8) bool {
		count := int(generated%16) + 1
		items := make([]map[string]any, count)
		for index := range items {
			items[index] = map[string]any{
				"type": 1,
				"name": "Imported account",
				"login": map[string]any{
					"username": "user@example.com",
					"password": "Password-Sentinel",
					"uris": []map[string]any{{
						"uri": "https://example.com",
					}},
				},
			}
		}
		encoded, err := json.Marshal(map[string]any{
			"encrypted": false,
			"folders":   []any{},
			"items":     items,
		})
		if err != nil {
			return false
		}
		preview, err := PreviewBitwardenImport(
			bytes.NewReader(encoded),
			nil,
		)
		if err != nil || len(preview.Items) != count {
			return false
		}
		for index, item := range preview.Items {
			want := "Imported account"
			switch index {
			case 0:
			case 1:
				want += " (Duplicada)"
			default:
				want += " (Duplicada) - " +
					strconv.Itoa(index)
			}
			if item.Login == nil || item.Login.Name != want {
				return false
			}
		}
		return true
	}
	if err := quick.Check(
		property,
		&quick.Config{MaxCount: 32},
	); err != nil {
		t.Fatal(err)
	}
}
