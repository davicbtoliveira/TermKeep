package client

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
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
