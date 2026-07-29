package client

import (
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
