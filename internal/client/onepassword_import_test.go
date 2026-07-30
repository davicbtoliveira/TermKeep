package client

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestPreviewOnePasswordImportNormalizesLogin(t *testing.T) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Infrastructure"
				},
				"items": [{
					"uuid": "login-id",
					"favIndex": 1,
					"state": "active",
					"categoryUuid": "001",
					"overview": {
						"title": "Production database",
						"urls": [{
							"label": "database",
							"url": "https://db.example.com"
						}]
					},
					"details": {
						"loginFields": [{
							"value": "operator@example.com",
							"name": "username",
							"fieldType": "T",
							"designation": "username"
						}, {
							"value": "Password-Sentinel",
							"name": "password",
							"fieldType": "P",
							"designation": "password"
						}],
						"notesPlain": "Primary credentials"
					}
				}]
			}]
		}]
	}`)

	preview, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (ImportCounts{
		Logins:  1,
		Folders: 1,
	}) || len(preview.Items) != 2 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	folder := preview.Items[0].Folder
	login := preview.Items[1].Login
	if folder == nil ||
		folder.ItemID == "" ||
		folder.Name != "Infrastructure" {
		t.Fatalf("normalized Folder: %+v", folder)
	}
	if login == nil ||
		login.ItemID == "" ||
		login.Name != "Production database" ||
		login.Username != "operator@example.com" ||
		login.Password != "Password-Sentinel" ||
		login.Notes != "Primary credentials" ||
		!login.Favorite ||
		login.FolderID != folder.ItemID ||
		len(login.URLs) != 1 ||
		login.URLs[0] != "https://db.example.com" {
		t.Fatalf("normalized Login: %+v", login)
	}
}

func TestPreviewOnePasswordImportPreservesNativeItems(t *testing.T) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Infrastructure"
				},
				"items": [{
					"uuid": "login-id",
					"favIndex": 1,
					"state": "active",
					"categoryUuid": "001",
					"overview": {"title": "Production database"},
					"details": {
						"loginFields": [{
							"value": "operator@example.com",
							"designation": "username"
						}, {
							"value": "Password-Sentinel",
							"designation": "password"
						}],
						"sections": [{
							"title": "Operations",
							"name": "operations",
							"fields": [{
								"title": "region",
								"id": "region",
								"value": {"string": "us-east-1"}
							}, {
								"title": "one-time password",
								"id": "TOTP_seed",
								"value": {
									"totp": "otpauth://totp/Example:operator@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45"
								}
							}]
						}]
					}
				}, {
					"uuid": "note-id",
					"favIndex": 1,
					"state": "active",
					"categoryUuid": "003",
					"overview": {"title": "Recovery procedure"},
					"details": {
						"notesPlain": "Sensitive recovery steps"
					}
				}]
			}]
		}]
	}`)

	preview, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (ImportCounts{
		Logins:      1,
		SecureNotes: 1,
		Folders:     1,
	}) || len(preview.Items) != 3 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	folder := preview.Items[0].Folder
	login := preview.Items[1].Login
	note := preview.Items[2].SecureNote
	if folder == nil || login == nil ||
		!reflect.DeepEqual(login.CustomFields, []CustomField{{
			Name:  "region",
			Value: "us-east-1",
		}}) ||
		login.TOTP == nil ||
		login.TOTP.Secret != "JBSWY3DPEHPK3PXP" ||
		login.TOTP.Issuer != "Example" ||
		login.TOTP.Account != "operator@example.com" ||
		login.TOTP.Algorithm != TOTPAlgorithmSHA256 ||
		login.TOTP.Digits != 8 ||
		login.TOTP.Period != 45 {
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

func TestPreviewOnePasswordImportPreservesUnsupportedItemAsGeneric(
	t *testing.T,
) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Finance"
				},
				"items": [{
					"uuid": "card-id",
					"favIndex": 1,
					"state": "active",
					"categoryUuid": "002",
					"overview": {"title": "Corporate card"},
					"details": {
						"notesPlain": "Travel only",
						"sections": [{
							"title": "Card Details",
							"name": "card_details",
							"fields": [{
								"title": "card number",
								"id": "ccnum",
								"value": {
									"creditCardNumber": "4111111111111111"
								}
							}, {
								"title": "verification number",
								"id": "cvv",
								"value": {"concealed": "Security-Code-Sentinel"}
							}]
						}]
					}
				}]
			}]
		}]
	}`)

	preview, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (ImportCounts{
		Folders: 1,
		Generic: 1,
	}) || len(preview.Items) != 2 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	folder := preview.Items[0].Folder
	generic := preview.Items[1].Generic
	if folder == nil ||
		generic == nil ||
		generic.ItemID == "" ||
		generic.Title != "Corporate card" ||
		generic.Source != "1password" ||
		generic.SourceType != "credit_card" ||
		generic.FolderID != folder.ItemID ||
		!generic.Favorite {
		t.Fatalf("normalized Generic Item: %+v", generic)
	}
	var preserved map[string]any
	if err := json.Unmarshal(generic.Data, &preserved); err != nil {
		t.Fatal(err)
	}
	details, ok := preserved["details"].(map[string]any)
	if !ok {
		t.Fatalf("Generic Item lost details: %+v", preserved)
	}
	sections, ok := details["sections"].([]any)
	if !ok || len(sections) != 1 {
		t.Fatalf("Generic Item lost sections: %+v", preserved)
	}
	fields, ok := sections[0].(map[string]any)["fields"].([]any)
	if !ok || len(fields) != 2 {
		t.Fatalf("Generic Item lost fields: %+v", preserved)
	}
}

func TestPreviewOnePasswordImportKeepsUnmappedFieldInGenericItem(
	t *testing.T,
) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Personal"
				},
				"items": [{
					"uuid": "identity-login-id",
					"favIndex": 0,
					"state": "active",
					"categoryUuid": "001",
					"overview": {"title": "Account with address"},
					"details": {
						"loginFields": [{
							"value": "user@example.com",
							"designation": "username"
						}],
						"sections": [{
							"title": "Contact",
							"name": "contact",
							"fields": [{
								"title": "address",
								"id": "address",
								"value": {
									"address": {
										"street": "Main Street",
										"city": "Example City"
									}
								}
							}]
						}]
					}
				}]
			}]
		}]
	}`)

	preview, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (ImportCounts{
		Folders: 1,
		Generic: 1,
	}) || len(preview.Items) != 2 {
		t.Fatalf("preview summary: %+v", preview)
	}
	generic := preview.Items[1].Generic
	if generic == nil ||
		generic.SourceType != "login" ||
		generic.Title != "Account with address" {
		t.Fatalf("Generic Login differs: %+v", generic)
	}
	if !bytes.Contains(generic.Data, []byte(`"Main Street"`)) {
		t.Fatalf("Generic Login lost address: %s", generic.Data)
	}
}

func onePasswordArchive(t *testing.T, data string) *bytes.Reader {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	writeArchiveFile := func(name string, content string) {
		t.Helper()
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	writeArchiveFile("export.attributes", `{
		"version": 3,
		"description": "1Password Unencrypted Export",
		"createdAt": 1785412800
	}`)
	writeArchiveFile("export.data", data)
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buffer.Bytes())
}
