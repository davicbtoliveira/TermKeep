package client

import (
	"archive/zip"
	"bytes"
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
