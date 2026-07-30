package client

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
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
						"url": "https://db.example.com"
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

func TestPreviewOnePasswordImportKeepsUnmappedSecureNoteFieldInGenericItem(
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
					"uuid": "note-id",
					"favIndex": 0,
					"state": "active",
					"categoryUuid": "003",
					"overview": {"title": "Recovery procedure"},
					"details": {
						"notesPlain": "Recovery steps",
						"sections": [{
							"title": "Ownership",
							"name": "ownership",
							"fields": [{
								"title": "owner",
								"id": "owner",
								"value": {"string": "platform"}
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
		generic.SourceType != "secure_note" ||
		!bytes.Contains(generic.Data, []byte(`"platform"`)) {
		t.Fatalf("Generic Secure Note differs: %+v", generic)
	}
}

func TestPreviewOnePasswordImportKeepsTagsInGenericItem(t *testing.T) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Personal"
				},
				"items": [{
					"uuid": "tagged-login-id",
					"categoryUuid": "001",
					"overview": {
						"title": "Tagged account",
						"tags": ["production", "database"]
					},
					"details": {
						"loginFields": [{
							"value": "operator@example.com",
							"designation": "username"
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
		t.Fatalf("tagged item preview: %+v", preview)
	}
	generic := preview.Items[1].Generic
	if generic == nil ||
		!bytes.Contains(generic.Data, []byte(`"production"`)) ||
		!bytes.Contains(generic.Data, []byte(`"database"`)) {
		t.Fatalf("Generic Item lost tags: %+v", generic)
	}
}

func TestPreviewOnePasswordImportKeepsArchivedItemInGenericItem(
	t *testing.T,
) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Archive"
				},
				"items": [{
					"uuid": "archived-login-id",
					"state": "archived",
					"categoryUuid": "001",
					"overview": {"title": "Former account"},
					"details": {
						"loginFields": [{
							"value": "former@example.com",
							"designation": "username"
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
		t.Fatalf("archived item preview: %+v", preview)
	}
	generic := preview.Items[1].Generic
	if generic == nil ||
		!bytes.Contains(generic.Data, []byte(`"archived"`)) {
		t.Fatalf("Generic Item lost archived state: %+v", generic)
	}
}

func TestPreviewOnePasswordImportRenamesOnlySemanticDuplicates(
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
		},
	}}
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "vault-id",
					"name": "Infrastructure"
				},
				"items": [{
					"uuid": "first-login-id",
					"categoryUuid": "001",
					"overview": {
						"title": "Production database",
						"urls": [{"url": "https://DB.example.com"}]
					},
					"details": {
						"notesPlain": " Primary credentials ",
						"loginFields": [{
							"value": " OPERATOR@example.com ",
							"designation": "username"
						}, {
							"value": "Password-Sentinel",
							"designation": "password"
						}]
					}
				}, {
					"uuid": "second-login-id",
					"categoryUuid": "001",
					"overview": {
						"title": "Production database",
						"urls": [{"url": "https://db.example.com/"}]
					},
					"details": {
						"notesPlain": "Primary credentials",
						"loginFields": [{
							"value": "operator@example.com",
							"designation": "username"
						}, {
							"value": "Password-Sentinel",
							"designation": "password"
						}]
					}
				}, {
					"uuid": "different-login-id",
					"categoryUuid": "001",
					"overview": {
						"title": "Production database",
						"urls": [{"url": "https://db.example.com"}]
					},
					"details": {
						"notesPlain": "Primary credentials",
						"loginFields": [{
							"value": "different@example.com",
							"designation": "username"
						}, {
							"value": "Different-Password-Sentinel",
							"designation": "password"
						}]
					}
				}]
			}]
		}]
	}`)

	preview, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		existing,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 4 || len(preview.Errors) != 0 {
		t.Fatalf("preview summary: %+v", preview)
	}
	var names []string
	for _, item := range preview.Items[1:] {
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

func TestPreviewOnePasswordImportIgnoresGenericSourceMetadataForDuplicates(
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
					"uuid": "first-card-id",
					"favIndex": 0,
					"createdAt": 1785240000,
					"updatedAt": 1785243600,
					"state": "active",
					"categoryUuid": "002",
					"overview": {
						"title": "Corporate card",
						"subtitle": "First source subtitle"
					},
					"details": {
						"sections": [{
							"fields": [{
								"title": "card number",
								"value": {
									"creditCardNumber": "4111111111111111"
								}
							}]
						}]
					}
				}, {
					"uuid": "second-card-id",
					"favIndex": 1,
					"createdAt": 1785326400,
					"updatedAt": 1785330000,
					"state": "active",
					"categoryUuid": "002",
					"overview": {
						"title": "Backup card",
						"subtitle": "Second source subtitle"
					},
					"details": {
						"sections": [{
							"fields": [{
								"title": "card number",
								"value": {
									"creditCardNumber": "4111111111111111"
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
	if len(preview.Items) != 3 ||
		preview.Items[2].Generic == nil ||
		preview.Items[2].Generic.Title != "Backup card (Duplicada)" {
		t.Fatalf("Generic duplicate names differ: %+v", preview)
	}
}

func TestPreviewOnePasswordImportRejectsUnsafeInput(t *testing.T) {
	malformed := bytes.NewReader([]byte("not a ZIP archive"))
	missingData := onePasswordArchiveWithFiles(t, map[string]string{
		"export.attributes": `{
			"version": 3,
			"description": "1Password Unencrypted Export"
		}`,
	})
	unsupportedVersion := onePasswordArchiveWithFiles(
		t,
		map[string]string{
			"export.attributes": `{
				"version": 99,
				"description": "1Password Unencrypted Export"
			}`,
			"export.data": `{"accounts":[]}`,
		},
	)
	trailingJSON := onePasswordArchive(
		t,
		`{"accounts":[]} {}`,
	)
	oversized := onePasswordArchive(
		t,
		`{"accounts":[]}`+
			strings.Repeat(" ", maxOnePasswordExportDataSize),
	)
	tests := []struct {
		name    string
		archive *bytes.Reader
		wantErr error
	}{
		{
			name:    "nil reader",
			wantErr: ErrInvalidOnePasswordExport,
		},
		{
			name:    "malformed archive",
			archive: malformed,
			wantErr: ErrInvalidOnePasswordExport,
		},
		{
			name:    "missing export data",
			archive: missingData,
			wantErr: ErrInvalidOnePasswordExport,
		},
		{
			name:    "unsupported version",
			archive: unsupportedVersion,
			wantErr: ErrInvalidOnePasswordExport,
		},
		{
			name:    "trailing JSON",
			archive: trailingJSON,
			wantErr: ErrInvalidOnePasswordExport,
		},
		{
			name:    "oversized export data",
			archive: oversized,
			wantErr: ErrOnePasswordExportTooLarge,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var size int64
			if test.archive != nil {
				size = test.archive.Size()
			}
			_, err := PreviewOnePasswordImport(
				test.archive,
				size,
				nil,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("want %v, got %v", test.wantErr, err)
			}
		})
	}
}

func TestPreviewOnePasswordImportReportsUnmappedAttachments(
	t *testing.T,
) {
	archive := onePasswordArchiveWithFiles(t, map[string]string{
		"export.attributes": `{
			"version": 3,
			"description": "1Password Unencrypted Export"
		}`,
		"export.data": `{
			"accounts": [{
				"attrs": {"uuid": "account-id"},
				"vaults": [{
					"attrs": {
						"uuid": "vault-id",
						"name": "Infrastructure"
					},
					"items": [{
						"uuid": "document-login-id",
						"categoryUuid": "001",
						"overview": {"title": "Database runbook"},
						"details": {
							"documentAttributes": {
								"fileName": "runbook.txt",
								"documentId": "document-id",
								"decryptedSize": 19
							}
						}
					}]
				}]
			}]
		}`,
		"files/document-id___runbook.txt": "Attachment-Sentinel",
	})

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
	}) || len(preview.Items) != 2 ||
		len(preview.UnmappedFields) != 1 {
		t.Fatalf("attachment preview: %+v", preview)
	}
	issue := preview.UnmappedFields[0]
	if issue.Field != "files/document-id___runbook.txt" ||
		issue.Message != "attachment binary is not imported" {
		t.Fatalf("attachment warning differs: %+v", issue)
	}
	generic := preview.Items[1].Generic
	if generic == nil ||
		!bytes.Contains(generic.Data, []byte(`"runbook.txt"`)) ||
		bytes.Contains(generic.Data, []byte("Attachment-Sentinel")) {
		t.Fatalf("Generic attachment metadata differs: %+v", generic)
	}
}

func TestPreviewOnePasswordImportRejectsTooManyRecords(t *testing.T) {
	var data strings.Builder
	data.WriteString(`{
		"accounts": [{
			"vaults": [{
				"attrs": {"uuid": "vault-id", "name": "Personal"},
				"items": [`)
	for index := 0; index < maxOnePasswordImportRecords; index++ {
		if index > 0 {
			data.WriteByte(',')
		}
		data.WriteString(
			`{"categoryUuid":"001","overview":{"title":"x"}}`,
		)
	}
	data.WriteString(`]}]}]}`)
	archive := onePasswordArchive(t, data.String())

	_, err := PreviewOnePasswordImport(
		archive,
		archive.Size(),
		nil,
	)
	if !errors.Is(err, ErrOnePasswordExportTooManyRecords) {
		t.Fatalf(
			"want %v, got %v",
			ErrOnePasswordExportTooManyRecords,
			err,
		)
	}
}

func TestPreviewOnePasswordImportReportsInvalidRecords(t *testing.T) {
	archive := onePasswordArchive(t, `{
		"accounts": [{
			"attrs": {"uuid": "account-id"},
			"vaults": [{
				"attrs": {
					"uuid": "duplicate-vault-id",
					"name": "Personal"
				},
				"items": [{
					"uuid": "missing-title-id",
					"categoryUuid": "001",
					"overview": {"title": "   "}
				}, {
					"uuid": "missing-category-id",
					"overview": {"title": "Missing category"}
				}, {
					"uuid": "invalid-totp-id",
					"categoryUuid": "001",
					"overview": {"title": "Invalid TOTP"},
					"details": {
						"sections": [{
							"fields": [{
								"title": "one-time password",
								"value": {"totp": "not-an-otpauth-uri"}
							}]
						}]
					}
				}, {
					"uuid": "valid-note-id",
					"categoryUuid": "003",
					"overview": {"title": "Recovery procedure"},
					"details": {"notesPlain": "Recovery steps"}
				}]
			}, {
				"attrs": {
					"uuid": "duplicate-vault-id",
					"name": "Duplicate vault"
				},
				"items": [{
					"uuid": "skipped-login-id",
					"categoryUuid": "001",
					"overview": {"title": "Skipped Login"}
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
		SecureNotes: 1,
		Folders:     1,
	}) || len(preview.Items) != 2 {
		t.Fatalf("invalid records changed preview: %+v", preview)
	}
	var fields []string
	for _, issue := range preview.Errors {
		fields = append(fields, issue.Field)
	}
	want := []string{
		"overview.title",
		"categoryUuid",
		"details.sections[0].fields[0].value",
		"vaults[1].attrs.uuid",
	}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("error fields:\nwant: %v\ngot:  %v",
			want, fields)
	}
}

func TestPreviewOnePasswordImportPreservesPasswordHistory(t *testing.T) {
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
					"categoryUuid": "001",
					"overview": {"title": "Production database"},
					"details": {
						"loginFields": [{
							"value": "Current-Password-Sentinel",
							"designation": "password"
						}],
						"passwordHistory": [{
							"value": "Previous-Password-Sentinel",
							"time": 1785241800
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
	want := []PasswordHistoryEntry{{
		Password: "Previous-Password-Sentinel",
		ChangedAt: time.Date(
			2026, time.July, 28, 12, 30, 0, 0, time.UTC,
		),
	}}
	if len(preview.Items) != 2 ||
		preview.Items[1].Login == nil ||
		!reflect.DeepEqual(
			preview.Items[1].Login.PasswordHistory,
			want,
		) {
		t.Fatalf("password history differs: %+v", preview)
	}
}

func TestPreviewOnePasswordImportPreservesEquivalentCustomFields(
	t *testing.T,
) {
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
					"categoryUuid": "001",
					"overview": {"title": "Production database"},
					"details": {
						"sections": [{
							"title": "Operations",
							"name": "operations",
							"fields": [{
								"title": "recovery code",
								"id": "recovery",
								"value": {"concealed": "Recovery-Sentinel"}
							}, {
								"title": "owner",
								"id": "owner",
								"value": {"email": "operator@example.com"}
							}, {
								"title": "dashboard",
								"id": "dashboard",
								"value": {"url": "https://db.example.com/admin"}
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
	if len(preview.Items) != 2 ||
		preview.Items[1].Login == nil ||
		!reflect.DeepEqual(
			preview.Items[1].Login.CustomFields,
			[]CustomField{
				{
					Name:  "recovery code",
					Value: "Recovery-Sentinel",
				},
				{
					Name:  "owner",
					Value: "operator@example.com",
				},
				{
					Name:  "dashboard",
					Value: "https://db.example.com/admin",
				},
			},
		) {
		t.Fatalf("custom fields differ: %+v", preview)
	}
}

func TestPreviewOnePasswordImportPreservesUndesignatedLoginField(
	t *testing.T,
) {
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
					"categoryUuid": "001",
					"overview": {"title": "Production database"},
					"details": {
						"loginFields": [{
							"value": "operator@example.com",
							"name": "username",
							"designation": "username"
						}, {
							"value": "Security-Answer-Sentinel",
							"name": "security_answer",
							"fieldType": "T"
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
	if len(preview.Items) != 2 ||
		preview.Items[1].Login == nil ||
		!reflect.DeepEqual(
			preview.Items[1].Login.CustomFields,
			[]CustomField{{
				Name:  "security_answer",
				Value: "Security-Answer-Sentinel",
			}},
		) {
		t.Fatalf("undesignated Login field differs: %+v", preview)
	}
}

func TestPreviewOnePasswordImportFixture(t *testing.T) {
	file, err := os.Open("testdata/onepassword-export.1pux")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	preview, err := PreviewOnePasswordImport(
		file,
		info.Size(),
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Counts != (ImportCounts{
		Logins:      1,
		SecureNotes: 1,
		Folders:     1,
		Generic:     1,
	}) || len(preview.Items) != 4 || len(preview.Errors) != 0 {
		t.Fatalf("fixture preview: %+v", preview)
	}
}

func FuzzPreviewOnePasswordImport(f *testing.F) {
	fixture, err := os.ReadFile("testdata/onepassword-export.1pux")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(fixture)
	f.Add([]byte("not a ZIP archive"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, input []byte) {
		reader := bytes.NewReader(input)
		preview, err := PreviewOnePasswordImport(
			reader,
			reader.Size(),
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

func onePasswordArchive(t *testing.T, data string) *bytes.Reader {
	t.Helper()
	return onePasswordArchiveWithFiles(t, map[string]string{
		"export.attributes": `{
			"version": 3,
			"description": "1Password Unencrypted Export",
			"createdAt": 1785412800
		}`,
		"export.data": data,
	})
}

func onePasswordArchiveWithFiles(
	t *testing.T,
	files map[string]string,
) *bytes.Reader {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.NewReader(buffer.Bytes())
}
