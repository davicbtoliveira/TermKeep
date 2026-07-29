package client

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

func TestSearchIndexRanksPartialTitleMatchesDeterministically(t *testing.T) {
	items := []NativeItem{
		{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
				Name:   "Production database",
			},
		},
		{
			Type: NativeItemTypeSecureNote,
			SecureNote: &SecureNoteItem{
				ItemID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
				Title:  "Production database",
			},
		},
		{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				Name:   "Emergency production access",
			},
		},
		{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
				Name:   "Primary on-call database",
			},
		},
	}

	index := NewSearchIndex(items, nil)
	results := index.Search("prod", SearchModeMetadata)
	got := make([]string, len(results))
	for resultIndex, result := range results {
		got[resultIndex] = result.ItemID
	}
	want := []string{
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		"dddddddd-dddd-4ddd-8ddd-dddddddddddd",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ranked results:\nwant: %v\ngot:  %v", want, got)
	}
}

func TestSearchIndexFindsItemsByNonSecretMetadata(t *testing.T) {
	const folderID = "ffffffff-ffff-4fff-8fff-ffffffffffff"
	index := NewSearchIndex(
		[]NativeItem{{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID:   "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
				Name:     "Database credential",
				Username: "operator@example.com",
				FolderID: folderID,
				URLs: []string{
					"https://db.production.example.com/admin",
				},
				CustomFields: []CustomField{{
					Name:  "Emergency contact",
					Value: "hidden-custom-value",
				}},
			},
		}},
		[]FolderItem{{
			ItemID: folderID,
			Name:   "Infrastructure",
		}},
	)

	for _, query := range []string{
		"operat",
		"prod.example",
		"/admin",
		"infras",
		"emcont",
	} {
		t.Run(query, func(t *testing.T) {
			results := index.Search(query, SearchModeMetadata)
			if len(results) != 1 ||
				results[0].ItemID !=
					"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
				t.Fatalf("results for %q: %+v", query, results)
			}
		})
	}
}

func TestSearchIndexRequiresExplicitModeForNoteContents(t *testing.T) {
	loginID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	noteID := "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	index := NewSearchIndex([]NativeItem{
		{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID:   loginID,
				Name:     "Database",
				Password: "current-password-sentinel",
				PasswordHistory: []PasswordHistoryEntry{{
					Password: "historic-password-sentinel",
				}},
				Notes: "maintenance-window-sentinel",
				CustomFields: []CustomField{{
					Name:  "Recovery contact",
					Value: "custom-value-sentinel",
				}},
			},
		},
		{
			Type: NativeItemTypeSecureNote,
			SecureNote: &SecureNoteItem{
				ItemID:  noteID,
				Title:   "Runbook",
				Content: "recovery-coordinates-sentinel",
			},
		},
	}, nil)

	for _, query := range []string{
		"maintenance-window",
		"recovery-coordinates",
		"current-password",
		"historic-password",
		"custom-value",
	} {
		if results := index.Search(query, SearchModeMetadata); len(results) != 0 {
			t.Fatalf("metadata search exposed %q: %+v", query, results)
		}
	}

	for query, wantItemID := range map[string]string{
		"maintenance-window":   loginID,
		"recovery-coordinates": noteID,
	} {
		results := index.Search(query, SearchModeNoteContents)
		if len(results) != 1 || results[0].ItemID != wantItemID {
			t.Fatalf("Note-content results for %q: %+v", query, results)
		}
	}
	for _, query := range []string{
		"current-password",
		"historic-password",
		"custom-value",
	} {
		if results := index.Search(
			query,
			SearchModeNoteContents,
		); len(results) != 0 {
			t.Fatalf("Note-content search exposed %q: %+v", query, results)
		}
	}
}

func TestRepresentativeVaultSearchMeetsLatencyBudget(t *testing.T) {
	const (
		itemCount    = 10_000
		targetID     = "item-04321"
		buildBudget  = 500 * time.Millisecond
		searchBudget = 250 * time.Millisecond
	)
	folders := make([]FolderItem, 100)
	for folderIndex := range folders {
		folders[folderIndex] = FolderItem{
			ItemID: fmt.Sprintf("folder-%03d", folderIndex),
			Name:   fmt.Sprintf("Team %03d infrastructure", folderIndex),
		}
	}
	items := make([]NativeItem, 0, itemCount+1)
	for itemIndex := range itemCount {
		itemID := fmt.Sprintf("item-%05d", itemIndex)
		folderID := fmt.Sprintf("folder-%03d", itemIndex%len(folders))
		if itemIndex%10 == 0 {
			items = append(items, NativeItem{
				Type: NativeItemTypeSecureNote,
				SecureNote: &SecureNoteItem{
					ItemID:   itemID,
					Title:    fmt.Sprintf("Runbook %05d", itemIndex),
					Content:  fmt.Sprintf("note-secret-%05d", itemIndex),
					FolderID: folderID,
				},
			})
			continue
		}
		name := fmt.Sprintf("Service %05d", itemIndex)
		if itemID == targetID {
			name = "Production database"
		}
		items = append(items, NativeItem{
			Type: NativeItemTypeLogin,
			Login: &LoginItem{
				ItemID:   itemID,
				Name:     name,
				Username: fmt.Sprintf("operator-%05d@example.com", itemIndex),
				Password: fmt.Sprintf("password-secret-%05d", itemIndex),
				FolderID: folderID,
				URLs: []string{
					fmt.Sprintf("https://service-%05d.example.com", itemIndex),
				},
				Notes: fmt.Sprintf("login-note-secret-%05d", itemIndex),
				CustomFields: []CustomField{{
					Name:  "Environment",
					Value: fmt.Sprintf("custom-secret-%05d", itemIndex),
				}},
			},
		})
	}
	items = append(items, NativeItem{
		Type: NativeItemTypeLogin,
		Login: &LoginItem{
			ItemID: "item-secondary",
			Name:   "Emergency production access",
		},
	})

	started := time.Now()
	index := NewSearchIndex(items, folders)
	if elapsed := time.Since(started); elapsed > buildBudget {
		t.Fatalf("build took %s; budget %s", elapsed, buildBudget)
	}

	started = time.Now()
	results := index.Search("prod", SearchModeMetadata)
	if elapsed := time.Since(started); elapsed > searchBudget {
		t.Fatalf("search took %s; budget %s", elapsed, searchBudget)
	}
	if len(results) < 2 ||
		results[0].ItemID != targetID ||
		results[1].ItemID != "item-secondary" {
		t.Fatalf("representative ranking: %+v", results)
	}
	for _, query := range []string{
		"password-secret-04321",
		"custom-secret-04321",
		"login-note-secret-04321",
	} {
		if results := index.Search(
			query,
			SearchModeMetadata,
		); len(results) != 0 {
			t.Fatalf("metadata search exposed %q: %+v", query, results)
		}
	}
}
