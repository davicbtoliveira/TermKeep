package client

import (
	"reflect"
	"testing"
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
