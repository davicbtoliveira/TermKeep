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
