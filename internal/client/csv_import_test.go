package client

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestPreviewCSVImportMapsLoginColumnsExplicitly(t *testing.T) {
	fixture, err := os.ReadFile("testdata/csv-import.csv")
	if err != nil {
		t.Fatal(err)
	}
	source := "\ufeff" + string(fixture)

	preview, err := PreviewCSVImport(
		strings.NewReader(source),
		CSVImportOptions{
			Type: NativeItemTypeLogin,
			Mapping: map[string]string{
				"name":     "Title",
				"username": "User",
				"password": "Password",
				"url":      "URL",
				"notes":    "Notes",
			},
			IgnoredColumns: []string{"Unused"},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Errors) != 0 ||
		preview.Counts.Logins != 1 ||
		len(preview.Items) != 1 {
		t.Fatalf("preview: %+v", preview)
	}
	login := preview.Items[0].Login
	if login == nil ||
		login.Name != "Produção" ||
		login.Username != "davi@example.com" ||
		login.Password != "segredo" ||
		len(login.URLs) != 1 ||
		login.URLs[0] != "https://example.com" ||
		login.Notes != "primeira linha\nsegunda linha" {
		t.Fatalf("login: %+v", login)
	}
}

func TestPreviewCSVImportReportsInvalidRowsWithoutPartialSilence(
	t *testing.T,
) {
	source := "Title,User\nValid,one@example.com\nBroken\n" +
		"Other,two@example.com\n"
	preview, err := PreviewCSVImport(
		strings.NewReader(source),
		CSVImportOptions{
			Type: NativeItemTypeLogin,
			Mapping: map[string]string{
				"name":     "Title",
				"username": "User",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 2 ||
		len(preview.Errors) != 1 ||
		preview.Errors[0].Item != 2 ||
		!strings.Contains(preview.Errors[0].Message, "input line 3") {
		t.Fatalf("preview: %+v", preview)
	}
}

func TestPreviewCSVImportUsesCommonDuplicateNaming(t *testing.T) {
	source := "Title,User,Password\nFirst,a@example.com,secret\n" +
		"Second,a@example.com,secret\n"
	preview, err := PreviewCSVImport(
		strings.NewReader(source),
		CSVImportOptions{
			Type: NativeItemTypeLogin,
			Mapping: map[string]string{
				"name":     "Title",
				"username": "User",
				"password": "Password",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Items) != 2 ||
		preview.Items[0].Login.Name != "First" ||
		preview.Items[1].Login.Name != "Second (Duplicada)" {
		t.Fatalf("duplicate names: %+v", preview.Items)
	}
}

func TestInspectCSVImportRequiresExplicitAmbiguousDelimiter(t *testing.T) {
	if _, err := InspectCSVImport(
		strings.NewReader("Only\nvalue\n"),
		0,
		"",
	); !errors.Is(err, ErrCSVDelimiterRequired) {
		t.Fatalf("got %v", err)
	}
	inspection, err := InspectCSVImport(
		strings.NewReader("Only\nvalue\n"),
		',',
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(inspection.Columns) != 1 ||
		inspection.Columns[0] != "Only" ||
		inspection.Encoding != "utf-8" {
		t.Fatalf("inspection: %+v", inspection)
	}
}

func TestPreviewCSVImportMapsSecureNoteAndGenericItem(t *testing.T) {
	note, err := PreviewCSVImport(
		strings.NewReader("Title|Body\nRunbook|Use café\n"),
		CSVImportOptions{
			Type:      NativeItemTypeSecureNote,
			Delimiter: '|',
			Mapping: map[string]string{
				"title":   "Title",
				"content": "Body",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(note.Items) != 1 ||
		note.Items[0].SecureNote.Content != "Use café" {
		t.Fatalf("note: %+v", note)
	}

	generic, err := PreviewCSVImport(
		strings.NewReader("Title\tAccount\nCard\t1234\n"),
		CSVImportOptions{
			Type:      NativeItemTypeGeneric,
			Delimiter: '\t',
			Mapping: map[string]string{
				"title":         "Title",
				"field.account": "Account",
			},
		},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(generic.Items) != 1 ||
		string(generic.Items[0].Generic.Data) != `{"account":"1234"}` {
		t.Fatalf("generic: %+v", generic)
	}
}

func FuzzPreviewCSVImport(f *testing.F) {
	for _, seed := range []struct {
		source    string
		delimiter string
	}{
		{"Title,Notes\nEntry,\"line one\nline two\"\n", ","},
		{"Title,Notes\nUnicode,ação 日本語\n", ","},
		{"Title;Notes\nEntry;value\n", ";"},
		{"Title\tNotes\nEntry\tvalue\n", "\t"},
		{"Title|Notes\nEntry|value\n", "|"},
		{"Title,Notes\nEntry,\"unterminated\n", ","},
	} {
		f.Add(seed.source, seed.delimiter)
	}
	f.Fuzz(func(t *testing.T, source string, rawDelimiter string) {
		delimiter := ','
		switch rawDelimiter {
		case ";":
			delimiter = ';'
		case "\t":
			delimiter = '\t'
		case "|":
			delimiter = '|'
		}
		_, _ = PreviewCSVImport(
			strings.NewReader(source),
			CSVImportOptions{
				Type:      NativeItemTypeSecureNote,
				Delimiter: delimiter,
				Mapping: map[string]string{
					"title":   "Title",
					"content": "Notes",
				},
			},
			nil,
		)
	})
}
