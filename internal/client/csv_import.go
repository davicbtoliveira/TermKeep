package client

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxCSVImportSize = 16 << 20
const maxCSVImportRecords = 10_000

var ErrInvalidCSVExport = errors.New("invalid CSV export")
var ErrCSVExportTooLarge = errors.New("CSV export exceeds 16 MiB")
var ErrCSVExportTooManyRecords = errors.New(
	"CSV export exceeds 10000 records",
)
var ErrCSVDelimiterRequired = errors.New(
	"CSV delimiter is ambiguous; choose one explicitly",
)

type CSVImportOptions struct {
	Type           NativeItemType
	Mapping        map[string]string
	IgnoredColumns []string
	Delimiter      rune
	Encoding       string
}

type CSVImportInspection struct {
	Columns   []string
	Delimiter rune
	Encoding  string
}

func InspectCSVImport(
	reader io.Reader,
	delimiter rune,
	encoding string,
) (CSVImportInspection, error) {
	input, normalizedEncoding, err := readCSVImport(reader, encoding)
	if err != nil {
		return CSVImportInspection{}, err
	}
	defer clearBytes(input)
	delimiter, err = csvImportDelimiter(input, delimiter)
	if err != nil {
		return CSVImportInspection{}, err
	}
	parser := newCSVReader(input, delimiter)
	header, err := parser.Read()
	if err != nil {
		return CSVImportInspection{},
			fmt.Errorf("%w: read header", ErrInvalidCSVExport)
	}
	if err := validateCSVHeader(header); err != nil {
		return CSVImportInspection{}, err
	}
	return CSVImportInspection{
		Columns:   append([]string(nil), header...),
		Delimiter: delimiter,
		Encoding:  normalizedEncoding,
	}, nil
}

func PreviewCSVImport(
	reader io.Reader,
	options CSVImportOptions,
	existing []NativeItem,
) (ImportPreview, error) {
	input, _, err := readCSVImport(reader, options.Encoding)
	if err != nil {
		return ImportPreview{}, err
	}
	defer clearBytes(input)
	delimiter, err := csvImportDelimiter(input, options.Delimiter)
	if err != nil {
		return ImportPreview{}, err
	}
	parser := newCSVReader(input, delimiter)
	header, err := parser.Read()
	if err != nil {
		return ImportPreview{},
			fmt.Errorf("%w: read header", ErrInvalidCSVExport)
	}
	if err := validateCSVHeader(header); err != nil {
		return ImportPreview{}, err
	}
	if err := validateCSVMapping(header, options); err != nil {
		return ImportPreview{}, err
	}

	preview := ImportPreview{}
	duplicateCounts := importDuplicateCounts(existing)
	for rowNumber := 1; ; rowNumber++ {
		record, readErr := parser.Read()
		if errors.Is(readErr, io.EOF) {
			break
		}
		if rowNumber > maxCSVImportRecords {
			return ImportPreview{}, ErrCSVExportTooManyRecords
		}
		if readErr != nil {
			preview.Errors = append(preview.Errors, ImportIssue{
				Item:    rowNumber,
				Message: csvRowError(readErr),
			})
			continue
		}
		item, issue, err := csvImportItem(header, record, options)
		if err != nil {
			return ImportPreview{}, err
		}
		if issue != nil {
			issue.Item = rowNumber
			preview.Errors = append(preview.Errors, *issue)
			continue
		}
		nameImportDuplicate(&item, duplicateCounts)
		preview.Items = append(preview.Items, item)
		switch item.Type {
		case NativeItemTypeLogin:
			preview.Counts.Logins++
		case NativeItemTypeSecureNote:
			preview.Counts.SecureNotes++
		case NativeItemTypeGeneric:
			preview.Counts.Generic++
		}
	}
	return preview, nil
}

func readCSVImport(
	reader io.Reader,
	encoding string,
) ([]byte, string, error) {
	if reader == nil {
		return nil, "", ErrInvalidCSVExport
	}
	input, err := io.ReadAll(io.LimitReader(reader, maxCSVImportSize+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: read input", ErrInvalidCSVExport)
	}
	if len(input) > maxCSVImportSize {
		clearBytes(input)
		return nil, "", ErrCSVExportTooLarge
	}
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	hasBOM := bytes.HasPrefix(input, []byte{0xef, 0xbb, 0xbf})
	switch encoding {
	case "", "auto":
	case "utf-8", "utf8":
		if hasBOM {
			input = input[3:]
		}
	case "utf-8-bom":
		if !hasBOM {
			clearBytes(input)
			return nil, "", fmt.Errorf(
				"%w: expected UTF-8 BOM",
				ErrInvalidCSVExport,
			)
		}
		input = input[3:]
	default:
		clearBytes(input)
		return nil, "", fmt.Errorf(
			"%w: unsupported encoding %q",
			ErrInvalidCSVExport,
			encoding,
		)
	}
	if hasBOM && (encoding == "" || encoding == "auto") {
		input = input[3:]
	}
	if !utf8.Valid(input) {
		clearBytes(input)
		return nil, "", fmt.Errorf(
			"%w: encoding is not UTF-8; choose a supported encoding explicitly",
			ErrInvalidCSVExport,
		)
	}
	if hasBOM {
		return input, "utf-8-bom", nil
	}
	return input, "utf-8", nil
}

func csvImportDelimiter(input []byte, delimiter rune) (rune, error) {
	if delimiter != 0 {
		if !validCSVDelimiter(delimiter) {
			return 0, fmt.Errorf(
				"%w: unsupported delimiter",
				ErrInvalidCSVExport,
			)
		}
		return delimiter, nil
	}
	var detected []rune
	for _, candidate := range []rune{',', ';', '\t', '|'} {
		parser := newCSVReader(input, candidate)
		header, err := parser.Read()
		if err == nil && len(header) > 1 {
			detected = append(detected, candidate)
		}
	}
	if len(detected) != 1 {
		return 0, ErrCSVDelimiterRequired
	}
	return detected[0], nil
}

func validCSVDelimiter(delimiter rune) bool {
	return delimiter == ',' ||
		delimiter == ';' ||
		delimiter == '\t' ||
		delimiter == '|'
}

func newCSVReader(input []byte, delimiter rune) *csv.Reader {
	parser := csv.NewReader(bytes.NewReader(input))
	parser.Comma = delimiter
	parser.FieldsPerRecord = 0
	return parser
}

func validateCSVHeader(header []string) error {
	if len(header) == 0 {
		return fmt.Errorf("%w: missing header", ErrInvalidCSVExport)
	}
	seen := make(map[string]struct{}, len(header))
	for index := range header {
		header[index] = strings.TrimSpace(header[index])
		if header[index] == "" {
			return fmt.Errorf(
				"%w: empty header column",
				ErrInvalidCSVExport,
			)
		}
		if _, exists := seen[header[index]]; exists {
			return fmt.Errorf(
				"%w: duplicate header %q",
				ErrInvalidCSVExport,
				header[index],
			)
		}
		seen[header[index]] = struct{}{}
	}
	return nil
}

func validateCSVMapping(
	header []string,
	options CSVImportOptions,
) error {
	required := ""
	switch options.Type {
	case NativeItemTypeLogin:
		required = "name"
	case NativeItemTypeSecureNote, NativeItemTypeGeneric:
		required = "title"
	default:
		return fmt.Errorf("%w: unsupported Item type", ErrInvalidCSVExport)
	}
	columns := make(map[string]struct{}, len(header))
	for _, column := range header {
		columns[column] = struct{}{}
	}
	decided := make(map[string]struct{}, len(header))
	for target, column := range options.Mapping {
		if !validCSVTarget(options.Type, target) {
			return fmt.Errorf(
				"%w: unsupported mapping target %q",
				ErrInvalidCSVExport,
				target,
			)
		}
		if _, exists := columns[column]; !exists {
			return fmt.Errorf(
				"%w: unknown column %q",
				ErrInvalidCSVExport,
				column,
			)
		}
		if _, exists := decided[column]; exists {
			return fmt.Errorf(
				"%w: column %q mapped more than once",
				ErrInvalidCSVExport,
				column,
			)
		}
		decided[column] = struct{}{}
	}
	if _, exists := options.Mapping[required]; !exists {
		return fmt.Errorf(
			"%w: %s mapping is required",
			ErrInvalidCSVExport,
			required,
		)
	}
	for _, column := range options.IgnoredColumns {
		if _, exists := columns[column]; !exists {
			return fmt.Errorf(
				"%w: unknown ignored column %q",
				ErrInvalidCSVExport,
				column,
			)
		}
		if _, exists := decided[column]; exists {
			return fmt.Errorf(
				"%w: column %q is both mapped and ignored",
				ErrInvalidCSVExport,
				column,
			)
		}
		decided[column] = struct{}{}
	}
	for _, column := range header {
		if _, exists := decided[column]; !exists {
			return fmt.Errorf(
				"%w: column %q must be mapped or ignored",
				ErrInvalidCSVExport,
				column,
			)
		}
	}
	return nil
}

func validCSVTarget(itemType NativeItemType, target string) bool {
	switch itemType {
	case NativeItemTypeLogin:
		switch target {
		case "name", "username", "password", "url", "notes",
			"totp", "favorite":
			return true
		}
		return prefixedCSVTarget(target, "url.") ||
			prefixedCSVTarget(target, "custom.")
	case NativeItemTypeSecureNote:
		return target == "title" ||
			target == "content" ||
			target == "favorite"
	case NativeItemTypeGeneric:
		return target == "title" ||
			target == "favorite" ||
			prefixedCSVTarget(target, "field.")
	default:
		return false
	}
}

func prefixedCSVTarget(target string, prefix string) bool {
	return strings.HasPrefix(target, prefix) &&
		strings.TrimSpace(strings.TrimPrefix(target, prefix)) != ""
}

func csvImportItem(
	header []string,
	record []string,
	options CSVImportOptions,
) (NativeItem, *ImportIssue, error) {
	values := make(map[string]string, len(header))
	for index, column := range header {
		values[column] = record[index]
	}
	value := func(target string) string {
		return values[options.Mapping[target]]
	}
	itemID, err := NewItemID()
	if err != nil {
		return NativeItem{}, nil, err
	}
	favorite, issue := csvFavorite(value("favorite"))
	if issue != nil {
		issue.Field = options.Mapping["favorite"]
		return NativeItem{}, issue, nil
	}
	switch options.Type {
	case NativeItemTypeLogin:
		name := strings.TrimSpace(value("name"))
		if name == "" {
			return NativeItem{}, &ImportIssue{
				Field:   options.Mapping["name"],
				Message: "Login name is required",
			}, nil
		}
		var totp *TOTPConfig
		if raw := strings.TrimSpace(value("totp")); raw != "" {
			parsed, err := ParseTOTPURI(raw)
			if err != nil {
				return NativeItem{}, &ImportIssue{
					Field:   options.Mapping["totp"],
					Message: "invalid TOTP configuration",
				}, nil
			}
			totp = &parsed
		}
		targets := sortedCSVTargets(options.Mapping)
		customFields := make([]CustomField, 0)
		for _, target := range targets {
			if strings.HasPrefix(target, "custom.") {
				customFields = append(customFields, CustomField{
					Name:  strings.TrimPrefix(target, "custom."),
					Value: values[options.Mapping[target]],
				})
			}
		}
		var urls []string
		for _, target := range targets {
			if target != "url" &&
				!strings.HasPrefix(target, "url.") {
				continue
			}
			if raw := strings.TrimSpace(value(target)); raw != "" {
				urls = append(urls, raw)
			}
		}
		login := LoginItem{
			ItemID:       itemID,
			Name:         name,
			Username:     strings.TrimSpace(value("username")),
			Password:     value("password"),
			Favorite:     favorite,
			URLs:         urls,
			Notes:        value("notes"),
			CustomFields: customFields,
			TOTP:         totp,
		}
		return NativeItem{
			Type:  NativeItemTypeLogin,
			Login: &login,
		}, nil, nil
	case NativeItemTypeSecureNote:
		title := strings.TrimSpace(value("title"))
		if title == "" {
			return NativeItem{}, &ImportIssue{
				Field:   options.Mapping["title"],
				Message: "Secure Note title is required",
			}, nil
		}
		note := SecureNoteItem{
			ItemID:   itemID,
			Title:    title,
			Content:  value("content"),
			Favorite: favorite,
		}
		return NativeItem{
			Type:       NativeItemTypeSecureNote,
			SecureNote: &note,
		}, nil, nil
	case NativeItemTypeGeneric:
		title := strings.TrimSpace(value("title"))
		if title == "" {
			return NativeItem{}, &ImportIssue{
				Field:   options.Mapping["title"],
				Message: "Generic Item title is required",
			}, nil
		}
		data := make(map[string]string)
		for target, column := range options.Mapping {
			if strings.HasPrefix(target, "field.") {
				data[strings.TrimPrefix(target, "field.")] =
					values[column]
			}
		}
		encoded, err := json.Marshal(data)
		if err != nil {
			return NativeItem{}, nil, err
		}
		generic := GenericItem{
			ItemID:     itemID,
			Title:      title,
			Source:     "csv",
			SourceType: "generic",
			Favorite:   favorite,
			Data:       encoded,
		}
		return NativeItem{
			Type:    NativeItemTypeGeneric,
			Generic: &generic,
		}, nil, nil
	default:
		return NativeItem{}, nil, ErrInvalidCSVExport
	}
}

func sortedCSVTargets(mapping map[string]string) []string {
	targets := make([]string, 0, len(mapping))
	for target := range mapping {
		targets = append(targets, target)
	}
	sort.Strings(targets)
	return targets
}

func csvFavorite(raw string) (bool, *ImportIssue) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return false, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, &ImportIssue{
			Message: "favorite must be true or false",
		}
	}
	return value, nil
}

func csvRowError(err error) string {
	var parseErr *csv.ParseError
	if errors.As(err, &parseErr) {
		return fmt.Sprintf(
			"invalid CSV row near input line %d: %s",
			parseErr.Line,
			parseErr.Err,
		)
	}
	return "invalid CSV row"
}
