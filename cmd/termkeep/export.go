package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

var errExportUsage = errors.New("invalid export command usage")

type exportFormat string

const (
	exportFormatJSON exportFormat = "json"
	exportFormatCSV  exportFormat = "csv"
)

type exportRequest struct {
	format    exportFormat
	path      string
	confirm   bool
	csvType   client.NativeItemType
	delimiter rune
}

func parseExportRequest(args []string) (exportRequest, error) {
	if len(args) == 0 {
		return exportRequest{}, errExportUsage
	}
	formatName := ""
	if !strings.HasPrefix(args[0], "-") {
		formatName = args[0]
		args = args[1:]
	}
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.StringVar(&formatName, "format", formatName, "json or csv")
	path := fs.String("file", "", "plaintext export destination")
	confirm := fs.Bool(
		"confirm",
		false,
		"confirm that the destination will contain plaintext",
	)
	confirmPlaintext := fs.Bool(
		"confirm-plaintext",
		false,
		"alias for --confirm",
	)
	typeName := fs.String(
		"type",
		"all",
		"CSV Item type: all, login, secure-note, folder, or generic",
	)
	delimiterName := fs.String(
		"delimiter",
		"comma",
		"CSV delimiter: comma, semicolon, tab, or pipe",
	)
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return exportRequest{}, errExportUsage
	}
	format := exportFormat(strings.ToLower(strings.TrimSpace(formatName)))
	if format != exportFormatJSON && format != exportFormatCSV {
		return exportRequest{}, errExportUsage
	}
	pathValue := strings.TrimSpace(*path)
	if pathValue == "" {
		return exportRequest{}, errExportUsage
	}
	itemType, err := parseExportItemType(*typeName)
	if err != nil {
		return exportRequest{}, errExportUsage
	}
	delimiter, err := parseExportDelimiter(*delimiterName)
	if err != nil {
		return exportRequest{}, errExportUsage
	}
	if format == exportFormatJSON && itemType != "" {
		return exportRequest{}, errExportUsage
	}
	return exportRequest{
		format:    format,
		path:      pathValue,
		confirm:   *confirm || *confirmPlaintext,
		csvType:   itemType,
		delimiter: delimiter,
	}, nil
}

func parseExportItemType(raw string) (client.NativeItemType, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "all":
		return "", nil
	case "login":
		return client.NativeItemTypeLogin, nil
	case "secure-note", "secure_note":
		return client.NativeItemTypeSecureNote, nil
	case "folder":
		return client.NativeItemTypeFolder, nil
	case "generic":
		return client.NativeItemTypeGeneric, nil
	default:
		return "", errExportUsage
	}
}

func parseExportDelimiter(raw string) (rune, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "comma":
		return ',', nil
	case "semicolon":
		return ';', nil
	case "tab":
		return '\t', nil
	case "pipe":
		return '|', nil
	default:
		return 0, errExportUsage
	}
}

func runExport(cfg client.Config, args []string) int {
	request, err := parseExportRequest(args)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep export [json|csv] --file FILE "+
				"[--type TYPE] [--delimiter NAME] [--confirm]",
		)
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read terminal session failed")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := runExportAt(
		ctx,
		cfg,
		scope.SocketPath,
		request,
		os.Stdout,
		os.Stderr,
	); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func runExportAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	request exportRequest,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if request.format != exportFormatJSON && request.format != exportFormatCSV {
		return errExportUsage
	}
	if strings.TrimSpace(request.path) == "" {
		return errExportUsage
	}
	if err := exportContextErr(ctx); err != nil {
		return err
	}
	_, cache, err := currentSessionCache(ctx, cfg, socketPath)
	if err != nil {
		return err
	}
	if backupPathOverwritesCache(request.path, cache.Path()) {
		return errors.New("export path must differ from the encrypted cache")
	}
	items, err := localExportItems(ctx, socketPath, cache)
	if err != nil {
		return err
	}
	writePlaintextExportWarning(stderr)
	writeExportPreview(stdout, request, len(items))
	if !request.confirm {
		fmt.Fprintln(stdout, "Preview only; rerun with --confirm to write plaintext.")
		return nil
	}
	if err := exportContextErr(ctx); err != nil {
		return err
	}
	switch request.format {
	case exportFormatJSON:
		err = client.WriteJSONExportFileContext(ctx, request.path, items)
	case exportFormatCSV:
		err = client.WriteCSVExportFileContext(
			ctx,
			request.path,
			items,
			client.CSVExportOptions{
				ItemType:  request.csvType,
				Delimiter: request.delimiter,
			},
		)
	}
	if err != nil {
		return err
	}
	// Keep output useful for scripts without ever printing exported values.
	fmt.Fprintf(stdout, "Export created: %s (%d Items)\n", request.path, len(items))
	if request.format == exportFormatCSV && request.csvType == "" {
		fmt.Fprintln(
			stdout,
			"CSV limitation: arrays, TOTP, history, custom fields, and Generic data are JSON cells; map them explicitly when importing.",
		)
	}
	return nil
}

func exportContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func localExportItems(
	ctx context.Context,
	socketPath string,
	cache *client.Cache,
) ([]client.NativeItem, error) {
	groups, err := cache.ItemHeads()
	if err != nil {
		return nil, errors.New("read encrypted cache failed")
	}
	items := make([]client.NativeItem, 0, len(groups))
	for _, group := range groups {
		for _, revision := range group.Revisions {
			if revision.Deleted || revision.Purged {
				continue
			}
			opened, openErr := session.OpenNativeItem(ctx, socketPath, revision)
			if openErr != nil {
				return nil, errors.New("decrypt cached Item failed")
			}
			items = append(items, opened)
			break
		}
	}
	return items, nil
}

func writePlaintextExportWarning(writer io.Writer) {
	fmt.Fprintln(
		writer,
		"Warning: this export is plaintext. Backups, journaling, copy-on-write snapshots, and filesystem caches may retain it; secure erase is not guaranteed.",
	)
}

func writeExportPreview(writer io.Writer, request exportRequest, count int) {
	format := strings.ToUpper(string(request.format))
	fmt.Fprintf(writer, "%s plaintext export preview\n", format)
	fmt.Fprintf(writer, "Items: %d\n", count)
	if request.format == exportFormatCSV {
		if request.csvType == "" {
			fmt.Fprintln(writer, "CSV type: all native Item types")
		} else {
			fmt.Fprintf(writer, "CSV type: %s\n", request.csvType)
		}
		fmt.Fprintln(
			writer,
			"Non-tabular fields are JSON cells; Generic data is preserved in the data column.",
		)
	}
	fmt.Fprintln(writer, "The destination will contain plaintext secrets.")
}
