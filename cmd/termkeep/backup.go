package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/davicbtoliveira/TermKeep/internal/client"
	"github.com/davicbtoliveira/TermKeep/internal/session"
)

var errBackupUsage = errors.New("invalid backup command usage")

type backupAction string

const (
	backupActionCreate  backupAction = "create"
	backupActionRestore backupAction = "restore"
)

type backupRequest struct {
	action  backupAction
	path    string
	confirm bool
}

func currentSessionCache(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
) (session.Info, *client.Cache, error) {
	info, err := session.Status(ctx, socketPath)
	if err != nil {
		return session.Info{}, nil, errors.New("read unlocked session failed")
	}
	cache, err := client.OpenCache(cfg, info.Email)
	if err != nil {
		return session.Info{}, nil, errors.New("open encrypted cache failed")
	}
	return info, cache, nil
}

func parseBackupRequest(args []string) (backupRequest, error) {
	if len(args) == 0 {
		return backupRequest{}, errBackupUsage
	}
	action := backupAction(strings.ToLower(strings.TrimSpace(args[0])))
	if action != backupActionCreate && action != backupActionRestore {
		return backupRequest{}, errBackupUsage
	}
	fs := flag.NewFlagSet(
		"backup "+string(action),
		flag.ContinueOnError,
	)
	path := fs.String("file", "", "portable backup file")
	confirm := fs.Bool(
		"confirm",
		false,
		"confirm restore after preview",
	)
	if err := fs.Parse(args[1:]); err != nil ||
		strings.TrimSpace(*path) == "" || fs.NArg() != 0 ||
		(action == backupActionCreate && *confirm) {
		return backupRequest{}, errBackupUsage
	}
	return backupRequest{
		action:  action,
		path:    strings.TrimSpace(*path),
		confirm: *confirm,
	}, nil
}

func runBackup(cfg client.Config, args []string) int {
	request, err := parseBackupRequest(args)
	if err != nil {
		fmt.Fprintln(
			os.Stderr,
			"usage: termkeep backup create|restore --file FILE [--confirm]",
		)
		return exitUsageFailure
	}
	scope, err := session.CurrentScope(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: read terminal session failed")
		return 1
	}
	password, err := readMasterPassword("Backup password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	backupPassword := []byte(password)
	defer clearPassword(backupPassword)
	if request.action == backupActionCreate {
		confirmation, confirmErr := readMasterPassword(
			"Confirm backup password: ",
		)
		if confirmErr != nil {
			fmt.Fprintln(os.Stderr, "error:", confirmErr)
			return 1
		}
		if password != confirmation {
			fmt.Fprintln(os.Stderr, "error: backup passwords do not match")
			return 1
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var runErr error
	switch request.action {
	case backupActionCreate:
		runErr = runBackupCreateAt(
			ctx,
			cfg,
			scope.SocketPath,
			request,
			backupPassword,
			os.Stdout,
		)
	case backupActionRestore:
		runErr = runBackupRestoreAt(
			ctx,
			cfg,
			scope.SocketPath,
			request,
			backupPassword,
			os.Stdout,
			os.Stderr,
		)
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "error:", runErr)
		return 1
	}
	return 0
}

func runBackupCreateAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	request backupRequest,
	backupPassword []byte,
	stdout io.Writer,
) error {
	if request.action != backupActionCreate {
		return errBackupUsage
	}
	_, cache, err := currentSessionCache(ctx, cfg, socketPath)
	if err != nil {
		return err
	}
	if backupPathOverwritesCache(request.path, cache.Path()) {
		return errors.New("backup path must differ from the encrypted cache")
	}
	if vaultKey, unlockErr := cache.Unlock(backupPassword); unlockErr == nil {
		clearPassword(vaultKey)
		return errors.New(
			"backup password must differ from the master password",
		)
	}
	snapshot, err := cache.PortableBackupSnapshot()
	if err != nil {
		return err
	}
	items, err := nativeItemsFromHeads(
		ctx,
		socketPath,
		snapshot.ItemHeads(),
		"decrypt cached Item failed",
	)
	if err != nil {
		return err
	}
	if items == nil {
		items = []client.NativeItem{}
	}
	if err := cache.WritePortableBackupFileFromSnapshot(
		request.path,
		backupPassword,
		snapshot,
		items,
	); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Backup created: %s\n", request.path)
	return nil
}

func backupPathOverwritesCache(backupPath, cachePath string) bool {
	backupAbsolute, backupErr := filepath.Abs(backupPath)
	cacheAbsolute, cacheErr := filepath.Abs(cachePath)
	if backupErr == nil && cacheErr == nil && backupAbsolute == cacheAbsolute {
		return true
	}
	backupInfo, backupErr := os.Stat(backupPath)
	cacheInfo, cacheErr := os.Stat(cachePath)
	return backupErr == nil && cacheErr == nil && os.SameFile(backupInfo, cacheInfo)
}

func runBackupRestoreAt(
	ctx context.Context,
	cfg client.Config,
	socketPath string,
	request backupRequest,
	backupPassword []byte,
	stdout io.Writer,
	stderr io.Writer,
) error {
	if request.action != backupActionRestore {
		return errBackupUsage
	}
	info, cache, err := currentSessionCache(ctx, cfg, socketPath)
	if err != nil {
		return err
	}
	backup, err := client.ReadPortableBackupFile(
		request.path,
		backupPassword,
	)
	if err != nil {
		return err
	}
	if backup.FormatVersion == 0 ||
		(backup.FormatVersion == 1 && backup.AccountID != info.AccountID) ||
		(backup.FormatVersion >= 2 && backup.Items == nil &&
			backup.AccountID != info.AccountID && len(backup.Revisions) != 0) {
		return errors.New(
			"backup lacks portable item data for the destination account",
		)
	}
	stateMatches, err := cache.PortableStateMatches(backup)
	if err != nil {
		return err
	}
	restoredMarker, err := cache.PortableRestoreMarker(backup)
	if err != nil {
		return err
	}
	existing, err := cachedNativeItems(ctx, cache, socketPath)
	if err != nil {
		return err
	}
	var items []client.NativeItem
	if !stateMatches {
		items, err = nativeItemsFromPortableBackup(
			ctx,
			socketPath,
			backup,
		)
		if err != nil {
			return err
		}
	}
	preview, err := client.PreparePortableBackupImportWithNamespace(
		items,
		existing,
		backup.Fingerprint,
	)
	if err != nil {
		return err
	}
	if restoredMarker && !stateMatches {
		preview.Errors = append(preview.Errors, client.ImportIssue{
			Item:    1,
			Field:   "backup",
			Message: "this backup was restored before, but the local graph changed; resolve the conflict before retrying",
		})
	}
	writeBackupRestorePreview(stdout, backup, preview)
	if !request.confirm {
		fmt.Fprintln(stdout, "Preview only; rerun with --confirm to restore.")
		return nil
	}
	if len(preview.Errors) != 0 {
		return errors.New("backup preview contains errors; restore canceled")
	}
	if restoredGraph, err := tryRestorePortableState(
		ctx,
		cache,
		socketPath,
		info.AccountID,
		backup,
	); err != nil {
		return err
	} else if !restoredGraph {
		if err := queueImportWithNamespace(
			ctx,
			cache,
			socketPath,
			preview.Items,
			backup.Fingerprint,
		); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "Restored locally: %d\n", len(preview.Items))
	token, tokenErr := session.AccessToken(ctx, socketPath)
	if tokenErr == nil && len(token) > 0 {
		defer clearPassword(token)
		if err := client.SyncCache(
			ctx,
			cfg,
			string(token),
			cache,
		); err != nil {
			fmt.Fprintln(
				stderr,
				"Warning: synchronization failed; "+
					"restore remains queued locally.",
			)
		}
	}
	return nil
}

func nativeItemsFromPortableBackup(
	ctx context.Context,
	socketPath string,
	backup client.PortableBackup,
) ([]client.NativeItem, error) {
	if backup.FormatVersion >= 2 {
		return append([]client.NativeItem(nil), backup.Items...), nil
	}
	if backup.Items != nil {
		return append([]client.NativeItem(nil), backup.Items...), nil
	}
	if backup.AccountID == "" {
		return nil, errors.New("backup does not contain portable item data")
	}
	return nativeItemsFromHeads(
		ctx,
		socketPath,
		backup.ItemHeads(),
		"decrypt backup Item failed",
	)
}

func tryRestorePortableState(
	ctx context.Context,
	cache *client.Cache,
	socketPath string,
	accountID string,
	backup client.PortableBackup,
) (bool, error) {
	if backup.AccountID != accountID {
		return false, nil
	}
	empty, err := cache.IsEmpty()
	if err != nil || !empty {
		return false, err
	}
	if backup.Items != nil && len(backup.Items) > 0 &&
		len(backup.ItemHeads()) == 0 {
		return false, nil
	}
	// Only reuse the encrypted graph when the current Vault key can open its
	// active heads. Otherwise fall back to semantic import with fresh envelopes.
	if _, err := nativeItemsFromHeads(
		ctx,
		socketPath,
		backup.ItemHeads(),
		"decrypt backup Item failed",
	); err != nil {
		return false, nil
	}
	if err := cache.RestorePortableState(backup); err != nil {
		return false, err
	}
	return true, nil
}

func writeBackupRestorePreview(
	writer io.Writer,
	backup client.PortableBackup,
	preview client.ImportPreview,
) {
	fmt.Fprintln(writer, "Portable backup restore preview")
	fmt.Fprintf(writer, "Logins: %d\n", preview.Counts.Logins)
	fmt.Fprintf(writer, "Secure Notes: %d\n", preview.Counts.SecureNotes)
	fmt.Fprintf(writer, "Folders: %d\n", preview.Counts.Folders)
	fmt.Fprintf(writer, "Generic: %d\n", preview.Counts.Generic)
	fmt.Fprintf(writer, "Conflicts preserved: %d\n", backup.ConflictCount())
	fmt.Fprintf(writer, "Errors: %d\n", len(preview.Errors))
	for _, issue := range preview.Errors {
		fmt.Fprintf(
			writer,
			"Error Item %d %s: %s\n",
			issue.Item,
			issue.Field,
			issue.Message,
		)
	}
}
