# TermKeep

TermKeep is a self-hosted, zero-knowledge password vault built for the Linux terminal.
It combines a Go CLI/TUI, offline-first encrypted storage, and a multi-account Go server.

> [!WARNING]
> TermKeep is currently in the design phase. Do not use it to store real credentials yet.

## MVP direction

- Linux-only CLI/TUI and per-terminal session agent
- Email and master-password accounts with OPAQUE authentication
- Client-side encryption and a server that stores only encrypted vault blobs
- Offline unlock, editing, fuzzy search, and eventual synchronization
- Login items, secure notes, folders, favorites, custom fields, and TOTP generation
- Bitwarden, 1Password, and generic CSV imports
- Password generation and optional Pwned Passwords checks
- Multi-account self-hosting with PostgreSQL, Traefik, and Docker Compose

## Design documents

- [MVP product requirements](docs/prd/0001-termkeep-mvp.md)
- [Domain glossary](docs/glossary.md)
- [Architecture Decision Records](docs/adr/README.md)
- [Reference self-hosted deployment](docs/deployment.md)

## Terminal sessions

Login starts a Linux session agent scoped to the current shell and TTY:

```sh
termkeep login --email user@example.com
```

Later logins from that terminal reuse the unlocked session. Another terminal
must authenticate separately. Auto-lock defaults to 15 minutes and can be
selected when creating the session:

```sh
termkeep login --email user@example.com --auto-lock 30
termkeep login --email user@example.com --auto-lock off
```

Values from 1 through 60 are minutes. To change an active session's setting,
log out and create it again. `termkeep logout` clears the current terminal's
unlocked material and removes its local socket. Closing the owning shell or
reaching the inactivity timeout does the same automatically. Local cleanup
always completes, even when the server cannot be reached; TermKeep also makes
a best-effort attempt to revoke the corresponding online session.

Press `s` from the unlocked vault to open Active Sessions. The screen shows
each session's host, creation time, last use, and approximate source IP. Use
`j`/`k` to select a remote session, `x` to revoke it, `r` to refresh, and `v`
to return to the vault. A revoked session is rejected on its next online
operation.

Repeated login failures are delayed after the fifth failure: 1, 5, 10, then
15 minutes, capped at 15 minutes. A successful login or 24 hours without a
failure resets the delay. Limits are isolated by account and source address
and never permanently lock an account.

The agent restricts its Unix socket to the current OS user, checks peer
credentials, disables core dumps, and memory-locks and clears key material on
a best-effort basis. These measures do not protect against root or a
compromised client host.

## Login items

An unlocked online vault lists Login names and usernames. Use `j`/`k` to
select an item and `enter` to open it. Passwords are masked by default; press
`p` in the detail view to reveal or hide the selected password, or `c` to
copy it without revealing it.

Press `c` in the vault to create a Login or `e` on an existing Login to edit
it. The form captures name, username, password, comma-separated URLs, notes,
and comma-separated custom fields in `name=value` form. `enter` advances
through the fields and saves the final field. A successful edit writes the
next item revision; concurrent duplicate saves are ignored while the first
save is running.

Changing a non-empty password stores the replaced value with its UTC change
timestamp inside the encrypted Login, newest first, keeping at most five.
Saving the same password does not add an entry. Historical passwords remain
hidden from the vault list, Login detail, search, and automatic checks. From a
Login detail, press `h` to open Password History; entries remain masked until
`p` reveals the selected one. Press `c` to copy the selected historical
password without revealing it. Press `x` twice to clear the complete history;
the first press shows an irreversible-clear warning.

When offline edits create multiple heads for one Login, the vault marks it as
`Conflict` instead of choosing a winner. Open it to compare every version,
use `j`/`k` and `enter` to keep the selected content, or press `m` to edit and
save a manual merge. Either choice writes a new revision whose parents are all
conflicting heads. Password history belongs to that encrypted version and
follows the same offline mutation and explicit Conflict workflow.

Press `d` in a Login detail view to move it to encrypted Trash. From the vault,
press `t` to open Trash, `j`/`k` to select an item, `r` to restore it, or `v`
to return. Trashed content remains encrypted and restorable for 30 days.
Pressing `x` twice permanently deletes the selected content before that
deadline; the first press displays the irreversible-deletion warning.

After permanent deletion, or the first synchronization after the 30-day
deadline, the server and synchronized cache retain only a technical Tombstone.
They remove the encrypted item content but keep enough opaque revision metadata
to prevent an old client from silently recreating it. A disconnected historic
cache cannot be remotely erased; if it later submits an offline edit, TermKeep
shows an explicit Conflict between that edit and the Tombstone.

Login content is serialized and encrypted on the client with
XChaCha20-Poly1305. Each item UUID gets a derived key and each encryption gets
a random nonce. Account UUID, item UUID, schema version, and revision are
authenticated as associated data. The vault key remains in the per-terminal
session agent; its local IPC exposes only seal/open operations.

The server stores and returns the opaque envelope plus account ownership,
item UUID, schema version, revision number, immutable revision UUID, and
parent revision UUIDs. It cannot inspect or index Login names, usernames,
passwords, password history, URLs, notes, or custom fields.

## Secure Notes

Press `n` from an unlocked vault to create a Secure Note with a required title
and sensitive content. The vault list shows `[Secure Note]` and its title but
never its content. Open the selected Note with `enter`; use `e` to edit it or
`c` to copy its content, and `d` to move it to encrypted Trash.

Secure Notes use the same encrypted cache, immutable revision graph, mutation
queue, synchronization, Trash, and explicit Conflict workflow as Logins. They
remain createable and editable offline. Concurrent versions can be selected
or manually merged without last-write-wins.

Native Item type and payload version live inside authenticated ciphertext.
The Server receives the same opaque envelope and generic Item metadata for
Logins and Secure Notes; it cannot identify titles, content, or native type.

## Secret output and clipboard

Reveal and copy are separate actions. Copying a secret reports the field name,
never the copied value. On Linux, TermKeep uses `wl-copy`/`wl-paste` under
Wayland or `xclip`/`xsel` under X11. It reports a fixed error when no supported
clipboard is available.

Copied content is checked after 30 seconds. TermKeep clears the clipboard only
when it still exactly matches the value TermKeep placed there; content copied
later by the user is left untouched.

CLI secret output requires an unlocked terminal session and an explicit
`--stdout` flag:

```sh
termkeep secret --item ITEM_UUID --field password --stdout
termkeep secret --item ITEM_UUID --field notes --stdout
termkeep secret --item ITEM_UUID --field content --stdout
termkeep secret --item ITEM_UUID --field 'custom:API token' --stdout
```

Account creation also requires `--stdout-recovery-key` before the one-time
Recovery key can be written to stdout:

```sh
termkeep bootstrap --email admin@example.com --stdout-recovery-key
termkeep register --email user@example.com --invite-token TOKEN \
  --stdout-recovery-key
```

## Folders and favorites

Press `f` in the vault to switch the Favorites view on or off. From a Login or
Secure Note detail view, `f` favorites or unfavorites that Item and `o` moves it
to one Folder or to `No Folder`.

Press `o` in the vault to manage Folders. Use `c` to create one, `e` to rename
the selected Folder, or `enter` to navigate its Items. `a` returns to all Items
and `u` shows Items without a Folder. Removing a Folder requires a second `d`;
the warning states how many Items will move to `No Folder`. Those Items remain
live and retain their favorite status.

Folder names are encrypted Folder records in the same local revision graph as
other vault content. An Item's optional Folder UUID and favorite status are
inside its encrypted native payload. Creates, moves, favorite changes,
renames, and removals work offline and synchronize through the durable mutation
queue. Concurrent organization changes remain explicit Conflicts. The Server
sees only generic Item/revision metadata and cannot identify Folder names,
associations, favorite status, or native record types.

## Local fuzzy search

Press `/` from the unlocked vault and type a partial query to search Item
titles, Login usernames, URLs and domains, Folder names, and custom-field
names. Results use deterministic relevance ranking and keep the `★` marker on
favorites. Press `enter` to keep the current results or `esc` to clear the
query.

Login Notes and Secure Note content are excluded from ordinary search. Press
`ctrl+f` to start the separate Notes-content mode. Passwords, password history,
TOTP secrets, and custom-field values are excluded in both modes.

The index is rebuilt from decrypted Items after unlock and remains only in the
TUI process memory. It is never written to the encrypted cache, synchronized,
or sent to the Server.

## Offline use and synchronization

A successful registration or online login authorizes an encrypted local
cache. Later `termkeep login` attempts online authentication first and, when
the Server is unavailable, unlocks that cache locally. A TLS validation
failure never permits offline fallback.

The cache stores the append-only encrypted revision graph, its derived heads,
the encrypted Vault-key wrapper, a change cursor, and stable mutation UUIDs.
It does not persist the master password, plaintext Vault key, plaintext Login
content, or plaintext search indexes. Cache files use mode `0600`, live under
`$XDG_DATA_HOME/termkeep` (default `~/.local/share/termkeep`), and are replaced
atomically after file and directory flushes. Version 1 caches migrate locally
to the revision graph without dropping pending mutations.

Offline creates and edits appear immediately in the TUI and enter the durable
mutation queue. Batch synchronization pushes those mutations and pulls
changes by per-Account cursor. The Server records mutation UUIDs in the same
transaction as revisions, so retrying after a lost response does not create
another revision. Concurrent descendants remain separate heads regardless of
push/pull order; unrelated items in the same batch continue synchronizing.
Incremental changes are retained for 30 days. When a cursor references pruned
history, the Server returns a complete snapshot of current encrypted heads;
the Client replaces synchronized state while preserving local pending
mutations, so missing content is not resurrected.

Synchronization runs when an online Vault opens, after an online mutation,
every 30 seconds while the TUI remains open, with `[y] sync`, or with:

```sh
termkeep sync
```

The TUI and `termkeep status` distinguish `Client offline`, `Server
unavailable`, `TLS validation failed`, and ambiguous `Connection unavailable`
states. Authenticated synchronization failures create fixed operational audit
events without Item IDs, envelopes, or semantic Vault content.

## Activity audit

Press `a` from the unlocked vault to open Activity. Ordinary accounts see
only their own authentication, invitation, registration, and session events.
Administrators can use `g` to switch between their account and all accounts;
the global view identifies the subject Account and actor by UUID. Use `n` for
the next page, `r` to refresh, and `v` to return to the vault.

Audit events contain fixed operational fields only: event type, Account,
actor, session or invitation UUID where applicable, approximate source IP,
and timestamp. They never contain passwords, Recovery keys, vault content,
search terms, TOTP values, invitation tokens, access tokens, or raw OPAQUE
messages.

Events are retained for 90 days by default. Operators can change the positive
day count with `AUDIT_RETENTION_DAYS`; expired events are removed
automatically as activity is recorded or queried.

## License

TermKeep is licensed under the GNU Affero General Public License v3.0 or later.
