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
copy it without revealing it. Press `b` to explicitly check the current
password against the configured Pwned Passwords range endpoint.

Press `c` in the vault to create a Login or `e` on an existing Login to edit
it. The form captures name, username, password, comma-separated URLs, notes,
and comma-separated custom fields in `name=value` form. `enter` advances
through the fields and saves the final field. A successful edit writes the
next item revision; concurrent duplicate saves are ignored while the first
save is running.

From a Login detail, press `t` to configure TOTP. Paste a standard
`otpauth://totp/...` URI in the first field, or leave it empty and enter the
Base32 secret, issuer, account, algorithm, digits, and period manually.
Supported algorithms are SHA-1, SHA-256, and SHA-512; supported code lengths
are 6 and 8 digits. Blank manual algorithm, digits, and period fields default
to SHA-1, 6, and 30 seconds. Invalid input keeps the form open and writes no
revision.

The Login detail generates the current code locally and refreshes its
expiration window every second. The TOTP secret and `otpauth` URI remain
masked in the setup form. The complete supported configuration is serialized
without dropping issuer, account, algorithm, digits, or period, then encrypted
inside the Login payload.

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
passwords, password history, URLs, notes, custom fields, or TOTP
configuration.

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

Current TOTP output uses the same unlocked terminal session and requires the
same explicit stdout opt-in. The client decrypts the Login and generates the
code locally:

```sh
termkeep totp --item ITEM_UUID --stdout
```

Account creation also requires `--stdout-recovery-key` before the one-time
Recovery key can be written to stdout:

```sh
termkeep bootstrap --email admin@example.com --stdout-recovery-key
termkeep register --email user@example.com --invite-token TOKEN \
  --stdout-recovery-key
```

## Password generation

Press `g` from an unlocked vault to open Password Generator. Configure length,
enabled character sets, minimum digit/special counts, and ambiguous-character
exclusion. Generated output is masked; press `p` to reveal, `c` to copy with
the normal 30-second conditional clipboard cleanup, `b` to explicitly check
it against Pwned Passwords, or `g` to regenerate from the same configuration.

Supported length is 5–128. Character sets are:

- Uppercase: `A-Z`
- Lowercase: `a-z`
- Digits: `0-9`
- Special: `!@#$%^&*()-_=+[]{};:,.?/|`

Exclude-ambiguous removes `I`, `l`, `1`, `O`, `o`, `0`, and `|` from every
selected or minimum-required pool. At least one set must remain enabled,
digit/special minimums require their corresponding sets, and combined
minimums cannot exceed length.

CLI defaults are length 20, all four sets enabled, minimum one digit and one
special character, with ambiguous characters allowed. Output requires
explicit opt-in:

```sh
termkeep generate-password --stdout
termkeep generate-password --length 32 \
  --special=false --min-special 0 \
  --min-digits 4 --exclude-ambiguous --stdout
```

Generation uses Go's `crypto/rand`, backed by the Linux operating-system
cryptographic random source. Passwords remain in the client process and
explicit output destination only; generation performs no server request,
synchronization, persistence, audit event, or logging.

## Pwned Passwords checks

Pwned Passwords checks run only after `b` is pressed in Password Generator or
a Login detail. Opening, typing, generating, saving, importing, synchronizing,
or rendering never starts a check, and historical passwords are not checked.

The client computes SHA-1 locally and sends a direct padded range request
containing only the first five hexadecimal hash characters. It never sends or
logs the password, full hash, email, Login URLs, or Login domains. The response
is matched locally and reported as `not found`, `found` with an occurrence
count, `unavailable`, or `invalid response`. A negative result does not prove
that a password is safe.

The default endpoint is `https://api.pwnedpasswords.com/range`. Operators may
select a compatible self-hosted range endpoint or disable checks:

```sh
termkeep --pwned-passwords-url https://pwned.example.com/range
TERMKEEP_PWNED_PASSWORDS_URL=https://pwned.example.com/range termkeep
termkeep --pwned-passwords-url off
```

The endpoint must use HTTPS unless it is on localhost. Redirects, endpoint
credentials, query strings, and fragments are refused. `TERMKEEP_CA_CERT`
also supplies the trust anchor for a self-hosted endpoint.

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

## Bitwarden import

TermKeep accepts an unencrypted Bitwarden JSON export from an unlocked terminal
session. In the TUI, press `i`, enter the local file path, and press `enter`.
The Client displays Login, Secure Note, Folder, and Generic counts together
with unmapped fields and validation errors before writing anything. Press `y`
to confirm or `esc` to cancel.

The equivalent scriptable preview is read-only:

```sh
termkeep import bitwarden --file ./bitwarden-export.json
```

After reviewing it, explicitly confirm:

```sh
termkeep import bitwarden --file ./bitwarden-export.json --confirm
```

The parser accepts at most 16 MiB and 10,000 combined Folders and Items.
Supported Login fields, Login password history, Login text custom fields,
Secure Notes, Folders, favorites, and TOTP become native records. Cards,
identities, SSH keys, and unknown source types become encrypted Generic Items
containing the complete original record. Unsupported fields on otherwise
native Logins and Secure Notes are listed in the preview.

Semantic duplicates are retained. Their names receive `(Duplicada)`, then
`(Duplicada) - 2`, `(Duplicada) - 3`, and so on; a matching title alone is not
a duplicate. Confirmation first queues encrypted local mutations, so an
unavailable Server leaves the import pending for later synchronization. The
source file is opened only by the Client and is never uploaded.

Bitwarden documents JSON exports as plaintext files that contain unencrypted
Vault data. Delete the source securely as soon as it is no longer needed; see
[Bitwarden's export guidance](https://bitwarden.com/help/export-your-data/).

## 1Password import

TermKeep accepts a version 3 1Password Unencrypted Export (`.1pux`) from the
same local preview and confirmation pipeline. Press `i` in the unlocked TUI
and enter the archive path; the Client detects the ZIP archive without sending
it to the Server. For scripts, preview and confirm explicitly:

```sh
termkeep import 1password --file ./account.1pux
termkeep import 1password --file ./account.1pux --confirm
```

Each 1Password Vault becomes an encrypted Folder. Login (`001`) and Secure
Note (`003`) categories become native records when their source fields have
lossless native equivalents. Favorites, URLs, notes, password history, TOTP,
and string-like custom fields are preserved. Other categories and native
records containing unsupported structured fields become encrypted Generic
Items containing the complete original Item JSON.

The Client reads only `export.attributes` and `export.data`, accepts at most
16 MiB of export data and 10,000 combined Vaults and Items, and reports
invalid or incomplete records in the preview. Attachment metadata remains in
its Generic Item, but binary entries under `files/` are not imported and
produce preview warnings because attachments are outside the current record
model. Duplicate naming, read-only cancellation, offline mutation queuing,
and idempotent synchronization are shared with the Bitwarden importer.

1Password exports are unencrypted ZIP archives. Delete the source after
verifying the import; see
[1Password's 1PUX format documentation](https://support.1password.com/1pux-format/).

## Generic CSV import

Generic CSV imports use a two-step, local-only CLI flow. First inspect the
header and the detected UTF-8 encoding and delimiter:

```sh
termkeep import csv --file ./vault.csv
```

If detection is ambiguous, choose `--delimiter comma`, `semicolon`, `tab`, or
`pipe`. Supported encodings are UTF-8 with or without a BOM and can be selected
with `--encoding utf-8` or `utf-8-bom`.

Rerun with an Item type and an explicit decision for every column. Mapping uses
`TARGET=COLUMN`; columns that should not be imported must be named with
`--ignore`:

```sh
termkeep import csv --file ./vault.csv --type login \
  --map name=Title --map username=User --map password=Password \
  --map url=URL --map notes=Notes --ignore "Legacy ID"
```

Login targets are `name`, `username`, `password`, `url` (or repeatable
`url.LABEL` targets), `notes`, `totp`, `favorite`, and `custom.FIELD`. Secure
Note targets are `title`, `content`, and `favorite`. Generic Item targets are
`title`, `favorite`, and `field.FIELD`.
The name/title mapping is required. The final preview reports malformed or
invalid rows by row and blocks confirmation when any error exists:

```sh
termkeep import csv --file ./vault.csv --type login \
  --map name=Title --map username=User --map password=Password \
  --map url=URL --map notes=Notes --ignore "Legacy ID" --confirm
```

Quoting, embedded newlines, Unicode, duplicate naming, cancellation, encrypted
offline mutation queuing, and synchronization follow the same import pipeline
as Bitwarden and 1Password. The Client warns about plaintext before and after
the flow; the CSV contents are never sent to the Server.

## Portable encrypted backup

Backups are self-contained encrypted files. The backup password is requested
and confirmed separately from the master-password flow and must not be the
master password:

```sh
termkeep backup create --file ./termkeep-backup.tkb
```

The header contains only the versioned format and Argon2id parameters; semantic
Vault data, encrypted Item envelopes, pending mutations, revisions, cursor, and
the password envelope are inside authenticated XChaCha20-Poly1305 ciphertext.
Restore always previews first and preserves source conflict heads as separate
records. A same-account restore into an empty cache can retain the complete
encrypted graph; semantic restores give records fresh deterministic IDs,
retain folder links, favorites, password history, TOTP, and Generic Item data,
then queue ordinary
offline-first mutations:

```sh
termkeep backup restore --file ./termkeep-backup.tkb
termkeep backup restore --file ./termkeep-backup.tkb --confirm
```

The destination Vault must already be authorized and unlocked locally; an
empty destination means a provisioned Vault with no cached Items.

Wrong passwords, truncation, tampering, and unsupported format versions fail
before any cache mutation. If synchronization is unavailable, the restored
mutations remain queued locally for a later retry.

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
