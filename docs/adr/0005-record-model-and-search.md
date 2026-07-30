# ADR 0005: Encrypted record model and local fuzzy search

- Status: Accepted
- Date: 2026-07-21
- Updated: 2026-07-30

## Context

The MVP needs useful credential management and imports without exposing searchable metadata or attempting to model every item type from other password managers.

## Decision

The native item types are Login and Secure Note. Login items support name, username, password, multiple URLs, notes, custom fields, TOTP parameters, folder, favorite status, and the five most recent passwords with timestamps. Unsupported imported records are preserved as generic encrypted items instead of losing fields.

Secure Notes contain a required title and sensitive free-form content. They use the same local encrypted cache, immutable revision graph, mutation queue, Trash, synchronization, and explicit Conflict resolution as Logins. Lists expose only decrypted titles in the unlocked Client; Note content appears only when the Item or a Conflict version is opened.

Native type and payload version are authenticated fields inside the encrypted plaintext schema. The outer synchronization contract remains a generic opaque envelope with Item and revision identifiers. Consequently, the Server cannot distinguish a Login from a Secure Note or interpret either payload.

Folders are encrypted organization records with an Item UUID and name. Login and Secure Note payloads contain an optional Folder UUID and a favorite flag inside ciphertext. An Item belongs to at most one Folder. Renaming a Folder changes only its record; moving or favoriting an Item changes only that Item.

The unlocked TUI provides All Items, No Folder, individual Folder, and Favorites views. Removing a Folder requires an explicit warning and queues new revisions that move its assigned Items to No Folder before deleting the Folder record; it never deletes those Items and preserves their favorite status. Folder creation, rename, removal, Item movement, and favorite changes use the same local revision graph, mutation queue, and explicit Conflict workflow as content edits.

The Server cannot distinguish Folder records from content records or inspect Folder names, associations, or favorite status. Folders and favorites are supported; tags, cards, identities, passkeys, SSH-key models, attachments, and shared records are deferred.

When a Login password changes, the Client prepends the replaced non-empty value and its UTC change timestamp to encrypted password history, then retains the five newest entries. Saving the same password creates no history entry. History is masked until an explicit Password History reveal action and can be cleared only after confirmation. It is part of the Login payload and selected Conflict version; it is never added to fuzzy search or automatic password checks.

After unlock, the client builds an in-memory fuzzy index over item name, username, domain/URL, folder, and custom-field names. Passwords, TOTP secrets, and hidden values are never indexed. Notes enter search only through an explicit content-search action. No semantic search index is stored by the server.

Bitwarden, 1Password, and generic CSV exports are parsed locally. The Bitwarden path accepts an unencrypted JSON export bounded to 16 MiB and 10,000 combined records. It maps supported Login fields, Login password history, Login text custom fields, Secure Notes, Folders, favorites, and TOTP to native records. Unsupported item types retain their complete original JSON inside the encrypted Generic Item schema; native Login and Secure Note fields that cannot be represented are listed in the preview.

The 1Password path accepts a version 3 1Password Unencrypted Export (`.1pux`) ZIP archive. It bounds `export.data` to 16 MiB and 10,000 combined Vaults and Items, maps each Vault to a Folder, and maps lossless Login (`001`) and Secure Note (`003`) fields to native records. Unsupported categories and native records with unsupported structured fields retain their complete original Item JSON as Generic Items. Attachment metadata remains in that JSON, while binary `files/` entries are reported in the preview and not imported because attachments remain deferred.

Import previews never mutate the cache or contact the Server. Confirmation encrypts every normalized record through the terminal session agent and queues ordinary offline-first mutations before optional synchronization. Cancellation leaves both cache and Server unchanged. Semantically identical records are retained and renamed with `(Duplicada)`, then `(Duplicada) - 2`, `(Duplicada) - 3`, and so on. Same-name records with different content are not duplicates.

TOTP accepts `otpauth://totp/...` URIs or manual Base32 secret, issuer, account, algorithm, digits, and period parameters; QR decoding is deferred. SHA-1, SHA-256, and SHA-512 are supported with 6- or 8-digit codes. Manual algorithm, digits, and period default to SHA-1, 6, and 30 seconds. URI labels and supported parameters are retained in the encrypted Login payload, while malformed or unsupported input is rejected before a new revision is queued.

Codes are derived locally from RFC 4226/6238 HOTP/TOTP primitives. The unlocked TUI displays the current code and refreshes its expiration window; the CLI requires an explicit `totp --item UUID --stdout` action. Neither the TOTP configuration nor generated codes enter the search index, server requests in plaintext, or audit events.

The random-password generator supports 5–128 characters and independently enabled ASCII uppercase, lowercase, digit, and `!@#$%^&*()-_=+[]{};:,.?/|` special-character sets. Users may require minimum digit and special counts. Exclude-ambiguous removes `I`, `l`, `1`, `O`, `o`, `0`, and `|` from both general and minimum-required pools. Empty character pools, disabled required pools, out-of-range lengths, negative minimums, and combined minimums above length are rejected before generation.

Generation and unbiased shuffling use Go's `crypto/rand`, backed by the Linux operating-system cryptographic random source. The TUI masks generated output until explicit reveal or copy; CLI output requires `generate-password ... --stdout`. Generation is local and produces no server request, synchronization, persistence, audit event, or log entry. Passphrases are deferred.

Pwned-password checks use a configurable k-anonymity-compatible range endpoint directly from the Client. They run only after an explicit action in Password Generator or a Login detail; open, type, generate, save, import, sync, and background work never start them. The Client computes SHA-1 locally, sends only its five-character prefix with response padding requested, and matches the suffix locally. Passwords, full hashes, account emails, Login URLs, and Login domains are never included in the request or logs. The result distinguishes no match, a match and occurrence count, endpoint unavailability, and an invalid response.

The public Pwned Passwords range API is the default. Operators may configure a compatible self-hosted endpoint or disable the feature with `off`. Endpoints require HTTPS outside localhost, use the configured CA trust anchor, reject embedded credentials, query strings, and fragments, and do not follow redirects.

Encrypted portable backup and guarded plaintext JSON/CSV export are supported. Encrypted backups use a distinct backup password.

## Consequences

- Search requires unlocked plaintext in client memory.
- Native-type dispatch and schema-version compatibility remain Client responsibilities.
- Organization views require decrypting Folder records and Item organization fields locally.
- Import files and plaintext exports require prominent deletion/exposure warnings.
- The server synchronizes opaque versioned records and does not understand their schema beyond envelope metadata.
