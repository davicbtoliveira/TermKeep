# ADR 0005: Encrypted record model and local fuzzy search

- Status: Accepted
- Date: 2026-07-21
- Updated: 2026-07-28

## Context

The MVP needs useful credential management and imports without exposing searchable metadata or attempting to model every item type from other password managers.

## Decision

The native item types are Login and Secure Note. Login items support name, username, password, multiple URLs, notes, custom fields, TOTP parameters, folder, favorite status, and the five most recent passwords with timestamps. Unsupported imported records are preserved as generic encrypted items instead of losing fields.

Secure Notes contain a required title and sensitive free-form content. They use the same local encrypted cache, immutable revision graph, mutation queue, Trash, synchronization, and explicit Conflict resolution as Logins. Lists expose only decrypted titles in the unlocked Client; Note content appears only when the Item or a Conflict version is opened.

Native type and payload version are authenticated fields inside the encrypted plaintext schema. The outer synchronization contract remains a generic opaque envelope with Item and revision identifiers. Consequently, the Server cannot distinguish a Login from a Secure Note or interpret either payload.

Folders and favorites are supported; tags, cards, identities, passkeys, SSH-key models, attachments, and shared records are deferred.

After unlock, the client builds an in-memory fuzzy index over item name, username, domain/URL, folder, and custom-field names. Passwords, TOTP secrets, and hidden values are never indexed. Notes enter search only through an explicit content-search action. No semantic search index is stored by the server.

Bitwarden, 1Password, and generic CSV exports are parsed locally. Import previews never merge items automatically. Semantically identical records are retained and renamed with `(Duplicada)`, then `(Duplicada) - 2`, `(Duplicada) - 3`, and so on. Same-name records with different content are not duplicates.

TOTP accepts `otpauth://` URIs or manual parameters; QR decoding is deferred. Secrets are hidden by default and can be revealed or copied. Clipboard content is cleared after 30 seconds only if unchanged.

The random-password generator supports 5–128 characters, uppercase, lowercase, digits, special characters, minimum digit/special counts, and ambiguous-character exclusion. Passphrases are deferred. Pwned-password checks use a configurable k-anonymity-compatible endpoint directly from the client, only from the generator or an explicit item-view action.

Encrypted portable backup and guarded plaintext JSON/CSV export are supported. Encrypted backups use a distinct backup password.

## Consequences

- Search requires unlocked plaintext in client memory.
- Native-type dispatch and schema-version compatibility remain Client responsibilities.
- Import files and plaintext exports require prominent deletion/exposure warnings.
- The server synchronizes opaque versioned records and does not understand their schema beyond envelope metadata.
