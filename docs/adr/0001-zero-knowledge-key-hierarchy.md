# ADR 0001: Zero-knowledge threat model and key hierarchy

- Status: Accepted
- Date: 2026-07-21

## Context

TermKeep stores credentials on a self-hosted multi-account server. A database, backup, or server operator must not be able to decrypt vault content. The client must also unlock a previously authorized cache while offline.

## Decision

All semantic data is encrypted and decrypted by the client. The server may know account email, random identifiers, revisions, timestamps, tombstones, blob counts, and approximate ciphertext sizes, but not item names, usernames, passwords, URLs, notes, folders, custom-field values, or TOTP secrets.

Each vault has a random 256-bit vault key. Argon2id derives password-based key material with a floor of 64 MiB and three passes. HKDF-SHA-256 separates keys by purpose. XChaCha20-Poly1305 protects the wrapped vault key and records. A per-record key is derived from the vault key and record UUID; random nonces are used. Account UUID, record UUID, schema version, and revision are authenticated as associated data.

A high-entropy recovery key protects a second wrapping of the vault key and is displayed once. Neither the master password nor recovery key is stored or transmitted in plaintext.

## Consequences

- Fuzzy search, imports, exports, password checks, and TOTP generation happen on the client.
- Losing both the master password and recovery key permanently loses access.
- Changing the master password rewraps the vault key instead of reciphering every item.
- An offline cache made before a password change can still be opened with the old password; remote invalidation cannot erase it.
- A compromised root account, keylogger, malicious client binary, or memory-reading malware is outside the confidentiality boundary.
- Buffers are cleared and keys are memory-locked on a best-effort basis, and the session agent disables core dumps, but the Go runtime cannot guarantee perfect zeroization.
- A malicious server can delete, withhold, or replay a complete old snapshot to a fresh client. Backups and local revision checks mitigate but cannot eliminate this availability/rollback risk.

