# ADR 0003: Offline-first synchronization with explicit conflicts

- Status: Accepted
- Date: 2026-07-21
- Updated: 2026-07-28

## Context

TermKeep must unlock, search, create, edit, and delete while the server is unreachable. Multiple terminals may independently change the same item.

## Decision

The client keeps a complete encrypted cache and an idempotent local mutation queue. The server exposes a versioned HTTP/JSON API with per-account incremental cursors, immutable revision identifiers, base revisions, and tombstones. Synchronization runs on unlock, after online mutations, periodically while the TUI is open, and on manual request. The MVP does not use WebSockets.

Concurrent changes are never resolved with silent last-write-wins. Both revisions are preserved and presented in the TUI for explicit selection or manual merge. Deleted items remain in an encrypted trash for 30 days; permanent deletion retains only the technical tombstone needed for stale-client reconciliation.

Folder records, Item-to-Folder associations, and favorite flags follow the same rules. Concurrent Folder renames or Item organization edits remain multiple heads until explicit resolution. Removing a Folder queues revisions that clear its UUID from assigned Items, followed by a deleted Folder revision, so the Items remain live and appear under No Folder.

Each accepted mutation UUID is also its immutable revision UUID. Revisions form an append-only directed acyclic graph through parent revision UUIDs. Active heads are derived from that graph instead of from arrival order. Selecting a version or saving a manual merge creates one new revision with every conflicting head as a parent.

Deletion appends a normal encrypted revision marked `deleted`; it leaves the normal list and becomes visible in Trash. Restoration appends a live child revision before expiration. Permanent deletion requires an explicit TUI confirmation and a Tombstone that descends from every current head. The first synchronization at or after 30 days creates the same Tombstone automatically for an unconflicted deleted head.

A Tombstone is marked `deleted` and `purged` and has no envelope. Accepting it scrubs envelopes from prior server revisions and incremental changes for that Item while preserving opaque identifiers, parent links, revision numbers, and mutation idempotency metadata. Synchronized clients perform the same local scrubbing. Historic disconnected cache copies cannot be remotely erased.

Incremental changes are retained for 30 days. The server detects any gap between a Client cursor and retained cursors and returns every current revision head as a full encrypted snapshot. The Client replaces synchronized graph state but preserves queued local mutations. Consequently, a stale offline edit accepted after purge remains a live head beside the Tombstone and is presented as an explicit Conflict; the Tombstone does not silently discard the edit, and the edit does not silently resurrect the deleted Item.

Connection state is classified without third-party probes: local DNS/route/interface failures are shown as Client offline; a reachable proxy with a failing API or 502/503/504 is Server unavailable; invalid TLS is a security error; ambiguous failures are Connection unavailable.

## Consequences

- Local changes remain immediately usable and synchronize eventually.
- A client whose cursor is older than retained change history must receive a full encrypted snapshot.
- An offline edit to a remotely deleted item becomes an explicit conflict instead of silently resurrecting it.
- Retry safety depends on stable mutation IDs and database transactions.
- Technical revision and Tombstone metadata remains durable; purged encrypted content does not.
- A server cannot guarantee deletion from disconnected historic caches, backups, or a compromised Client host.
