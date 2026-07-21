# ADR 0003: Offline-first synchronization with explicit conflicts

- Status: Accepted
- Date: 2026-07-21

## Context

TermKeep must unlock, search, create, edit, and delete while the server is unreachable. Multiple terminals may independently change the same item.

## Decision

The client keeps a complete encrypted cache and an idempotent local mutation queue. The server exposes a versioned HTTP/JSON API with per-account incremental cursors, immutable revision identifiers, base revisions, and tombstones. Synchronization runs on unlock, after online mutations, periodically while the TUI is open, and on manual request. The MVP does not use WebSockets.

Concurrent changes are never resolved with silent last-write-wins. Both revisions are preserved and presented in the TUI for explicit selection or manual merge. Deleted items remain in an encrypted trash for 30 days; permanent deletion retains only the technical tombstone needed for stale-client reconciliation.

Connection state is classified without third-party probes: local DNS/route/interface failures are shown as Client offline; a reachable proxy with a failing API or 502/503/504 is Server unavailable; invalid TLS is a security error; ambiguous failures are Connection unavailable.

## Consequences

- Local changes remain immediately usable and synchronize eventually.
- A client whose cursor is older than retained change history must receive a full encrypted snapshot.
- An offline edit to a remotely deleted item becomes an explicit conflict instead of silently resurrecting it.
- Retry safety depends on stable mutation IDs and database transactions.

