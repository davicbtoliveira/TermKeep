# Domain glossary

- **Account**: An independently authenticated user identity, addressed by email and an immutable UUID.
- **Administrator**: An account allowed to invite, suspend, reactivate, and schedule deletion of accounts, but never inspect their vaults.
- **Audit event**: Fixed, non-semantic operational metadata describing authentication, invitation, registration, or session activity without vault content or raw authentication material.
- **Client**: The Linux `termkeep` CLI/TUI that owns plaintext processing and cryptographic operations.
- **Conflict**: Two valid item revisions descended from the same base revision and changed independently.
- **Encrypted cache**: The complete local vault replica used for offline unlock, reads, writes, search, and queued synchronization.
- **Head revision**: An item revision that is not the parent of another preserved revision; multiple heads represent a Conflict.
- **Item**: A versioned encrypted vault record, initially a Login or Secure Note.
- **Master password**: The user-chosen secret used locally to unlock the vault and participate in online authentication. It is never sent to the server.
- **Recovery key**: A high-entropy, user-controlled secret that can rewrap the vault key under a new master password.
- **Revision graph**: The append-only set of encrypted item revisions connected by immutable parent revision UUIDs.
- **Server**: The self-hosted Go API that authenticates accounts and synchronizes opaque encrypted records.
- **Session agent**: A per-terminal local process that holds an unlocked vault key in memory and serves later `termkeep` invocations through a restricted Unix socket.
- **Secure Note**: A native encrypted Item containing a title and sensitive free-form content; its type, title, and content are visible only to an unlocked Client.
- **Tombstone**: A retained content-free deletion revision. It preserves only opaque reconciliation metadata so stale offline edits become explicit Conflicts instead of silently resurrecting deleted Items.
- **Vault**: One account's logical collection of encrypted items, folders, favorites, and settings.
- **Vault key**: A random 256-bit key used as the root of the per-vault encryption hierarchy.
- **Zero knowledge**: The property that the server and administrator cannot decrypt semantic vault content.
