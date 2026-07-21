# PRD 0001: TermKeep MVP

## Problem Statement

People who prefer terminal-native workflows need a password vault they can self-host without giving the server or its administrator access to their credentials. Existing password managers often prioritize browser and mobile interfaces, require cloud trust, or provide terminal clients as secondary integrations. Users also need to bring existing data from established managers, continue working through client or server outages, quickly find credentials, generate strong passwords and TOTP codes, and identify leaked passwords without disclosing secrets to the server.

A self-hosted vault creates additional risks: database backups may be stolen, administrators may be curious or compromised, a server may become unavailable while credentials are needed, stale clients may overwrite newer data, and plaintext import/export files may linger on disk. TermKeep must make the secure behavior the normal behavior while remaining practical to operate from a Linux terminal.

## Solution

TermKeep will provide a Linux-only Go CLI/TUI backed by a self-hosted multi-account Go service. The client owns all plaintext and cryptographic operations; the service authenticates accounts and synchronizes versioned opaque blobs through a REST/JSON API. Each account has an isolated vault, a complete encrypted local cache, a per-terminal session agent, and explicit conflict handling. The user can unlock and edit offline, then synchronize queued changes when connectivity returns.

The MVP will manage Login and Secure Note items, folders, favorites, custom fields, TOTP secrets, and password history. It will import Bitwarden, 1Password, and generic CSV exports locally, provide fuzzy search over non-secret fields, generate configurable random passwords, optionally check passwords through a k-anonymity-compatible Pwned Passwords endpoint, and produce encrypted or carefully guarded plaintext exports. A closed-registration administrative surface will manage accounts and audit operational security events without exposing vault content.

The reference self-hosted installation will use Docker Compose, PostgreSQL, and Traefik. TermKeep will be released under AGPL-3.0-or-later. It remains pre-production until the security-sensitive design and OPAQUE integration receive independent review.

## User Stories

1. As an operator, I want to deploy TermKeep with Docker Compose, so that I can run the complete service without assembling every dependency manually.
2. As an operator, I want Traefik to terminate HTTPS, so that credentials and authentication traffic are protected in transit.
3. As an operator, I want TermKeep to use PostgreSQL, so that synchronization and account operations have transactional persistence.
4. As an operator, I want trusted proxy addresses to be explicit, so that clients cannot forge proxy-derived request information.
5. As an operator, I want the server to expose health information that contains no secrets, so that I can monitor availability.
6. As an operator, I want closed registration, so that unknown people cannot create accounts on my instance.
7. As the bootstrap administrator, I want the first account to receive administrative capability, so that I can configure a fresh instance.
8. As an administrator, I want to create an expiring single-use invitation for a specific email, so that I can admit an intended user without public signup.
9. As an administrator, I want to copy an invitation token for out-of-band delivery, so that the instance does not require SMTP.
10. As an invited user, I want to register with email and a master password, so that I can create an isolated vault.
11. As a registering user, I want the client to enforce a 12-character minimum with uppercase, lowercase, number, and special-character requirements, so that weak master passwords are rejected.
12. As a registering user, I want to confirm my master password, so that a typing mistake does not permanently lock me out.
13. As a registering user, I want a recovery key displayed once with a clear storage warning, so that I can recover from a forgotten master password without trusting an administrator.
14. As a user, I want my master password to remain on my client, so that the server never receives it.
15. As a user, I want to authenticate through OPAQUE, so that online password authentication uses a standardized augmented PAKE.
16. As a user, I want the same master password to authenticate and unlock my vault, so that I do not manage two user-facing passwords.
17. As a user, I want encryption and authentication keys separated internally, so that key reuse does not couple independent security purposes.
18. As a user, I want to unlock a previously authorized encrypted cache while offline, so that server downtime does not block access to credentials.
19. As a user, I want to create, edit, and delete items while offline, so that my vault remains useful without connectivity.
20. As a user, I want an unmistakable connection status, so that I know whether changes are pending synchronization.
21. As a user, I want client network failure distinguished from server unavailability when possible, so that I know where to troubleshoot.
22. As a user, I want TLS validation failures shown as security errors, so that certificate problems are never normalized as ordinary offline operation.
23. As a user, I want queued changes synchronized automatically after connectivity returns, so that I do not have to repeat offline work.
24. As a user, I want a manual synchronization command, so that I can explicitly verify the latest server state.
25. As a user, I want retries to be idempotent, so that network failures do not duplicate mutations.
26. As a user with two terminals, I want concurrent edits preserved as a conflict, so that one valid change never silently destroys another.
27. As a user resolving a conflict, I want to select one revision or merge content manually, so that I control the final record.
28. As a user, I want stale-client deletions represented by tombstones, so that deleted records are not silently resurrected.
29. As a user, I want deleted items kept in trash for 30 days, so that I can recover accidental deletions.
30. As a user, I want to permanently delete a trashed item, so that sensitive obsolete content can be purged without waiting.
31. As a user, I want to open a terminal-scoped session once, so that later TermKeep invocations in that terminal do not repeatedly ask for my master password.
32. As a user, I want a different terminal to require its own login, so that unlock authority is not silently shared across terminal sessions.
33. As a user, I want the session agent to end with its owning shell, so that closing the terminal clears unlocked key material.
34. As a user, I want auto-lock configurable from 1 to 60 minutes or disabled, so that I can choose the right inactivity trade-off.
35. As a user, I want 15 minutes to be the default auto-lock, so that unattended terminals are protected without configuration.
36. As a user, I want a dedicated Active Sessions screen, so that I can see which terminals are connected.
37. As a user, I want to see a session's host, creation time, last use, and approximate IP, so that I can recognize unexpected activity.
38. As a user, I want to revoke another session, so that I can cut off a terminal I no longer trust.
39. As a user, I want logout to revoke the current online session and clear local key material, so that access ends deliberately.
40. As a user, I want repeated failed logins delayed progressively, so that online guessing is expensive without permanently locking my account.
41. As a user, I want to change my master password, so that I can respond to suspected compromise.
42. As a user changing my master password, I want other sessions revoked, so that old online credentials stop working.
43. As a user with a recovery key, I want to set a new master password, so that losing the old password does not necessarily lose the vault.
44. As a user, I want a clear warning that old disconnected caches may still unlock with an old password, so that remote revocation is not overstated.
45. As a user, I want to create a Login item, so that I can store a service credential.
46. As a user, I want a Login to contain a name, username, password, multiple URLs, notes, custom fields, and TOTP configuration, so that common credentials fit one record.
47. As a user, I want to create a Secure Note, so that I can store sensitive text that is not a login.
48. As a user, I want unsupported imported records preserved generically, so that imports do not discard data.
49. As a user, I want to organize items into folders, so that I can navigate a large vault.
50. As a user, I want to mark items as favorites, so that frequently used credentials are immediately accessible.
51. As a user, I want the last five passwords retained with timestamps, so that I can recover from an accidental credential change.
52. As a user, I want to clear password history explicitly, so that obsolete secrets can be removed.
53. As a user, I want secrets hidden by default, so that shoulder surfing is less likely.
54. As a user, I want separate reveal and copy actions, so that viewing a secret is never an accidental side effect of selecting it.
55. As a user, I want copied secrets cleared after 30 seconds if the clipboard is unchanged, so that credentials do not linger unnecessarily.
56. As a user, I want clipboard cleanup not to erase newer content, so that TermKeep does not disrupt unrelated work.
57. As a user, I want fuzzy search over names, usernames, URLs, folders, and custom-field names, so that I can find an item despite partial or imperfect input.
58. As a user, I want passwords, TOTP secrets, and hidden values excluded from the fuzzy index, so that secret values are not unnecessarily searchable in memory.
59. As a user, I want note-content search to require an explicit action, so that broad secret-text searches are intentional.
60. As a user, I want TOTP configuration from an `otpauth://` URI, so that I can transfer standard authenticator settings.
61. As a user, I want to enter TOTP secret, issuer, account, algorithm, digits, and period manually, so that QR scanning is not required.
62. As a user, I want current TOTP codes generated locally, so that the server never learns the secret or generated code.
63. As a user, I want to generate a random password between 5 and 128 characters, so that I can match different service constraints.
64. As a user, I want to select uppercase, lowercase, digits, and special characters, so that generated passwords satisfy a site's accepted character sets.
65. As a user, I want minimum digit and special-character counts, so that generated passwords satisfy composition policies.
66. As a user, I want to exclude ambiguous characters, so that manually transcribing a generated password is safer.
67. As a user, I want impossible generator configurations rejected before generation, so that output always honors my selected constraints.
68. As a user, I want to check a generated password against a breach corpus on demand, so that I can avoid a known leaked value.
69. As a user viewing a Login, I want an explicit leaked-password check, so that no external query occurs merely because I opened or saved an item.
70. As a privacy-conscious user, I want breach checks to send only a hash prefix directly from the client, so that the service never receives the password, full hash, email, or domain.
71. As an operator, I want to disable or redirect the breach-check endpoint, so that the instance can meet local network and privacy requirements.
72. As a migrating user, I want to preview a Bitwarden import locally, so that I can verify it before changing my vault.
73. As a migrating user, I want to preview a 1Password import locally, so that I can verify it before changing my vault.
74. As a migrating user, I want to map a generic CSV locally, so that I can import from other managers.
75. As a migrating user, I want import files never uploaded to the server, so that plaintext exports stay on my machine.
76. As a migrating user, I want a warning to delete plaintext source files after import, so that exported credentials do not remain exposed.
77. As a migrating user, I want semantically identical entries kept and renamed, so that import never destroys a record based on heuristic matching.
78. As a migrating user, I want duplicate names suffixed with `(Duplicada)` and sequential numbers, so that retained copies remain distinguishable.
79. As a migrating user, I want same-name records with different contents treated as distinct, so that separate accounts are not mislabeled as duplicates.
80. As a user, I want an encrypted portable backup protected by a separate password, so that I can restore independently of the server account.
81. As a user, I want an explicit plaintext JSON/CSV export, so that I can leave TermKeep or inspect my data with informed consent.
82. As a user exporting plaintext, I want strong warnings and an explicit destination, so that accidental exposure is less likely.
83. As a command-line user, I want `termkeep` without arguments to open the TUI, so that the interactive experience is the default.
84. As a command-line user, I want scriptable login, logout, sync, import, generate, status, and administration commands, so that routine operations compose with terminal workflows.
85. As a command-line user, I want secret output to stdout to require an explicit flag, so that pipelines and terminal history do not receive secrets accidentally.
86. As an administrator, I want to list account UUID, email, and lifecycle status, so that I can operate the instance without seeing vault content.
87. As an administrator, I want to suspend and reactivate an account, so that access can be controlled without immediately deleting encrypted data.
88. As an administrator, I want account deletion to require typing the UUID, so that destructive actions are deliberate.
89. As an administrator, I want account deletion to have a seven-day grace period, so that an operational mistake can be reversed.
90. As an administrator, I want sessions revoked immediately when deletion begins, so that a scheduled account cannot continue online access.
91. As an administrator, I want an audit event to include the actor's account UUID, so that administrative changes are attributable.
92. As an administrator, I want audit logs retained for 90 days by default, so that recent security events are available without indefinite retention.
93. As an administrator, I want audit retention configurable, so that instance policy can override the default.
94. As a user, I want an Activity screen for my login, session, recovery, and account events, so that I can recognize suspicious actions.
95. As a user, I want audit logs to exclude vault content and search terms, so that observability does not weaken zero knowledge.
96. As an administrator, I want no ability to reset a master password or use a recovery key, so that administrative power does not imply vault access.
97. As a user, I want all semantic fields encrypted before synchronization, so that database readers see only opaque blobs and limited envelope metadata.
98. As a user, I want record identifiers, revisions, and schema versions authenticated with ciphertext, so that blob substitution and undetected mutation fail.
99. As a security reviewer, I want cryptographic formats versioned, so that algorithms and parameters can evolve without ambiguous decoding.
100. As a security reviewer, I want the OPAQUE integration isolated and tested against RFC vectors, so that protocol risk is reviewable.
101. As a security reviewer, I want a production release gated on independent review, so that an unaudited password vault is not presented as mature.
102. As a contributor, I want the project licensed under AGPL-3.0-or-later, so that self-hosted network modifications remain available to users.

## Implementation Decisions

- The repository will contain Go client, session-agent, server, and shared protocol/cryptography packages while preserving process boundaries.
- Linux is the only MVP client platform. The session design may rely on Unix sockets, shell/TTY lifecycle observation, process credentials, `mlock`, and core-dump controls.
- Executing `termkeep` without a subcommand opens the TUI. Safe operational workflows are also available as CLI subcommands.
- Secret output is hidden by default in both CLI and TUI. Any stdout secret output requires an explicit user action or flag.
- The service exposes versioned HTTP/JSON routes under `/api/v1`; the wire contract represents vault content as opaque encrypted envelopes.
- PostgreSQL is the only MVP database. Schema migrations are versioned and applied predictably during deployment or an explicit migration step.
- The reference deployment is Docker Compose with TermKeep, PostgreSQL, and Traefik. Kubernetes, embedded databases, and SMTP are not parallel deployment targets.
- Traefik terminates TLS. The service trusts forwarded headers only from configured proxy addresses. The client rejects HTTP except for localhost and never treats TLS validation failure as offline mode.
- Instances are multi-account. Vaults are isolated; groups, organizations, credential sharing, and shared vault keys do not exist in the MVP.
- Registration is closed. Bootstrap creates the first Administrator. Further registrations require email-bound, expiring, one-time invitation tokens delivered out of band.
- Account identities have immutable UUIDs. Email is the login identifier; administrators see UUID, email, status, and operational metadata but no semantic vault metadata.
- The master-password policy is at least 12 characters and requires uppercase, lowercase, numeric, and special characters. Registration requires confirmation.
- Online registration and authentication use OPAQUE per RFC 9807. The Go integration remains behind a narrow interface, includes fake-record/user-enumeration defenses required by the protocol, and is not considered production-ready before independent review.
- Vault unlocking is independent of online authentication. Argon2id derives local password-based material with at least 64 MiB and three passes; parameters and format versions are stored with encrypted envelopes to permit future upgrades.
- Each Account owns a random 256-bit vault key. HKDF-SHA-256 separates wrapping, record, recovery, and other key purposes. XChaCha20-Poly1305 provides authenticated encryption with random nonces.
- Per-record keys are derived using the vault key and record UUID. Account UUID, record UUID, schema version, and revision are authenticated as associated data.
- A Recovery key is generated client-side, displayed once, and protects a second wrapping of the vault key. The server and Administrator cannot use it.
- A master-password change rewraps the vault key, revokes other online sessions, and cannot invalidate disconnected historic cache copies.
- The client stores a complete encrypted cache and a durable idempotent mutation queue. Plaintext indexes and unlocked keys are never persisted.
- A Session agent belongs to one shell/TTY, holds the unlocked vault key in memory, exposes a user-restricted Unix socket, and terminates when its owner ends. Key clearing, memory locking, and dump prevention are best effort within Go/Linux limitations.
- Auto-lock is configurable from 1 through 60 minutes, defaults to 15 minutes, and accepts an inactive/disabled setting. Locking clears unlocked key material but does not delete the encrypted cache.
- The Active Sessions TUI screen shows host, creation, last use, and approximate IP and permits revocation. Closing a terminal attempts best-effort remote revocation even though local clearing does not depend on server availability.
- Authentication throttling begins after five consecutive failures, progresses through 1, 5, 10, and 15-minute delays, remains capped at 15 minutes, and resets after a successful login or 24 hours without another failure. Enforcement combines account and source dimensions without permanent lockout.
- Synchronization uses per-account change cursors, immutable revisions, base revisions, stable mutation IDs, batched push/pull operations, and Tombstones. Clients outside retained incremental history receive a complete encrypted snapshot.
- Synchronization runs at unlock, after mutations while online, periodically while the TUI is active, and on explicit command. WebSockets are not used in the MVP.
- Conflicts retain every concurrent revision. The client never silently applies last-write-wins; the user selects a revision or performs a manual merge.
- Deletion moves encrypted content to trash for 30 days. Permanent or expired deletion removes content while retaining only reconciliation metadata required to keep stale clients from silently resurrecting it.
- Connectivity status is classified without third-party probes: client DNS/route/interface failure, reachable proxy with unavailable server, TLS security failure, or ambiguous connection failure.
- Native Item types are Login and Secure Note. Unsupported imported shapes are stored as generic encrypted items that preserve source fields.
- Login supports name, username, password, multiple URLs, notes, custom fields, TOTP configuration, folder, favorite status, and a timestamped five-entry password history.
- Organization uses Folders and favorites. Tags, cards, identities, passkeys, SSH-key-specific models, and attachments are deferred.
- The fuzzy-search index exists only in unlocked client memory and covers item name, username, domain/URL, folder, and custom-field names. Passwords, TOTP secrets, and hidden values are excluded. Note contents require a separate explicit search mode.
- TOTP supports standard `otpauth://` input and manual secret, issuer, account, algorithm, digit, and period fields. Code generation is local; QR image decoding is deferred.
- Reveal and copy are distinct. Clipboard clearing occurs after 30 seconds only when the clipboard still contains the value TermKeep placed there.
- The random-password generator accepts length 5–128, selectable uppercase/lowercase/digit/special sets, minimum digit and special counts, and ambiguous-character exclusion. It rejects unsatisfiable configurations and uses the operating system's cryptographically secure random source.
- Passphrase generation is outside the MVP.
- Pwned-password checks occur only from the generator or an explicit Login-view action. The client directly queries a configurable k-anonymity-compatible range endpoint and sends no email, domain, plaintext password, or complete hash.
- Bitwarden, 1Password, and generic CSV imports are parsed, normalized, previewed, and encrypted locally. Source files never go to the service.
- Imports do not merge heuristically. Semantic equality includes normalized username, password, URLs, notes, TOTP, and custom fields. Equal records remain separate and receive `(Duplicada)`, then `(Duplicada) - N`; title equality alone is not duplication.
- Portable encrypted backups use an export-specific password and self-describing cryptographic header. Plaintext JSON/CSV exports require explicit destination and strong warnings.
- Administrators can invite, list, suspend, reactivate, and schedule account deletion. They cannot reset master passwords, generate recovery material, decrypt records, search vaults, or inspect TOTP.
- Account deletion suspends immediately, revokes sessions, requires UUID confirmation, and has a seven-day cancellation window before server-side purge.
- Audit events cover authentication, throttling, invitations, sessions, email/master-password/recovery events, account lifecycle, administrative actions, and synchronization failures. Administrative events identify the actor UUID.
- Audit logs default to 90-day retention with Administrator configuration. Logs never include decrypted item content, search terms, passwords, TOTP values, sensitive clipboard data, or raw authentication material.
- The server can observe account email, opaque UUIDs, revisions, timestamps, Tombstones, blob counts, and approximate ciphertext sizes. This limited metadata leakage is part of the accepted threat model.
- A compromised client host with root access, a keylogger, a malicious binary, denial of service, server-side deletion, and undetectable whole-snapshot rollback to a fresh client are outside the guarantees of the MVP.

## Testing Decisions

- The primary test seam is black-box observable behavior of the compiled `termkeep` client against a real ephemeral TermKeep server and PostgreSQL database. Tests drive CLI commands or a pseudo-terminal and assert API-visible, database-visible ciphertext metadata, user-visible output, and cross-client behavior rather than internal calls.
- The primary seam covers bootstrap, invitation, registration, online login, terminal-session reuse, vault mutation, offline queuing, reconnection, synchronization, conflict handling, trash, recovery, administrative lifecycle, and audit behavior.
- TUI tests focus on stable user interactions and rendered semantic state through a pseudo-terminal, not exact styling or internal component structure.
- Server contract tests exercise `/api/v1` from the same generated or shared client contract used by the executable and verify status codes, idempotency, cursor progression, authorization boundaries, and opaque payload handling.
- Zero-knowledge tests inspect server requests, database rows, logs, and audit events to prove that known plaintext fixtures and secret-derived searchable values never appear.
- Cryptographic primitives and OPAQUE are deliberate lower-level exceptions to the single high seam. They use published RFC test vectors, negative authentication/tamper cases, format-version compatibility fixtures, and independent interoperability vectors where available.
- Property tests cover envelope round trips, nonce uniqueness assumptions, generator constraints, import normalization, duplicate naming, revision convergence, mutation idempotency, Tombstone reconciliation, and conflict preservation.
- Fuzz tests target every untrusted parser and state boundary: API decoding, encrypted envelope headers, backup files, Bitwarden/1Password/CSV imports, `otpauth://` values, and synchronization sequences.
- Fault-injection tests interrupt requests and processes around durable-write boundaries to demonstrate that retries neither lose accepted mutations nor create duplicate revisions.
- Multi-client scenarios use isolated encrypted caches against one account to verify offline edits, stale cursors, full resynchronization, conflicts, password changes, and session revocation.
- Deployment smoke tests start the reference Docker Compose stack, verify Traefik HTTPS routing and trusted-proxy behavior, apply migrations to an empty database, restart each component, and verify persistent encrypted state.
- Security log tests assert both required audit events and forbidden secret fields. Retention tests verify automatic deletion after the configured period.
- Clipboard and Session-agent tests run on Linux and verify permissions, terminal isolation, auto-lock, owner lifecycle, best-effort cleanup, and no overwrite of newer clipboard content.
- Performance tests use representative vaults with thousands of items to set budgets for unlock, in-memory index construction, fuzzy search, incremental sync, and Argon2id latency without weakening minimum parameters.
- The repository currently contains no implementation or testing prior art. The first tracer slice must establish the black-box harness and make it the default pattern for later features.
- A stable production release requires an independent security assessment; passing automated tests alone is not sufficient evidence that the vault is secure.

## Out of Scope

- Web vaults, browser extensions, browser autofill, desktop GUI applications, and mobile clients.
- macOS and Windows clients.
- Organizations, groups, shared vaults, shared credentials, collections, and emergency access to another user's vault.
- Administrator-assisted password reset or administrator access to Recovery keys.
- Account-level TOTP, SMS, email OTP, passkeys, WebAuthn, and other login second factors.
- Tags as an organization mechanism.
- Native Card, Identity, passkey, SSH key, and other specialized item schemas.
- File attachments.
- QR-code image decoding for TOTP enrollment.
- Passphrase generation.
- Automatic leaked-password checks during typing, save, import, unlock, or background audit.
- Server-side search or any plaintext/semantic search index on the server.
- Real-time synchronization through WebSockets or push notifications.
- Silent last-write-wins conflict resolution or automatic heuristic merging.
- SQLite, MySQL, or other database backends.
- Kubernetes manifests or an operator.
- Built-in mandatory SMTP delivery.
- Plain HTTP to non-localhost servers without an explicit future insecure-development mechanism.
- Complete protection from a compromised client OS, root user, malware, keylogger, malicious release binary, or exposed clipboard manager.
- Guaranteed remote erasure or invalidation of disconnected historic caches.
- Prevention of server denial of service, ciphertext deletion, change withholding, or undetectable complete rollback to a fresh client without an external trusted anchor.
- A production-security claim before independent protocol and implementation review.

## Further Notes

- The accepted architectural constraints are recorded in ADRs 0001 through 0005.
- Security-sensitive file and wire formats must carry explicit versions and remain backward-readable or provide an intentional migration path.
- Import and plaintext export workflows must assume source files are unencrypted and warn accordingly; TermKeep cannot securely erase arbitrary files from journaling or copy-on-write filesystems.
- Password and key memory clearing in Go is best effort. Documentation must avoid claiming guaranteed zeroization.
- Recovery protects against a forgotten master password only when the user retained the Recovery key. Losing both is permanent by design.
- The Pwned Passwords-compatible integration is configurable and can point at a self-hosted range endpoint; no availability dependency on a third party is introduced for ordinary vault use.
- The AGPL-3.0-or-later license applies to the project. Dependencies must be reviewed for license compatibility and cryptographic maintenance posture.

