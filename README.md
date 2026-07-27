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

## License

TermKeep is licensed under the GNU Affero General Public License v3.0 or later.
