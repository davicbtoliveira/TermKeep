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

## License

TermKeep is licensed under the GNU Affero General Public License v3.0 or later.
