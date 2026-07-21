# ADR 0004: Go service architecture and self-hosted deployment

- Status: Accepted
- Date: 2026-07-21

## Context

TermKeep is initially self-hosted, multi-account, and implemented in Go. It needs predictable deployment and transactional synchronization without maintaining multiple database implementations.

## Decision

The system consists of Go client, agent, and server components in one repository. The server provides a versioned `/api/v1` HTTP/JSON API and uses PostgreSQL as its only MVP database. The reference deployment is Docker Compose with TermKeep, PostgreSQL, and Traefik. Traefik terminates TLS; trusted-proxy addresses are explicit.

The client refuses plaintext HTTP except for localhost. TLS failures are never bypassed as ordinary offline behavior.

The instance supports multiple isolated accounts but no organizations, groups, shared credentials, or shared vaults. Administrators may invite, list, suspend, reactivate, and schedule account deletion. Scheduled deletion revokes sessions immediately and purges after seven days unless canceled. Destructive actions require UUID confirmation and are audited.

Security audit events are retained for 90 days by default and include actor UUID in the administrative view. Logs exclude decrypted content, search terms, item identifiers meaningful to users, TOTP values, and raw authentication material.

## Consequences

- SQLite, Kubernetes, SMTP, and non-Linux clients are outside the MVP.
- Docker Compose is the supported installation path; operators remain responsible for database and volume backups.
- Proxy headers are ignored unless the request came from a configured trusted proxy.

