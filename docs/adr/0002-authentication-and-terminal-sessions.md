# ADR 0002: OPAQUE authentication and terminal-scoped sessions

- Status: Accepted
- Date: 2026-07-21

## Context

Accounts authenticate with email and the same master password perceived by the user, without sending that password to the server. A user must be able to reopen TermKeep without logging in again within the same terminal session.

## Decision

Online registration and login use OPAQUE as standardized by RFC 9807. Its integration is isolated behind an authentication interface, checked against RFC vectors, and requires independent security review before a stable production release. Vault encryption remains independent so an authorized cache can unlock offline.

The first invocation in a terminal starts a per-terminal agent. It holds the unlocked vault key only in memory, exposes a Unix socket restricted to the current OS user, and terminates with its owning shell/TTY. Another terminal requires another login. Auto-lock is configurable from 1 to 60 minutes, defaults to 15 minutes, and may be disabled. Closing a terminal clears local material and attempts to revoke the online session.

The TUI has an Active Sessions screen with host name, creation time, last use, and approximate source IP. Users may revoke sessions. Access attempts use escalating delays of 1, 5, 10, and 15 minutes, beginning after five consecutive failures and resetting after success or 24 hours without a failure. Rate limits combine account and source to reduce account-lockout abuse.

Registration is closed. The bootstrap account is an administrator and issues single-use, expiring invitation tokens bound to email; tokens are shared out of band, so SMTP is not required.

## Consequences

- Linux is the only supported MVP client platform.
- No account-level TOTP is required; stored TOTP secrets belong to vault items.
- Administrators can manage account lifecycle but cannot reset master passwords or recover vault keys.
- Master-password changes revoke all other online sessions.

