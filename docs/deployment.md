# Reference self-hosted deployment

Docker Compose stack with three services: **Traefik** (TLS termination),
**server** (the TermKeep API), and **db** (PostgreSQL).

> [!WARNING]
> TermKeep is pre-production. This deployment proves the architecture; it
> is **not ready for real credentials**. OPAQUE integration and encryption
> still require an independent security review before any production use.

## First boot

```sh
cp deploy/.env.example deploy/.env
go run ./cmd/termkeep-server opaque-keygen  # copy both outputs into deploy/.env
deploy/generate-dev-certs.sh           # development CA + localhost certificate
docker compose -f deploy/compose.yml --env-file deploy/.env up -d --build
```

On an empty database the server applies all SQL migrations at boot
(embedded, versioned, transactional). Verify the instance:

```sh
termkeep --server https://localhost --ca-cert deploy/certs/ca.pem status
```

`termkeep` with no subcommand opens the TUI showing the same state.

## Configuration

All configuration is environment-driven; see `deploy/.env.example`.

| Variable               | Default    | Purpose                                            |
| ---------------------- | ---------- | -------------------------------------------------- |
| `POSTGRES_PASSWORD`    | (required) | Password of the `termkeep` PostgreSQL role         |
| `OPAQUE_SERVER_KEY`    | (required) | Persistent OPAQUE server private key               |
| `OPAQUE_OPRF_SEED`     | (required) | Persistent per-account OPRF derivation seed        |
| `AUDIT_RETENTION_DAYS` | `90`       | Positive number of days to retain audit events     |
| `TERMKEEP_HTTPS_PORT`  | `443`      | Host port publishing Traefik's HTTPS endpoint      |
| `TERMKEEP_SERVER_PORT` | `8080`     | Loopback-only direct server port (debugging/tests) |
| `TERMKEEP_CERTS_DIR`   | `./certs`  | Directory with `ca.pem`, `tls.crt`, `tls.key`      |

Server-side environment (set in `compose.yml`, usually unchanged):

- `DATABASE_URL` — PostgreSQL DSN, internal network only, `sslmode=disable`
  because traffic never leaves the Docker network.
- `TRUSTED_PROXIES` — CIDRs whose `X-Forwarded-For` headers are honored.
  Pinned to Traefik's fixed address `10.90.0.2/32`; anything else is
  ignored, including requests to the loopback debug port.
- `LISTEN_ADDR` — bind address inside the container (`:8080`).
- `AUDIT_RETENTION_DAYS` — audit events older than this positive day count
  are deleted automatically when activity is recorded or queried.

Client-side flags/environment:

- `--server` / `TERMKEEP_SERVER` — instance base URL. Plain HTTP is
  refused outside localhost.
- `--ca-cert` / `TERMKEEP_CA_CERT` — PEM trust anchor for the deployment
  CA. TLS verification is never disabled; a validation failure is
  reported as a security error, not as offline mode.

## Secrets

- `deploy/.env` and `deploy/certs/` are gitignored. Never commit them.
- `POSTGRES_PASSWORD` authenticates the server to PostgreSQL. Rotate by
  changing it in `.env` **and** in the database (`ALTER ROLE`), or by
  recreating the volume.
- `ca.key` signs the development server certificate. It grants nothing
  against the database, but any client that trusts `ca.pem` will trust
  certificates it signs — keep it local.
- `OPAQUE_SERVER_KEY` and `OPAQUE_OPRF_SEED` authenticate all OPAQUE records.
  Generate them once with `termkeep-server opaque-keygen`; back them up with
  the database. Rotating or losing either prevents existing accounts from
  logging in.

## Volumes and networks

- `pgdata` — the only stateful volume (PostgreSQL). **Back this up**;
  every other component is disposable and reproducible from the repo.
- `internal` network — server ↔ PostgreSQL. Not published to the host.
- `termkeep-proxy` network — Traefik ↔ server, fixed subnet
  `10.90.0.0/24` so `TRUSTED_PROXIES` can name an exact proxy address.
  The fixed name also means two stacks cannot run at once; the
  black-box harness and a running operator stack must be serialized.

## Operations

```sh
docker compose -f deploy/compose.yml logs -f server   # logs (no secrets)
docker compose -f deploy/compose.yml down             # stop, keep data
docker compose -f deploy/compose.yml down -v          # stop, DELETE data
```

Stack upgrades run pending migrations automatically at server boot.

Migration 6 adds `vault_items`. Its server-visible columns are limited to the
owning account UUID, item UUID, schema version, revision, opaque envelope, and
timestamps. Login fields are never separate columns or indexes. Revision 1
creates an item; later writes must advance exactly one revision or receive
HTTP 409.

## Testing

```sh
go test ./... -short                    # unit tests, no Docker
go test ./test/blackbox/ -timeout 15m   # full ephemeral stack, compiled client
```

The black-box harness (`test/blackbox/`) boots an ephemeral copy of this
stack on random ports, drives the compiled binary (including a
pseudo-terminal for the TUI), and tears everything down.
