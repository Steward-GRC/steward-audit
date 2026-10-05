# Configuration

Every setting is an environment variable, read once at start-up. A missing required setting or a
value that doesn't parse stops the service with every problem listed; nothing falls back quietly.
`.env.example` has each one with a local default.

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_DSN` | required | Postgres connection for the service. |
| `MIGRATE_DSN` | `DATABASE_DSN` | A direct connection for migrations, when `DATABASE_DSN` goes through a transaction-pooling proxy. |
| `MIGRATIONS_DIR` | `migrations` | Where the SQL migrations are. The image sets `/migrations`. |
| `RABBITMQ_URL` | required | The broker the audit events arrive on. |
| `GRPC_PORT` | `9090` | The gRPC listen port. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | The OTLP collector for traces and metrics. |
| `AUDIT_TSA_URL` | empty | The RFC 3161 time-stamp authority (`http` or `https`). Empty turns checkpoint anchoring off. |
| `AUDIT_CHECKPOINT_INTERVAL` | `15m` | How often a checkpoint is made. |
| `AUDIT_CHECKPOINT_BATCH_SIZE` | `10000` | The most records one checkpoint covers. A backlog drains one batch per interval. |
| `LOG_LEVEL` | go-log's default | `trace`, `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT` | go-log's default | `console` locally, `json` in every cluster. |

## Choosing a time-stamp authority

Steward ships with no authority chosen: it is the adopter's decision, and the anchors are only as
trustworthy as the authority that signs them. Pick one whose certificate chain you can keep for as
long as you keep the audit tier, and set `AUDIT_TSA_URL`. Until then the chain is still written and
verified, but no checkpoint is made.

A shorter interval or a smaller batch gives finer-grained anchors at the cost of more requests to
the authority.

## Migrations

The schema is one baseline, `migrations/0001_baseline.up.sql`. It is applied with go-postgres at
start-up, before the service connects for work.
