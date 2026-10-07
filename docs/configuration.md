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
| `PROBE_PORT` | `8080` | Plain HTTP for `/livez` (the process only) and `/readyz` (the dependencies). |
| `WORKLOAD_AUTH` | on | Unset means callers are authenticated. `disabled` is the only accepted value, for local runs only, and can't be combined with `WORKLOAD_OIDC_*`. |
| `WORKLOAD_OIDC_ISSUER` | required unless disabled | The cluster's service-account issuer; must equal the token's `iss` and be `https`. |
| `WORKLOAD_OIDC_JWKS_URL` | discovery | Overrides the key set URL found through `<issuer>/.well-known/openid-configuration`. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM bundle trusted for the discovery and key set fetch (the namespace's `kube-root-ca.crt`). |
| `WORKLOAD_OIDC_BEARER_FILE` | none | Token sent on the discovery and key set fetch, re-read each time (a second projected token with the API server's default audience). |
| `WORKLOAD_AUDIENCE` | `steward` | The audience every caller token must carry. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | required unless disabled | Comma list of `<namespace>/<serviceaccount>` that may call at all; for audit, `<ns>/steward-gateway`. |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | The OTLP collector for traces and metrics. |
| `AUDIT_TSA_URL` | empty | The RFC 3161 time-stamp authority (`http` or `https`). Empty turns checkpoint anchoring off. |
| `AUDIT_CHECKPOINT_INTERVAL` | `15m` | How often a checkpoint is made. |
| `AUDIT_CHECKPOINT_BATCH_SIZE` | `10000` | The most records one checkpoint covers. A backlog drains one batch per interval. |
| `AUDIT_PURGE_INTERVAL` | `1h` | How often the activity-tier retention purge runs. It also runs once at start-up. Every replica schedules it; an advisory lock lets one purge at a time. |
| `LOG_LEVEL` | go-log's default | `trace`, `debug`, `info`, `warn` or `error`. |
| `LOG_FORMAT` | go-log's default | `console` locally, `json` in every cluster. |

## Service-to-service authentication

Every call except health and reflection must carry the caller's projected service-account token as
`authorization: Bearer <token>`. Audit verifies it against the issuer's key set (audience, issuer,
expiry, signature), maps `<ns>/steward-<name>` to the caller `<name>`, and checks the per-method
allow-list in code (`internal/server/callers.go`):

| Method | Callers |
| --- | --- |
| `QueryAuditLog`, `ExportAuditSegment`, `VerifyAuditChain` | gateway, on behalf of the signed-in user it names in `requester` |
| `ShredSubject`, `CreateLegalHold`, `ListLegalHolds`, `ReleaseLegalHold` | gateway, on behalf of the signed-in user it names in `requester` (who still needs `compliance.manage`) |
| `ListRecentEvents` | none (the gateway's live tail reads the broker) |

A missing or rejected token is `Unauthenticated`; a verified caller not listed for the method is
`PermissionDenied`. Each refusal is logged and appended to the chain as an `rpc.denied` record in
the audit tier. While no key set has loaded (the issuer unreachable, or refusing the fetch) every
call is refused with `Unavailable`, and readiness reports `jwks` as a failing required dependency.
Events still arrive over RabbitMQ and are not affected. `internal/workloadauth` is a byte-identical
copy of steward-core's, pinned by `STEWARD_CORE_REF` in `proto-refs.env` and compared in CI by
`scripts/workloadauth-check.sh`; change it in steward-core first.

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
