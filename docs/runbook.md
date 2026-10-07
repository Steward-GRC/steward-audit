# Runbook

## Start-up

The service applies the migrations, connects to Postgres, starts the checkpointer (when
`AUDIT_TSA_URL` is set), starts the event consumer and serves gRPC. A bad setting stops it at once
with every problem listed. It stops cleanly on SIGINT or SIGTERM, draining in-flight calls for up to
ten seconds.

Health: `grpc.health.v1.Health/Check` on `GRPC_PORT` (the empty name and `readiness` follow the
dependencies; `liveness` is the process only), and `/readyz` and `/livez` on `PROBE_PORT`.
Readiness needs Postgres, RabbitMQ and, while caller authentication is on, the issuer's key set
(`jwks`). With `WORKLOAD_AUTH=disabled` audit reports itself degraded and logs a warning every
five minutes.

## Logs worth knowing

| Message | Meaning | What to do |
| --- | --- | --- |
| `AUDIT_TSA_URL is not set: checkpoints are not anchored` | Anchoring is off | Choose an authority and set `AUDIT_TSA_URL`. |
| `checkpoint tick failed` | The authority or the database failed a checkpoint | Nothing is lost: the same records are tried on the next interval. Check the authority's reachability. |
| `rabbitmq: handler dead-lettered a message` | An event couldn't be stored | Read it from the dead-letter queue; fix the publisher. |
| `audit store read failed` | An API read failed (`op` says which) | Check Postgres. The caller got `AUDIT_STORE_UNAVAILABLE` (2001). |
| `audit chain verification failed` | A verify found a problem | Treat as a possible tamper: export the range and verify it offline, and compare with backups. |
| `Unavailable: workload verifier unavailable`, `/readyz` 503 with `jwks` down | No issuer key set has loaded | Check `WORKLOAD_OIDC_ISSUER`, the CA file and the bearer file: an API server answers 401 to a bearer with the `steward` audience, so the bearer must be the second projected token. |
| `Unauthenticated: no workload token` / `workload token rejected` | The caller sent no token, or one with the wrong audience, issuer or expiry, or from a service account outside `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | Check the caller's `WORKLOAD_TOKEN_FILE` mount and audit's allow-list. |
| `PermissionDenied: caller not allowed on this method` | A verified caller isn't listed for the method | Expected for anything but the gateway; the refusal is in the chain as `rpc.denied`. |
| `recording a refused call failed` | A refusal couldn't be appended to the chain | Check Postgres. |
| `export meta-audit record failed` | An export happened but wasn't recorded | Check Postgres; record the export by hand from the log line. |

## Verifying the chain

Call `VerifyAuditChain` over the range, or export it with `ExportAuditSegment` and verify it off
the server (see [the integrity model](integrity.md)). Verify a stored reply with the authority's
certificates, for example `openssl ts -verify -data root.txt -in reply.der -CAfile ca.pem`, where
`root.txt` holds the checkpoint's hex root with no trailing newline.

## Backups and migration

Back up the whole database: the chain, the checkpoints and the tokens are only useful together.
Crypto-shred keys must move with the audit data, or erased subjects become readable again.

## Local run

```bash
cp .env.example .env   # point it at a local Postgres and RabbitMQ
task run
```
