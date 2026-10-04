# Runbook

## Start-up

The service applies the migrations, connects to Postgres, starts the checkpointer (when
`AUDIT_TSA_URL` is set), starts the event consumer and serves gRPC. A bad setting stops it at once
with every problem listed. It stops cleanly on SIGINT or SIGTERM, draining in-flight calls for up to
ten seconds.

Health: `grpc.health.v1.Health/Check` on `GRPC_PORT`.

## Logs worth knowing

| Message | Meaning | What to do |
| --- | --- | --- |
| `AUDIT_TSA_URL is not set: checkpoints are not anchored` | Anchoring is off | Choose an authority and set `AUDIT_TSA_URL`. |
| `checkpoint tick failed` | The authority or the database failed a checkpoint | Nothing is lost: the same records are tried on the next interval. Check the authority's reachability. |
| `rabbitmq: handler dead-lettered a message` | An event couldn't be stored | Read it from the dead-letter queue; fix the publisher. |
| `audit store read failed` | An API read failed (`op` says which) | Check Postgres. The caller got `AUDIT_STORE_UNAVAILABLE` (2001). |
| `audit chain verification failed` | A verify found a problem | Treat as a possible tamper: export the range and verify it offline, and compare with backups. |
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
