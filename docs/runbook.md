# Runbook

## Start-up

The service applies the migrations, connects to Postgres, starts the checkpointer (when
`AUDIT_TSA_URL` is set), starts the event consumer and serves gRPC. A bad setting stops it at once
with every problem listed. It stops cleanly on SIGINT or SIGTERM, draining in-flight calls for up to
ten seconds.

## Probes

Readiness follows go-buildinfo's dependency checker. Each check has a 2-second timeout, and a result
is reused for 5 seconds.

| Dependency | Required | When it's down |
| --- | --- | --- |
| `postgres` | yes | Not ready: events can't be stored and nothing can be read. |
| `rabbitmq` | yes | Not ready: the consumer can't take events. |
| `jwks` | yes, while service-to-service authentication is on | Not ready: no caller can be verified. A good fetch keeps it up for a minute; a failure is retried on the next probe. |
| `workloadauth` | no, reported only with `WORKLOAD_AUTH=disabled` | Always degraded, with a warning logged every five minutes. Never run like this outside local development. |

- **HTTP on `PROBE_PORT` (8080):** `GET /livez` is 200 while the process is up and never checks a
  dependency. `GET /readyz` is 200 while ready and 503 while a required dependency is down; its JSON
  body lists every dependency with its state, whether it's required, the error class, the check
  time and the version.
- **gRPC on `GRPC_PORT`:** `grpc.health.v1` with the service name `liveness` reports the process
  only. The empty name and `readiness` follow readiness. Every `Health/Check` answer, and no other
  call, carries these response headers:
  - `steward-version`: the image tag, `dev` for an unstamped build;
  - `steward-commit`: the source commit, falling back to the binary's `vcs.revision`, then `unknown`;
  - `steward-dep-postgres`: the server version from `SHOW server_version`;
  - `steward-depstate-<name>`: `ok`, `degraded` or `down`.

  There's no `steward-dep-rabbitmq` yet: the RabbitMQ client library doesn't expose the broker's
  version from the handshake.
- Point liveness at `/livez` (or the `liveness` service), never at a dependency: a database outage
  would restart every replica. Point readiness at `/readyz` (or the `readiness` service).
- Readiness recovers on its own once the dependency is back.

## Build stamp

The Dockerfile takes two build arguments and stamps them into go-buildinfo:

| Argument | Value |
| --- | --- |
| `VERSION` | The image tag. Default `dev`. |
| `COMMIT` | The full source SHA. Empty reports `unknown`, since the build context has no `.git`. |

```sh
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

The start-up log line `starting` carries the same version and commit.

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
| `retention purge ran` | A purge run finished (`records_purged`, `duration_ms`) | Nothing. Other replicas log `retention purge skipped` at debug while one holds the lock. |
| `retention purge failed` | A purge run failed | Nothing is half-done (the run is one transaction); it is retried on the next interval. Check Postgres. |
| `recording the retention purge failed` | Records were tombstoned but `audit_log.purged` wasn't written | Check Postgres; the log line has the count. |
| `crypto-shred incomplete: the key is erased, retry the shred` | A shred erased the key but didn't clear the records or write `subject.shredded` | Run `ShredSubject` again with the same subject and reason. |
| `legal-hold meta-audit record failed` | A hold was created, listed or released but not recorded | Check Postgres; record it by hand from the log line. |

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
