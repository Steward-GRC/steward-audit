# steward-audit 🔐

> 🧭 Tamper-evident, hash-chained audit service for Steward

The audit service is Steward's append-only record of what happened and who did it. Services publish
events; each one becomes a link in a SHA-256 hash chain, so changing or removing any stored record is
detected on verification.

- **Hash chain:** every record commits to the one before it.
- **Merkle checkpoints:** record ranges are rolled up into a Merkle root and anchored with an
  RFC 3161 time-stamp authority.
- **Two tiers:** `audit` records are kept indefinitely, `activity` records for a set time, with legal
  holds to stop the purge.
- **Crypto-shred:** personal data is encrypted per subject, and destroying the key erases it without
  breaking the chain.
- **Verify:** on the server, or offline from an export.

## 🚀 Run

```bash
cp .env.example .env   # a local Postgres and RabbitMQ
task run
```

Or build the image with `docker build -t steward-audit .`. Settings are in
[configuration](docs/configuration.md).

## 📚 Docs

- [API](docs/api.md): the events in and the gRPC service.
- [Integrity model](docs/integrity.md): the chain, checkpoints, anchoring and verifying.
- [Tiers, retention and crypto-shred](docs/retention.md).
- [Configuration](docs/configuration.md).
- [Runbook](docs/runbook.md).
- [Error codes](docs/error-codes.md).

## 🛠 Develop

```bash
task build       # go build ./...
task test        # go test ./... (the store tests start Postgres with testcontainers)
task test-race   # the same with the race detector
task lint        # gofmt check + golangci-lint + yamllint
task proto       # buf lint + buf generate
task license     # check Apache-2.0 headers (golic)
```

Set `DATABASE_TEST_DSN` to run the store tests against an existing Postgres instead of a container.

## 🙏 Acknowledgements

Steward was originally written by [@Bugs5382](https://github.com/Bugs5382).

## ⚖️ License

Apache-2.0 (c) 2026 The Steward Authors
