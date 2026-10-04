# AGENTS.md - steward-audit

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Tamper-evident, hash-chained audit service for Steward: a Go gRPC service that consumes audit
events from RabbitMQ into an append-only SHA-256 hash chain in Postgres, anchors Merkle checkpoints
with an RFC 3161 time-stamp authority, and serves query, export, verify and tail RPCs.

Two things to know before changing it:

- The chain hash and Merkle layouts are fixed (`internal/chain/golden_test.go`). Changing them
  breaks every stored and migrated chain.
- Attributes and personal data never go on the wire, and store errors never reach the caller: they
  are coded through `internal/auditerr`.

## Layout

- `cmd/server/` - the entry point and wiring
- `proto/steward/audit/v1/`, `gen/go/` - the API and its generated stubs (`task proto`)
- `internal/chain`, `internal/merkle` - the hash chain, the Merkle tree, verification
- `internal/anchor`, `internal/checkpoint` - RFC 3161 anchoring and the checkpointer
- `internal/store` - Postgres stores; `migrations/` - the baseline schema
- `internal/ingest` - the event consumer; `internal/server` - the gRPC handlers and server
- `internal/kms`, `internal/pii`, `internal/shred` - keys, encryption, crypto-shred
- `internal/auditerr` - coded errors (band 2); `internal/fixture` - test sample data

## Build, test, lint

- Build: `task build`
- Test: `task test` (the store tests need Docker for testcontainers, or `DATABASE_TEST_DSN`)
- Lint: `task lint`; proto: `task proto`
- License headers: `task license`; error-code doc: `task docs`

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Test data comes from `internal/fixture` (the design brief's sample data); don't type literals.
- Dependencies are released versions only: never a `replace`, a pseudo-version or a committed
  `go.work`.
