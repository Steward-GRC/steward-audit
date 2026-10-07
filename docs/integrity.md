# Integrity model

## The hash chain

Every record's `record_hash` is the hex SHA-256 of

```text
prev_hash \0 tier \0 action \0 actor_user_id \0 subject \0 group_id \0 occurred_at \0 attributes \0
```

- `prev_hash` is the previous record's `record_hash`, and empty for the first record.
- `occurred_at` is UTC, truncated to microseconds (what Postgres keeps), in RFC 3339 with nanosecond
  digits.
- `attributes` is a JSON object with its keys sorted, `{}` when there are none.
- The NUL after each field stops bytes moving between fields unnoticed.

Changing any stored field, or removing a record, breaks that record's hash or the next record's
link. Personal data (`pii_ciphertext`) is not hashed, so crypto-shred doesn't break the chain.

Records are never deleted. The retention purge tombstones an expired activity record instead: its
action, actor, subject, group, attributes and personal data are cleared and `purged_at` is set,
while its id, tier, times, `prev_hash` and `record_hash` stay. A tombstone's hash can't be
recomputed, so a verifier checks its link and trusts its stored hash; the next record's link and
every checkpoint root over it still cover that hash, so replacing it is caught. A tombstone outside
the activity tier fails verification: nothing else is ever purged.

Appends run in a Serializable transaction that locks the current tip, so concurrent appends queue
up; a serialization conflict is retried by go-postgres. Record ids can have gaps (a rolled-back
insert still uses a sequence value); a gap is not tampering.

The layout is fixed: `internal/chain/golden_test.go` pins it with values from the service this one
replaces, so migrated chains keep verifying.

## Merkle checkpoints

On each interval the checkpointer takes the records after the last checkpoint (at most the batch
size), builds a binary Merkle tree over their hashes, anchors the root and saves the checkpoint
with its record range. After a restart it carries on after the last saved checkpoint.

The tree: a leaf is SHA-256 of a record hash's hex text; a parent is SHA-256 of its two children's
hex texts joined; the last node of an odd level is paired with itself. Inclusion proofs are in
`internal/merkle`.

## RFC 3161 anchoring

The root is anchored by sending a `TimeStampReq` (version 1, SHA-256 of the root's hex text,
`certReq` set) to the time-stamp authority. The reply must be a `TimeStampResp` with status
granted or grantedWithMods; anything else, or a reply that doesn't parse, fails the checkpoint,
and the same records are tried again on the next interval. The DER reply is stored as received in
`audit_checkpoints.tsa_token`.

The service checks only the reply's status. The token's signature, its message imprint and the
authority's certificate chain are checked offline from the stored DER (for example with
`openssl ts -verify`), against the authority's certificates you keep.

## Verifying

`VerifyAuditChain` recomputes every hash and link in a range, seeding the first link with the hash
of the record before the range, and recomputes the root of each checkpoint wholly inside it. A
tombstone's link is checked and its hash taken as stored; `records_purged` says how many there
were.

For an independent check, `ExportAuditSegment` returns the same records and checkpoints, including
each checkpoint's record range and token, so a verifier outside the service can redo all of it and
check the tokens without trusting this server. Each exported tombstone has `purged` set.
