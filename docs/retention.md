# Tiers, retention, legal holds and crypto-shred

## Tiers

| Tier | Holds | Default retention |
| --- | --- | --- |
| `audit` | Regulatory records: approvals, publications, acknowledgements, exports, shreds | Indefinite |
| `activity` | Operational records: views, sign-ins | 730 days |

Retention per tier is in `retention_policies` (NULL is indefinite). A record's own `retained_until`
decides when it may go.

## Purge and legal holds

The purge tombstones activity records whose `retained_until` has passed, unless the record is
legal-basis exempt or an unreleased legal hold matches it. A hold matches on subject, on group, or
both; an empty filter matches everything, so a hold with neither freezes the whole activity tier.
Audit-tier records are never purged.

A tombstone keeps its id, tier, times, link and hash and loses its action, actor, subject, group,
attributes and personal data; `purged_at` marks it. Rows are never deleted, so the chain and every
checkpoint still verify across a purged range, and no checkpoint loses the row it starts or ends on
(see [the integrity model](integrity.md)). Queries and the tail leave tombstones out; exports and
verify include them.

The purge runs once at start-up and then every `AUDIT_PURGE_INTERVAL` (default an hour). Every
replica schedules it, and a run takes the Postgres advisory lock `store.PurgeLockKey` for its
transaction, so only one replica purges at a time; the others skip that run. A run that
tombstoned anything appends an audit-tier, legal-basis-exempt `audit_log.purged` record with the
count.

Legal holds are managed through the API (`CreateLegalHold`, `ListLegalHolds`,
`ReleaseLegalHold`), each needing `compliance.manage` and each recorded in the audit tier as
`legal_hold.created`, `legal_hold.listed` or `legal_hold.released`, naming the caller.

## Crypto-shred

Personal data is stored AES-256-GCM encrypted under a per-subject key (`pii_subject_key` names it).
Shredding a subject:

1. destroys the subject's key, so the data can't be read again, backups included;
2. clears the personal-data columns on the subject's activity records;
3. writes an audit-tier, legal-basis-exempt `subject.shredded` record with the reason and the
   number of records cleared.

The key goes first: if step 2 or 3 fails the subject is already protected, and the error
(`ErrPartialShred`) says which step to retry. Audit-tier records keep their ciphertext under their
own legal basis; with the key gone it is unreadable all the same.

The only key provider today derives keys from a master key and records each subject's key alias,
and its erasure, in `subject_encryption_keys`, so an erasure survives a restart. It is for
development and tests: anyone holding the master key can still derive an erased key, so production
needs a key service that destroys the key material itself.

`ShredSubject` runs a shred through the API; it needs `compliance.manage`. The running service
encrypts nothing it ingests yet and holds no key material, so it erases a subject by recording the
erasure in `subject_encryption_keys`, which refuses the key from then on, then clears the subject's
personal-data columns and writes `subject.shredded`. If the key is erased but a later step fails,
the call returns `AUDIT_SHRED_INCOMPLETE`: run it again.

Keys must move with the audit data in a migration, or erased subjects become readable again.
