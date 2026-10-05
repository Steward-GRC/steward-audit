# Tiers, retention, legal holds and crypto-shred

## Tiers

| Tier | Holds | Default retention |
| --- | --- | --- |
| `audit` | Regulatory records: approvals, publications, acknowledgements, exports, shreds | Indefinite |
| `activity` | Operational records: views, sign-ins | 730 days |

Retention per tier is in `retention_policies` (NULL is indefinite). A record's own `retained_until`
decides when it may go.

## Purge and legal holds

The purge deletes activity records whose `retained_until` has passed, unless the record is
legal-basis exempt or an unreleased legal hold matches it. A hold matches on subject, on group, or
both; an empty filter matches everything, so a hold with neither freezes the whole activity tier.
Audit-tier records are never purged.

The purge and the hold store are in `internal/store/retention.go`. Nothing runs the purge on a
schedule yet, and there is no API for holds yet.

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
needs a key service that destroys the key material itself. Nothing exposes shred through the API
yet.

Keys must move with the audit data in a migration, or erased subjects become readable again.
