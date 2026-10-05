-- Copyright 2026 The Steward Authors
-- SPDX-License-Identifier: Apache-2.0

-- The append-only, hash-chained store of audit and activity events. Rows are
-- never updated by the application except to tombstone personal data, and are
-- deleted only by the activity-tier retention purge.
CREATE TABLE audit_records (
    id              BIGSERIAL PRIMARY KEY,
    record_uuid     UUID        NOT NULL DEFAULT gen_random_uuid(),
    tier            TEXT        NOT NULL CHECK (tier IN ('audit','activity')),
    action          TEXT        NOT NULL,
    actor_user_id   TEXT,
    subject         TEXT,
    group_id        TEXT,
    occurred_at     TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    attributes      JSONB       NOT NULL DEFAULT '{}',
    -- Encrypted personal data and the key alias it is encrypted under.
    pii_subject_key TEXT,
    pii_ciphertext  BYTEA,
    -- The chain: prev_hash is empty for the genesis record.
    prev_hash       TEXT,
    record_hash     TEXT    NOT NULL,
    legal_basis_exempt BOOLEAN NOT NULL DEFAULT FALSE,
    retained_until  TIMESTAMPTZ,
    UNIQUE (record_uuid)
);

CREATE INDEX audit_records_group_id_idx      ON audit_records (group_id);
CREATE INDEX audit_records_actor_idx         ON audit_records (actor_user_id);
CREATE INDEX audit_records_tier_occurred_idx ON audit_records (tier, occurred_at);
CREATE INDEX audit_records_subject_idx       ON audit_records (subject);

-- A Merkle root over a record range and the RFC 3161 token anchoring it.
CREATE TABLE audit_checkpoints (
    id              BIGSERIAL   PRIMARY KEY,
    checkpoint_uuid UUID        NOT NULL DEFAULT gen_random_uuid(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    from_record_id  BIGINT      NOT NULL REFERENCES audit_records(id),
    to_record_id    BIGINT      NOT NULL REFERENCES audit_records(id),
    merkle_root     TEXT        NOT NULL,
    anchor_type     TEXT        NOT NULL DEFAULT 'rfc3161',
    anchor_url      TEXT,
    tsa_token       BYTEA,
    anchored_at     TIMESTAMPTZ,
    anchor_status   TEXT        NOT NULL DEFAULT 'pending'
                                CHECK (anchor_status IN ('pending','anchored','failed')),
    UNIQUE (checkpoint_uuid)
);

-- Retention per tier, in days; NULL keeps records indefinitely.
CREATE TABLE retention_policies (
    tier            TEXT PRIMARY KEY CHECK (tier IN ('audit','activity')),
    retain_days     INT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO retention_policies (tier, retain_days) VALUES
    ('audit',    NULL),
    ('activity', 730);

-- Legal holds stop the purge for matching records. A NULL filter matches all.
CREATE TABLE legal_holds (
    id              BIGSERIAL   PRIMARY KEY,
    hold_uuid       UUID        NOT NULL DEFAULT gen_random_uuid(),
    subject_filter  TEXT,
    group_filter    TEXT,
    reason          TEXT        NOT NULL,
    held_by         TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    released_at     TIMESTAMPTZ,
    UNIQUE (hold_uuid)
);

-- The crypto-shred key registry: one key alias per subject; erased_at is set
-- when the key is destroyed.
CREATE TABLE subject_encryption_keys (
    id              BIGSERIAL   PRIMARY KEY,
    subject_id      TEXT        NOT NULL UNIQUE,
    key_alias       TEXT        NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    erased_at       TIMESTAMPTZ
);
