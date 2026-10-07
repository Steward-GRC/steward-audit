// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package store is the audit service's Postgres persistence: the append-only
// record chain, checkpoints, retention and legal holds.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/jackc/pgx/v5"

	"github.com/Steward-GRC/steward-audit/internal/chain"
)

// RecordInput is a new record. The store computes PrevHash and RecordHash.
type RecordInput struct {
	Tier             string // "audit" or "activity"
	Action           string
	ActorUserID      string // empty for system events
	Subject          string
	GroupID          string
	OccurredAt       time.Time
	Attributes       map[string]string // part of the hash
	PIISubjectKey    string            // the key alias PIICiphertext is encrypted under
	PIICiphertext    []byte
	LegalBasisExempt bool       // never purged
	RetainedUntil    *time.Time // nil keeps the record indefinitely
}

// Record is a stored record.
type Record struct {
	ID         int64
	RecordUUID string
	PrevHash   string
	RecordHash string
	// Purged marks a tombstone the retention purge left: its content is
	// cleared and only its id, tier, times, link and hash remain.
	Purged bool
	RecordInput
}

// VerifyRecord is the record as the chain verifier sees it.
func (r Record) VerifyRecord() chain.VerifyRecord {
	return chain.VerifyRecord{
		ID: r.ID, PrevHash: r.PrevHash, RecordHash: r.RecordHash, Tier: r.Tier, Action: r.Action,
		ActorUserID: r.ActorUserID, Subject: r.Subject, GroupID: r.GroupID, OccurredAt: r.OccurredAt,
		Attributes: r.Attributes, Purged: r.Purged,
	}
}

// QueryFilter selects records for a query page. Empty strings don't filter.
// AfterID is the forward cursor; Limit defaults to 50.
type QueryFilter struct {
	Tier        string
	GroupID     string
	ActorUserID string
	Subject     string
	AfterID     int64
	Limit       int
}

// RecentFilter selects records that occurred at or after Since. Empty strings
// don't filter; Limit defaults to 50.
type RecentFilter struct {
	Since     time.Time
	Actor     string
	EventType string
	Limit     int
}

const defaultLimit = 50

const recordColumns = `id, record_uuid, tier, action,
	COALESCE(actor_user_id,''), COALESCE(subject,''), COALESCE(group_id,''),
	occurred_at, attributes, pii_subject_key, pii_ciphertext,
	legal_basis_exempt, retained_until, COALESCE(prev_hash,''), record_hash, purged_at IS NOT NULL`

// RecordStore is the append-only record chain.
type RecordStore struct{ db *postgres.DB }

// NewRecordStore returns a RecordStore on db.
func NewRecordStore(db *postgres.DB) *RecordStore { return &RecordStore{db: db} }

// AppendRecord chains in onto the latest record. It runs Serializable and
// locks the tip, so concurrent appenders queue behind each other; a
// serialization conflict (two appenders at the genesis, say) is retried by
// go-postgres from the top.
func (s *RecordStore) AppendRecord(ctx context.Context, in RecordInput) (*Record, error) {
	attrsJSON, err := marshalAttributes(in.Attributes)
	if err != nil {
		return nil, fmt.Errorf("store: marshal attributes: %w", err)
	}
	var rec *Record
	err = s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		var prevHash string
		err := tx.QueryRow(ctx, `SELECT record_hash FROM audit_records ORDER BY id DESC LIMIT 1 FOR UPDATE`).Scan(&prevHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("store: read chain tip: %w", err)
		}
		recordHash := chain.ComputeHash(prevHash, in.Tier, in.Action, in.ActorUserID, in.Subject, in.GroupID,
			chain.CanonicalTime(in.OccurredAt), in.Attributes)
		r := &Record{RecordInput: in}
		if err := tx.QueryRow(ctx, `
			INSERT INTO audit_records
			    (tier, action, actor_user_id, subject, group_id, occurred_at,
			     attributes, pii_subject_key, pii_ciphertext, legal_basis_exempt,
			     retained_until, prev_hash, record_hash)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
			RETURNING id, record_uuid, prev_hash, record_hash`,
			in.Tier, in.Action, in.ActorUserID, in.Subject, in.GroupID, in.OccurredAt,
			attrsJSON, nilIfEmpty(in.PIISubjectKey), nilIfBytes(in.PIICiphertext),
			in.LegalBasisExempt, in.RetainedUntil, prevHash, recordHash,
		).Scan(&r.ID, &r.RecordUUID, &r.PrevHash, &r.RecordHash); err != nil {
			return fmt.Errorf("store: insert record: %w", err)
		}
		rec = r
		return nil
	}, postgres.WithIsolation(pgx.Serializable))
	if err != nil {
		return nil, err
	}
	return rec, nil
}

// RecordsInRange returns the records with fromID <= id <= toID in id order,
// the order the chain verifies in. Tombstones are included: the chain needs
// their links and hashes.
func (s *RecordStore) RecordsInRange(ctx context.Context, fromID, toID int64) ([]Record, error) {
	return s.query(ctx, `SELECT `+recordColumns+` FROM audit_records WHERE id BETWEEN $1 AND $2 ORDER BY id`, fromID, toID)
}

// QueryRecords returns one page of records matching q, in id order.
// Tombstones are left out: they have nothing left to show.
func (s *RecordStore) QueryRecords(ctx context.Context, q QueryFilter) ([]Record, error) {
	return s.query(ctx, `SELECT `+recordColumns+` FROM audit_records
		 WHERE purged_at IS NULL
		   AND ($1 = '' OR tier = $1)
		   AND ($2 = '' OR group_id = $2)
		   AND ($3 = '' OR actor_user_id = $3)
		   AND ($4 = '' OR subject = $4)
		   AND id > $5
		 ORDER BY id LIMIT $6`,
		q.Tier, q.GroupID, q.ActorUserID, q.Subject, q.AfterID, limitOr(q.Limit))
}

// ListRecentRecords returns records that occurred at or after f.Since, in id
// order, so the page is a stable slice of the chain even when times collide.
// Tombstones are left out.
func (s *RecordStore) ListRecentRecords(ctx context.Context, f RecentFilter) ([]Record, error) {
	return s.query(ctx, `SELECT `+recordColumns+` FROM audit_records
		 WHERE purged_at IS NULL
		   AND occurred_at >= $1
		   AND ($2 = '' OR actor_user_id = $2)
		   AND ($3 = '' OR action = $3)
		 ORDER BY id LIMIT $4`,
		f.Since.UTC(), f.Actor, f.EventType, limitOr(f.Limit))
}

// PrecedingHash returns the hash of the last record before fromID, or "" when
// there is none. A sub-range that doesn't start at the genesis verifies from it.
func (s *RecordStore) PrecedingHash(ctx context.Context, fromID int64) (string, error) {
	var h string
	err := s.db.Querier().QueryRow(ctx,
		`SELECT record_hash FROM audit_records WHERE id < $1 ORDER BY id DESC LIMIT 1`, fromID).Scan(&h)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("store: preceding hash: %w", err)
	}
	return h, nil
}

// HashesAfter returns the hashes of at most limit records after lastID, in id
// order, and the highest id among them (0 when there are none).
func (s *RecordStore) HashesAfter(ctx context.Context, lastID int64, limit int) ([]string, int64, error) {
	rows, err := s.db.Querier().Query(ctx,
		`SELECT id, record_hash FROM audit_records WHERE id > $1 ORDER BY id LIMIT $2`, lastID, limit)
	if err != nil {
		return nil, 0, fmt.Errorf("store: hashes after %d: %w", lastID, err)
	}
	defer rows.Close()
	var hashes []string
	var maxID int64
	for rows.Next() {
		var h string
		if err := rows.Scan(&maxID, &h); err != nil {
			return nil, 0, fmt.Errorf("store: scan hash: %w", err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("store: hashes after %d: %w", lastID, err)
	}
	return hashes, maxID, nil
}

// TombstonePII clears the personal data of the activity records encrypted
// under subjectKey and returns how many it cleared. Audit-tier records are
// kept under their own legal basis and never touched. Personal data isn't
// hashed, so the chain still verifies.
func (s *RecordStore) TombstonePII(ctx context.Context, subjectKey string) (int, error) {
	tag, err := s.db.Querier().Exec(ctx, `
		UPDATE audit_records SET pii_subject_key = NULL, pii_ciphertext = NULL
		 WHERE tier = 'activity' AND pii_subject_key = $1`, subjectKey)
	if err != nil {
		return 0, fmt.Errorf("store: tombstone personal data: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

func (s *RecordStore) query(ctx context.Context, sql string, args ...any) ([]Record, error) {
	rows, err := s.db.Querier().Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query records: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var (
			r             Record
			attrs         []byte
			piiKey        *string
			retainedUntil *time.Time
		)
		if err := rows.Scan(&r.ID, &r.RecordUUID, &r.Tier, &r.Action, &r.ActorUserID, &r.Subject, &r.GroupID,
			&r.OccurredAt, &attrs, &piiKey, &r.PIICiphertext, &r.LegalBasisExempt, &retainedUntil,
			&r.PrevHash, &r.RecordHash, &r.Purged); err != nil {
			return nil, fmt.Errorf("store: scan record: %w", err)
		}
		if r.Attributes, err = unmarshalAttributes(attrs); err != nil {
			return nil, fmt.Errorf("store: record %d attributes: %w", r.ID, err)
		}
		if piiKey != nil {
			r.PIISubjectKey = *piiKey
		}
		r.RetainedUntil = retainedUntil
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query records: %w", err)
	}
	return out, nil
}

func limitOr(n int) int {
	if n <= 0 {
		return defaultLimit
	}
	return n
}

func marshalAttributes(m map[string]string) ([]byte, error) {
	if len(m) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(m)
}

func unmarshalAttributes(b []byte) (map[string]string, error) {
	if len(b) == 0 || string(b) == "{}" {
		return nil, nil
	}
	out := map[string]string{}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nilIfBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
