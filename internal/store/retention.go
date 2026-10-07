// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"github.com/jackc/pgx/v5"
)

// LegalHoldInput is a new legal hold. An empty filter matches everything, so a
// hold with neither filter freezes the whole activity tier.
type LegalHoldInput struct {
	SubjectFilter string
	GroupFilter   string
	Reason        string
	HeldBy        string
}

// RetentionStore keeps the per-tier retention, the legal holds, and runs the
// activity-tier purge.
type RetentionStore struct{ db *postgres.DB }

// NewRetentionStore returns a RetentionStore on db.
func NewRetentionStore(db *postgres.DB) *RetentionStore { return &RetentionStore{db: db} }

// SetRetentionDays sets the tier's retention. Both tiers are seeded by the
// baseline, so this only updates.
func (s *RetentionStore) SetRetentionDays(ctx context.Context, tier string, days int) error {
	if _, err := s.db.Querier().Exec(ctx,
		`UPDATE retention_policies SET retain_days = $1, updated_at = now() WHERE tier = $2`, days, tier); err != nil {
		return fmt.Errorf("store: set retention: %w", err)
	}
	return nil
}

// GetRetentionDays returns the tier's retention; nil means indefinite.
func (s *RetentionStore) GetRetentionDays(ctx context.Context, tier string) (*int, error) {
	var days *int
	if err := s.db.Querier().QueryRow(ctx, `SELECT retain_days FROM retention_policies WHERE tier = $1`, tier).Scan(&days); err != nil {
		return nil, fmt.Errorf("store: get retention: %w", err)
	}
	return days, nil
}

// ErrHoldNotFound means no unreleased hold has that UUID.
var ErrHoldNotFound = errors.New("store: no active legal hold with that id")

// LegalHold is a stored hold. ReleasedAt is nil while it is in force.
type LegalHold struct {
	UUID          string
	SubjectFilter string
	GroupFilter   string
	Reason        string
	HeldBy        string
	CreatedAt     time.Time
	ReleasedAt    *time.Time
}

const holdColumns = `hold_uuid::text, COALESCE(subject_filter,''), COALESCE(group_filter,''), reason, held_by,
	created_at, released_at`

func scanHold(row pgx.Row) (LegalHold, error) {
	var h LegalHold
	err := row.Scan(&h.UUID, &h.SubjectFilter, &h.GroupFilter, &h.Reason, &h.HeldBy, &h.CreatedAt, &h.ReleasedAt)
	return h, err
}

// CreateLegalHold stores a hold.
func (s *RetentionStore) CreateLegalHold(ctx context.Context, in LegalHoldInput) (LegalHold, error) {
	h, err := scanHold(s.db.Querier().QueryRow(ctx, `
		INSERT INTO legal_holds (subject_filter, group_filter, reason, held_by)
		VALUES ($1,$2,$3,$4) RETURNING `+holdColumns,
		nilIfEmpty(in.SubjectFilter), nilIfEmpty(in.GroupFilter), in.Reason, in.HeldBy))
	if err != nil {
		return LegalHold{}, fmt.Errorf("store: create legal hold: %w", err)
	}
	return h, nil
}

// ListLegalHolds returns the holds in force, oldest first, or every hold when
// includeReleased is set.
func (s *RetentionStore) ListLegalHolds(ctx context.Context, includeReleased bool) ([]LegalHold, error) {
	rows, err := s.db.Querier().Query(ctx, `SELECT `+holdColumns+` FROM legal_holds
		WHERE $1 OR released_at IS NULL ORDER BY id`, includeReleased)
	if err != nil {
		return nil, fmt.Errorf("store: list legal holds: %w", err)
	}
	defer rows.Close()
	var out []LegalHold
	for rows.Next() {
		h, err := scanHold(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan legal hold: %w", err)
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: list legal holds: %w", err)
	}
	return out, nil
}

// IsUnderLegalHold reports whether an unreleased hold matches the subject and
// group.
func (s *RetentionStore) IsUnderLegalHold(ctx context.Context, subject, groupID string) (bool, error) {
	var held bool
	if err := s.db.Querier().QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM legal_holds
		 WHERE released_at IS NULL
		   AND (subject_filter IS NULL OR subject_filter = $1)
		   AND (group_filter  IS NULL OR group_filter  = $2))`, subject, groupID).Scan(&held); err != nil {
		return false, fmt.Errorf("store: legal hold check: %w", err)
	}
	return held, nil
}

// ReleaseLegalHold releases the unreleased hold holdUUID and returns it, or
// ErrHoldNotFound.
func (s *RetentionStore) ReleaseLegalHold(ctx context.Context, holdUUID string) (LegalHold, error) {
	h, err := scanHold(s.db.Querier().QueryRow(ctx, `
		UPDATE legal_holds SET released_at = $1
		 WHERE hold_uuid::text = $2 AND released_at IS NULL
		RETURNING `+holdColumns, time.Now().UTC(), holdUUID))
	if errors.Is(err, pgx.ErrNoRows) {
		return LegalHold{}, ErrHoldNotFound
	}
	if err != nil {
		return LegalHold{}, fmt.Errorf("store: release legal hold: %w", err)
	}
	return h, nil
}

// PurgeLockKey is the Postgres advisory lock a purge run holds, so only one
// replica purges at a time.
const PurgeLockKey int64 = 0x5354_4155_5052_4700 // "STAUPRG"

// PurgeResult is one purge run.
type PurgeResult struct {
	// Purged is how many records were tombstoned.
	Purged int64
	// Skipped means another replica held the purge lock, so nothing ran.
	Skipped bool
}

// PurgeExpired tombstones the activity records past retained_until that are
// not legal-basis exempt and match no unreleased hold. A tombstone keeps its
// id, tier, times, link and hash, so the chain and every checkpoint over it
// still verify, and no checkpoint loses the row it is bounded by; its action,
// actor, subject, group, attributes and personal data are cleared. Audit-tier
// records are never purged. The run holds PurgeLockKey for its transaction and
// is skipped while another replica holds it.
func (s *RetentionStore) PurgeExpired(ctx context.Context, now time.Time) (PurgeResult, error) {
	var res PurgeResult
	err := s.db.RunInTx(ctx, func(tx pgx.Tx) error {
		res = PurgeResult{}
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, PurgeLockKey).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			res.Skipped = true
			return nil
		}
		tag, err := tx.Exec(ctx, `
			UPDATE audit_records
			   SET action = '', actor_user_id = NULL, subject = NULL, group_id = NULL, attributes = '{}',
			       pii_subject_key = NULL, pii_ciphertext = NULL, purged_at = $1
			 WHERE tier = 'activity'
			   AND purged_at IS NULL
			   AND legal_basis_exempt = FALSE
			   AND retained_until IS NOT NULL
			   AND retained_until < $1
			   AND NOT EXISTS (
			       SELECT 1 FROM legal_holds lh
			       WHERE lh.released_at IS NULL
			         AND (lh.subject_filter IS NULL OR lh.subject_filter = audit_records.subject)
			         AND (lh.group_filter  IS NULL OR lh.group_filter  = audit_records.group_id))`, now)
		if err != nil {
			return err
		}
		res.Purged = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return PurgeResult{}, fmt.Errorf("store: purge expired: %w", err)
	}
	return res, nil
}
