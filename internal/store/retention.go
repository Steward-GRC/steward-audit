// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
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

// CreateLegalHold stores a hold and returns its UUID.
func (s *RetentionStore) CreateLegalHold(ctx context.Context, in LegalHoldInput) (string, error) {
	var id string
	if err := s.db.Querier().QueryRow(ctx, `
		INSERT INTO legal_holds (subject_filter, group_filter, reason, held_by)
		VALUES ($1,$2,$3,$4) RETURNING hold_uuid`,
		nilIfEmpty(in.SubjectFilter), nilIfEmpty(in.GroupFilter), in.Reason, in.HeldBy,
	).Scan(&id); err != nil {
		return "", fmt.Errorf("store: create legal hold: %w", err)
	}
	return id, nil
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

// ReleaseLegalHold releases a hold.
func (s *RetentionStore) ReleaseLegalHold(ctx context.Context, holdUUID string) error {
	if _, err := s.db.Querier().Exec(ctx,
		`UPDATE legal_holds SET released_at = $1 WHERE hold_uuid = $2`, time.Now().UTC(), holdUUID); err != nil {
		return fmt.Errorf("store: release legal hold: %w", err)
	}
	return nil
}

// PurgeExpired deletes activity records past retained_until that are not
// legal-basis exempt and match no unreleased hold, and returns how many it
// deleted. Audit-tier records are never purged.
func (s *RetentionStore) PurgeExpired(ctx context.Context, now time.Time) (int64, error) {
	tag, err := s.db.Querier().Exec(ctx, `
		DELETE FROM audit_records
		WHERE tier = 'activity'
		  AND legal_basis_exempt = FALSE
		  AND retained_until IS NOT NULL
		  AND retained_until < $1
		  AND NOT EXISTS (
		      SELECT 1 FROM legal_holds lh
		      WHERE lh.released_at IS NULL
		        AND (lh.subject_filter IS NULL OR lh.subject_filter = audit_records.subject)
		        AND (lh.group_filter  IS NULL OR lh.group_filter  = audit_records.group_id))`, now)
	if err != nil {
		return 0, fmt.Errorf("store: purge expired: %w", err)
	}
	return tag.RowsAffected(), nil
}
