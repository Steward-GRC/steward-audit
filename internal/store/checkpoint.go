// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
)

// CheckpointInput is a new checkpoint: a Merkle root over the records
// FromRecordID to ToRecordID and the anchor's reply.
type CheckpointInput struct {
	FromRecordID int64
	ToRecordID   int64
	MerkleRoot   string
	AnchorType   string
	AnchorURL    string
	TSAToken     []byte
	AnchoredAt   time.Time
	AnchorStatus string // "pending", "anchored" or "failed"
}

// Checkpoint is a stored checkpoint.
type Checkpoint struct {
	ID             int64
	CheckpointUUID string
	CreatedAt      time.Time
	CheckpointInput
}

const checkpointColumns = `id, checkpoint_uuid, created_at, from_record_id, to_record_id,
	merkle_root, anchor_type, COALESCE(anchor_url,''), tsa_token, anchored_at, anchor_status`

// CheckpointStore keeps the append-only checkpoints.
type CheckpointStore struct{ db *postgres.DB }

// NewCheckpointStore returns a CheckpointStore on db.
func NewCheckpointStore(db *postgres.DB) *CheckpointStore { return &CheckpointStore{db: db} }

// SaveCheckpoint stores in.
func (s *CheckpointStore) SaveCheckpoint(ctx context.Context, in CheckpointInput) (*Checkpoint, error) {
	cp := Checkpoint{CheckpointInput: in}
	err := s.db.Querier().QueryRow(ctx, `
		INSERT INTO audit_checkpoints
			(from_record_id, to_record_id, merkle_root, anchor_type, anchor_url, tsa_token, anchored_at, anchor_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, checkpoint_uuid, created_at`,
		in.FromRecordID, in.ToRecordID, in.MerkleRoot, in.AnchorType, nilIfEmpty(in.AnchorURL), in.TSAToken,
		in.AnchoredAt, in.AnchorStatus,
	).Scan(&cp.ID, &cp.CheckpointUUID, &cp.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("store: save checkpoint: %w", err)
	}
	return &cp, nil
}

// CheckpointsInRange returns the checkpoints wholly inside [fromID, toID], in
// id order.
func (s *CheckpointStore) CheckpointsInRange(ctx context.Context, fromID, toID int64) ([]Checkpoint, error) {
	return s.query(ctx, `SELECT `+checkpointColumns+` FROM audit_checkpoints
		 WHERE from_record_id >= $1 AND to_record_id <= $2 ORDER BY id`, fromID, toID)
}

// ListCheckpoints returns the newest limit checkpoints, newest first.
func (s *CheckpointStore) ListCheckpoints(ctx context.Context, limit int) ([]Checkpoint, error) {
	return s.query(ctx, `SELECT `+checkpointColumns+` FROM audit_checkpoints ORDER BY id DESC LIMIT $1`, limit)
}

// LastCheckpointedID returns the last record a checkpoint covers, or 0.
func (s *CheckpointStore) LastCheckpointedID(ctx context.Context) (int64, error) {
	var id int64
	if err := s.db.Querier().QueryRow(ctx, `SELECT COALESCE(MAX(to_record_id), 0) FROM audit_checkpoints`).Scan(&id); err != nil {
		return 0, fmt.Errorf("store: last checkpointed record: %w", err)
	}
	return id, nil
}

func (s *CheckpointStore) query(ctx context.Context, sql string, args ...any) ([]Checkpoint, error) {
	rows, err := s.db.Querier().Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query checkpoints: %w", err)
	}
	defer rows.Close()
	var out []Checkpoint
	for rows.Next() {
		var cp Checkpoint
		var anchoredAt *time.Time
		if err := rows.Scan(&cp.ID, &cp.CheckpointUUID, &cp.CreatedAt, &cp.FromRecordID, &cp.ToRecordID,
			&cp.MerkleRoot, &cp.AnchorType, &cp.AnchorURL, &cp.TSAToken, &anchoredAt, &cp.AnchorStatus); err != nil {
			return nil, fmt.Errorf("store: scan checkpoint: %w", err)
		}
		if anchoredAt != nil {
			cp.AnchoredAt = *anchoredAt
		}
		out = append(out, cp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: query checkpoints: %w", err)
	}
	return out, nil
}
