// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package checkpoint runs the loop that builds a Merkle root over newly
// appended records, anchors it, and saves the checkpoint.
package checkpoint

import (
	"context"
	"time"

	log "github.com/Bugs5382/go-log"

	"github.com/Steward-GRC/steward-audit/internal/anchor"
	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

// RecordReader returns the hashes of the records after lastID, in id order,
// and the highest id among them. No records means no hashes.
type RecordReader interface {
	HashesSince(ctx context.Context, lastID int64) (hashes []string, maxID int64, err error)
}

// SaveInput is one anchored checkpoint.
type SaveInput struct {
	FromID     int64
	ToID       int64
	MerkleRoot string
	AnchorType string
	AnchorURL  string
	RawToken   []byte
	AnchoredAt string
}

// CheckpointWriter persists an anchored checkpoint.
type CheckpointWriter interface {
	SaveCheckpoint(ctx context.Context, in SaveInput) error
}

// Scheduler checkpoints on a fixed interval. The reader bounds each batch; a
// backlog drains one batch per tick. A tick that fails is retried over the same
// records on the next one.
type Scheduler struct {
	reader   RecordReader
	writer   CheckpointWriter
	anc      anchor.Anchorer
	interval time.Duration
	lastID   int64
	logger   log.Logger
}

// New returns a scheduler that starts at the genesis.
func New(reader RecordReader, writer CheckpointWriter, anc anchor.Anchorer, interval time.Duration) *Scheduler {
	return &Scheduler{reader: reader, writer: writer, anc: anc, interval: interval, logger: log.Nop()}
}

// ResumeAfter starts the scheduler after record lastID, the end of the last
// saved checkpoint, so a restart doesn't anchor the same records again.
func (s *Scheduler) ResumeAfter(lastID int64) *Scheduler {
	s.lastID = lastID
	return s
}

// WithLogger sets the logger tick failures go to.
func (s *Scheduler) WithLogger(l log.Logger) *Scheduler {
	s.logger = l
	return s
}

// Run checkpoints on every tick until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.RunOnce(ctx); err != nil && ctx.Err() == nil {
				s.logger.Ctx(ctx).Error(err, "checkpoint tick failed", log.F("after_record_id", s.lastID))
			}
		}
	}
}

// RunOnce makes at most one checkpoint over the records after the last one.
func (s *Scheduler) RunOnce(ctx context.Context) error {
	hashes, maxID, err := s.reader.HashesSince(ctx, s.lastID)
	if err != nil || len(hashes) == 0 {
		return err
	}
	root, _ := merkle.BuildTree(hashes)
	started := time.Now()
	result, err := s.anc.Anchor(ctx, root)
	if err != nil {
		return err
	}
	if err := s.writer.SaveCheckpoint(ctx, SaveInput{
		FromID:     s.lastID + 1,
		ToID:       maxID,
		MerkleRoot: root,
		AnchorType: s.anc.Type(),
		AnchorURL:  s.anc.URL(),
		RawToken:   result.RawToken,
		AnchoredAt: result.AnchoredAt,
	}); err != nil {
		return err
	}
	s.logger.Ctx(ctx).Info("checkpoint anchored",
		log.F("from_record_id", s.lastID+1), log.F("to_record_id", maxID),
		log.F("records", len(hashes)), log.F("anchor", s.anc.Type()), log.F("duration_ms", time.Since(started).Milliseconds()))
	s.lastID = maxID
	return nil
}
