// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package shred crypto-shreds a subject: it destroys the subject's key, clears
// the now-unreadable ciphertext from activity records, and writes an audit
// record of the shred.
//
// The key goes first. Once it is gone the data is unrecoverable whatever
// happens next, so a later failure leaves the subject protected and is
// reported as ErrPartialShred for the caller to finish.
package shred

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/kms"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

// ErrInvalidRequest means a required argument was empty; nothing was changed.
var ErrInvalidRequest = errors.New("shred: invalid request")

// ErrPartialShred means the key is destroyed but tombstoning or the meta-audit
// record failed. Retry that step.
var ErrPartialShred = errors.New("shred: key erased, shred incomplete")

// KeyEraser destroys a subject key.
type KeyEraser interface {
	Delete(ctx context.Context, alias string) error
}

// PIITombstoner clears personal data on the subject's activity records only.
type PIITombstoner interface {
	TombstonePII(ctx context.Context, subjectKey string) (int, error)
}

// MetaAuditAppender writes the record of the shred.
type MetaAuditAppender interface {
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
}

// ShredResult is a completed shred.
type ShredResult struct {
	SubjectKey     string
	RowsTombstoned int
	MetaRecordID   int64
}

// CryptoShredService runs a shred.
type CryptoShredService struct {
	kms      KeyEraser
	tombstn  PIITombstoner
	appender MetaAuditAppender
}

// NewCryptoShredService returns a CryptoShredService.
func NewCryptoShredService(k KeyEraser, t PIITombstoner, a MetaAuditAppender) *CryptoShredService {
	return &CryptoShredService{kms: k, tombstn: t, appender: a}
}

// ShredSubject shreds subjectKey. reason and actorUserID are required: the
// "subject.shredded" record must say why and who.
func (s *CryptoShredService) ShredSubject(ctx context.Context, subjectKey, reason, actorUserID string) (ShredResult, error) {
	switch {
	case subjectKey == "":
		return ShredResult{}, fmt.Errorf("%w: a subject key is required", ErrInvalidRequest)
	case reason == "":
		return ShredResult{}, fmt.Errorf("%w: a reason is required", ErrInvalidRequest)
	case actorUserID == "":
		return ShredResult{}, fmt.Errorf("%w: an actor is required", ErrInvalidRequest)
	}

	if err := s.kms.Delete(ctx, subjectKey); err != nil {
		return ShredResult{}, fmt.Errorf("shred: delete key %q: %w", subjectKey, err)
	}
	rows, err := s.tombstn.TombstonePII(ctx, subjectKey)
	if err != nil {
		return ShredResult{}, fmt.Errorf("%w: tombstone %q (retry it): %w", ErrPartialShred, subjectKey, err)
	}
	meta, err := s.appender.AppendRecord(ctx, store.RecordInput{
		Tier:             "audit",
		Action:           "subject.shredded",
		ActorUserID:      actorUserID,
		Subject:          subjectKey,
		OccurredAt:       time.Now().UTC(),
		LegalBasisExempt: true,
		Attributes:       map[string]string{"reason": reason, "rows_tombstoned": strconv.Itoa(rows)},
	})
	if err != nil {
		return ShredResult{}, fmt.Errorf("%w: %d rows tombstoned for %q but the meta-audit record failed (retry it): %w",
			ErrPartialShred, rows, subjectKey, err)
	}
	return ShredResult{SubjectKey: subjectKey, RowsTombstoned: rows, MetaRecordID: meta.ID}, nil
}

var _ KeyEraser = (kms.KeyProvider)(nil)
