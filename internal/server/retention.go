// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/auditerr"
	"github.com/Steward-GRC/steward-audit/internal/shred"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

// HoldStore keeps the legal holds.
type HoldStore interface {
	CreateLegalHold(ctx context.Context, in store.LegalHoldInput) (store.LegalHold, error)
	ListLegalHolds(ctx context.Context, includeReleased bool) ([]store.LegalHold, error)
	ReleaseLegalHold(ctx context.Context, holdUUID string) (store.LegalHold, error)
}

// Shredder crypto-shreds a subject and records the shred.
type Shredder interface {
	ShredSubject(ctx context.Context, subjectKey, reason, actorUserID string) (shred.ShredResult, error)
}

// WithRetention sets the legal-hold store.
func (s *AuditServer) WithRetention(h HoldStore) *AuditServer {
	s.holds = h
	return s
}

// WithShredder sets the crypto-shred service.
func (s *AuditServer) WithShredder(sh Shredder) *AuditServer {
	s.shredder = sh
	return s
}

// retentionCaller authenticates the requester and checks compliance.manage,
// which every shred and legal-hold call needs.
func retentionCaller(r *auditv1.RequesterIdentity) (caller, error) {
	who, err := callerFrom(r)
	if err != nil {
		return caller{}, err
	}
	if !who.managesRetention {
		return caller{}, auditerr.ManageForbidden()
	}
	return who, nil
}

// ShredSubject crypto-shreds a subject. The shred service writes the
// "subject.shredded" record itself, naming the caller and the reason.
func (s *AuditServer) ShredSubject(ctx context.Context, req *auditv1.ShredSubjectRequest) (*auditv1.ShredSubjectResponse, error) {
	who, err := retentionCaller(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	switch {
	case req.GetSubjectKey() == "":
		return nil, auditerr.Error(ctx, auditerr.InvalidArgument("subject_key"))
	case req.GetReason() == "":
		return nil, auditerr.Error(ctx, auditerr.InvalidArgument("reason"))
	}
	res, err := s.shredder.ShredSubject(ctx, req.GetSubjectKey(), req.GetReason(), who.userID)
	if errors.Is(err, shred.ErrPartialShred) {
		s.logger.Ctx(ctx).Error(err, "crypto-shred incomplete: the key is erased, retry the shred")
		return nil, auditerr.Error(ctx, auditerr.ShredIncomplete(err))
	}
	if err != nil {
		s.logger.Ctx(ctx).Error(err, "crypto-shred failed")
		return nil, auditerr.Error(ctx, err)
	}
	s.logger.Ctx(ctx).Info("subject shredded", log.F("record_id", res.MetaRecordID), log.F("rows_tombstoned", res.RowsTombstoned))
	return &auditv1.ShredSubjectResponse{RecordsTombstoned: toInt32(res.RowsTombstoned), RecordId: res.MetaRecordID}, nil
}

// CreateLegalHold places a hold, held by the caller, and records it as
// "legal_hold.created".
func (s *AuditServer) CreateLegalHold(ctx context.Context, req *auditv1.CreateLegalHoldRequest) (*auditv1.CreateLegalHoldResponse, error) {
	who, err := retentionCaller(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if req.GetReason() == "" {
		return nil, auditerr.Error(ctx, auditerr.InvalidArgument("reason"))
	}
	h, err := s.holds.CreateLegalHold(ctx, store.LegalHoldInput{
		SubjectFilter: req.GetSubjectFilter(), GroupFilter: req.GetGroupFilter(), Reason: req.GetReason(), HeldBy: who.userID,
	})
	if err != nil {
		return nil, s.storeError(ctx, "create_legal_hold", err)
	}
	s.recordRetention(ctx, who, "legal_hold.created", "legal_hold:"+h.UUID, map[string]string{
		"subject_filter": h.SubjectFilter, "group_filter": h.GroupFilter, "reason": h.Reason,
	})
	return &auditv1.CreateLegalHoldResponse{Hold: holdProto(h)}, nil
}

// ListLegalHolds lists the holds and records the read as "legal_hold.listed".
func (s *AuditServer) ListLegalHolds(ctx context.Context, req *auditv1.ListLegalHoldsRequest) (*auditv1.ListLegalHoldsResponse, error) {
	who, err := retentionCaller(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	hs, err := s.holds.ListLegalHolds(ctx, req.GetIncludeReleased())
	if err != nil {
		return nil, s.storeError(ctx, "list_legal_holds", err)
	}
	s.recordRetention(ctx, who, "legal_hold.listed", "legal_holds", map[string]string{
		"include_released": strconv.FormatBool(req.GetIncludeReleased()), "count": strconv.Itoa(len(hs)),
	})
	out := make([]*auditv1.LegalHold, len(hs))
	for i, h := range hs {
		out[i] = holdProto(h)
	}
	return &auditv1.ListLegalHoldsResponse{Holds: out}, nil
}

// ReleaseLegalHold releases a hold in force and records it as
// "legal_hold.released".
func (s *AuditServer) ReleaseLegalHold(ctx context.Context, req *auditv1.ReleaseLegalHoldRequest) (*auditv1.ReleaseLegalHoldResponse, error) {
	who, err := retentionCaller(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if req.GetHoldUuid() == "" {
		return nil, auditerr.Error(ctx, auditerr.InvalidArgument("hold_uuid"))
	}
	h, err := s.holds.ReleaseLegalHold(ctx, req.GetHoldUuid())
	if errors.Is(err, store.ErrHoldNotFound) {
		return nil, auditerr.Error(ctx, auditerr.HoldNotFound(err))
	}
	if err != nil {
		return nil, s.storeError(ctx, "release_legal_hold", err)
	}
	s.recordRetention(ctx, who, "legal_hold.released", "legal_hold:"+h.UUID, map[string]string{"reason": h.Reason})
	return &auditv1.ReleaseLegalHoldResponse{Hold: holdProto(h)}, nil
}

// recordRetention appends an audit-tier, legal-basis-exempt record of a
// legal-hold call. The call has already happened, so a failed record is
// logged rather than returned, as for exports.
func (s *AuditServer) recordRetention(ctx context.Context, who caller, action, subject string, attrs map[string]string) {
	if _, err := s.store.AppendRecord(ctx, store.RecordInput{
		Tier: "audit", Action: action, ActorUserID: who.userID, Subject: subject,
		OccurredAt: time.Now().UTC(), LegalBasisExempt: true, Attributes: attrs,
	}); err != nil {
		s.logger.Ctx(ctx).Error(err, "legal-hold meta-audit record failed", log.F("action", action), log.F("subject", subject))
	}
}

func holdProto(h store.LegalHold) *auditv1.LegalHold {
	out := &auditv1.LegalHold{
		HoldUuid: h.UUID, SubjectFilter: h.SubjectFilter, GroupFilter: h.GroupFilter, Reason: h.Reason,
		HeldBy: h.HeldBy, CreatedAt: timestamppb.New(h.CreatedAt),
	}
	if h.ReleasedAt != nil {
		out.ReleasedAt = timestamppb.New(*h.ReleasedAt)
	}
	return out
}
