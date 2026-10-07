// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package server is the audit service's gRPC transport: the AuditService
// handlers and the server they run in.
package server

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strconv"
	"time"

	log "github.com/Bugs5382/go-log"
	"google.golang.org/protobuf/types/known/timestamppb"

	stewardauthz "github.com/Steward-GRC/steward-authz"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/auditerr"
	"github.com/Steward-GRC/steward-audit/internal/chain"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

// QueryStore is the persistence the handlers use.
type QueryStore interface {
	QueryRecords(ctx context.Context, q store.QueryFilter) ([]store.Record, error)
	RecordsInRange(ctx context.Context, fromID, toID int64) ([]store.Record, error)
	PrecedingHash(ctx context.Context, fromID int64) (string, error)
	CheckpointsInRange(ctx context.Context, fromID, toID int64) ([]store.Checkpoint, error)
	AppendRecord(ctx context.Context, in store.RecordInput) (*store.Record, error)
	ListRecentRecords(ctx context.Context, f store.RecentFilter) ([]store.Record, error)
}

// AuditServer implements auditv1.AuditServiceServer. Identity comes from the
// request's RequesterIdentity, which the gateway fills from the session it
// authenticated; this service does not re-authenticate the user.
type AuditServer struct {
	auditv1.UnimplementedAuditServiceServer
	store  QueryStore
	logger log.Logger
}

// NewAuditServer returns an AuditServer on s.
func NewAuditServer(s QueryStore) *AuditServer {
	return &AuditServer{store: s, logger: log.Nop()}
}

// WithLogger sets the server's logger.
func (s *AuditServer) WithLogger(l log.Logger) *AuditServer {
	s.logger = l
	return s
}

// caller is the requester as the audit API sees it. A role that holds the
// catalog's audit.read reads every group; otherwise the caller reads only the
// groups it manages.
type caller struct {
	userID   string
	readsAll bool
	managed  []string
}

func callerFrom(r *auditv1.RequesterIdentity) (caller, error) {
	if r.GetUserId() == "" {
		return caller{}, auditerr.Unauthenticated()
	}
	subject := stewardauthz.Subject{UserID: r.GetUserId()}
	for _, name := range r.GetRoles() {
		if role, err := stewardauthz.ParseRole(name); err == nil {
			subject.Roles = append(subject.Roles, role)
		}
	}
	return caller{
		userID:   r.GetUserId(),
		readsAll: stewardauthz.HasCapability(subject, stewardauthz.AuditRead),
		managed:  r.GetManagedGroups(),
	}, nil
}

func (r caller) managesAGroup() bool { return len(r.managed) > 0 }

func (r caller) manages(groupID string) bool {
	return groupID != "" && slices.Contains(r.managed, groupID)
}

// QueryAuditLog returns a page of records. A caller without audit.read must
// name a group it manages. Queries are not audited: reading the log would
// otherwise write to it.
func (s *AuditServer) QueryAuditLog(ctx context.Context, req *auditv1.QueryAuditLogRequest) (*auditv1.QueryAuditLogResponse, error) {
	who, err := callerFrom(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if !who.readsAll && !who.manages(req.GetGroupId()) {
		return nil, auditerr.Error(ctx, auditerr.GroupScopeDenied())
	}
	var cursor int64
	if req.GetPageToken() != "" {
		if cursor, err = strconv.ParseInt(req.GetPageToken(), 10, 64); err != nil {
			return nil, auditerr.Error(ctx, auditerr.InvalidPageToken())
		}
	}
	limit := pageSize(req.GetPageSize())
	recs, err := s.store.QueryRecords(ctx, store.QueryFilter{
		Tier: req.GetTier(), GroupID: req.GetGroupId(), ActorUserID: req.GetActorUserId(),
		Subject: req.GetSubject(), AfterID: cursor, Limit: int(limit),
	})
	if err != nil {
		return nil, s.storeError(ctx, "query", err)
	}
	resp := &auditv1.QueryAuditLogResponse{Records: toProtos(recs)}
	if len(recs) == int(limit) {
		resp.NextPageToken = strconv.FormatInt(recs[len(recs)-1].ID, 10)
	}
	return resp, nil
}

// ExportAuditSegment returns a record range and its checkpoints for offline
// verification. Only audit.read may export: ids are global and sequential, so
// a range export would let a group manager read other groups. Each export is itself recorded as "audit_log.exported".
func (s *AuditServer) ExportAuditSegment(ctx context.Context, req *auditv1.ExportAuditSegmentRequest) (*auditv1.ExportAuditSegmentResponse, error) {
	who, err := callerFrom(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if !who.readsAll {
		return nil, auditerr.Error(ctx, auditerr.ExportForbidden())
	}
	from, to := req.GetFromRecordId(), req.GetToRecordId()
	recs, err := s.store.RecordsInRange(ctx, from, to)
	if err != nil {
		return nil, s.storeError(ctx, "export_records", err)
	}
	cps, err := s.store.CheckpointsInRange(ctx, from, to)
	if err != nil {
		return nil, s.storeError(ctx, "export_checkpoints", err)
	}

	// The export has happened by now; a failed meta record must not hide it
	// from the caller, so it is logged rather than returned.
	if _, err := s.store.AppendRecord(ctx, store.RecordInput{
		Tier: "audit", Action: "audit_log.exported", ActorUserID: who.userID,
		Subject: fmt.Sprintf("range:%d-%d", from, to), OccurredAt: time.Now().UTC(),
	}); err != nil {
		s.logger.Ctx(ctx).Error(err, "export meta-audit record failed", log.F("from_record_id", from), log.F("to_record_id", to))
	}

	out := make([]*auditv1.Checkpoint, len(cps))
	for i, cp := range cps {
		out[i] = &auditv1.Checkpoint{
			CheckpointUuid: cp.CheckpointUUID, MerkleRoot: cp.MerkleRoot, AnchorType: cp.AnchorType,
			AnchorUrl: cp.AnchorURL, TsaToken: cp.TSAToken, AnchoredAt: timestamppb.New(cp.AnchoredAt),
			FromRecordId: cp.FromRecordID, ToRecordId: cp.ToRecordID,
		}
	}
	return &auditv1.ExportAuditSegmentResponse{Records: toProtos(recs), Checkpoints: out}, nil
}

// VerifyAuditChain verifies a record range and its checkpoints on the server.
// audit.read and group managers may verify: the answer reveals only pass or
// fail and counts, never a record.
func (s *AuditServer) VerifyAuditChain(ctx context.Context, req *auditv1.VerifyAuditChainRequest) (*auditv1.VerifyAuditChainResponse, error) {
	who, err := callerFrom(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if !who.readsAll && !who.managesAGroup() {
		return nil, auditerr.Error(ctx, auditerr.VerifyForbidden())
	}
	from, to := req.GetFromRecordId(), req.GetToRecordId()
	recs, err := s.store.RecordsInRange(ctx, from, to)
	if err != nil {
		return nil, s.storeError(ctx, "verify_records", err)
	}
	seed, err := s.store.PrecedingHash(ctx, from)
	if err != nil {
		return nil, s.storeError(ctx, "verify_preceding_hash", err)
	}
	cps, err := s.store.CheckpointsInRange(ctx, from, to)
	if err != nil {
		return nil, s.storeError(ctx, "verify_checkpoints", err)
	}
	vrecs := make([]chain.VerifyRecord, len(recs))
	for i, r := range recs {
		vrecs[i] = r.VerifyRecord()
	}
	vcps := make([]chain.VerifyCheckpoint, len(cps))
	for i, cp := range cps {
		vcps[i] = chain.VerifyCheckpoint{CheckpointUUID: cp.CheckpointUUID, FromRecordID: cp.FromRecordID,
			ToRecordID: cp.ToRecordID, MerkleRoot: cp.MerkleRoot, TSAToken: cp.TSAToken}
	}
	report := chain.VerifyChainFrom(seed, vrecs, vcps)
	if !report.Valid {
		s.logger.Ctx(ctx).Warn("audit chain verification failed", log.F("from_record_id", from),
			log.F("to_record_id", to), log.F("errors", len(report.Errors)))
	}
	return &auditv1.VerifyAuditChainResponse{
		Valid: report.Valid, RecordsChecked: toInt32(report.RecordsChecked),
		CheckpointsChecked: toInt32(report.CheckpointsChecked), Errors: report.Errors,
	}, nil
}

// ListRecentEvents returns records since a time, for a polling tail. A group
// manager without audit.read sees the records of the groups it manages and
// records with no group. Tailing is
// not audited: one record per poll would drown the log.
func (s *AuditServer) ListRecentEvents(ctx context.Context, req *auditv1.ListRecentEventsRequest) (*auditv1.ListRecentEventsResponse, error) {
	who, err := callerFrom(req.GetRequester())
	if err != nil {
		return nil, auditerr.Error(ctx, err)
	}
	if !who.readsAll && !who.managesAGroup() {
		return nil, auditerr.Error(ctx, auditerr.TailForbidden())
	}
	since := time.Now().Add(-time.Hour)
	if ts := req.GetSinceTimestamp(); ts != nil && ts.IsValid() {
		since = ts.AsTime()
	}
	recs, err := s.store.ListRecentRecords(ctx, store.RecentFilter{
		Since: since, Actor: req.GetActorFilter(), EventType: req.GetEventTypeFilter(), Limit: int(pageSize(req.GetLimit())),
	})
	if err != nil {
		return nil, s.storeError(ctx, "list_recent", err)
	}
	if !who.readsAll {
		recs = slices.DeleteFunc(recs, func(r store.Record) bool { return r.GroupID != "" && !who.manages(r.GroupID) })
	}
	return &auditv1.ListRecentEventsResponse{Records: toProtos(recs)}, nil
}

func (s *AuditServer) storeError(ctx context.Context, op string, cause error) error {
	s.logger.Ctx(ctx).Error(cause, "audit store read failed", log.F("op", op))
	return auditerr.Error(ctx, auditerr.StoreUnavailable(op, cause))
}

// toProtos projects records onto the wire. Attributes and personal data are
// left off: they are hashed into the chain but never read back out here.
func toProtos(recs []store.Record) []*auditv1.AuditRecord {
	out := make([]*auditv1.AuditRecord, len(recs))
	for i, r := range recs {
		out[i] = &auditv1.AuditRecord{
			Id: r.ID, RecordUuid: r.RecordUUID, Tier: r.Tier, Action: r.Action, ActorUserId: r.ActorUserID,
			Subject: r.Subject, GroupId: r.GroupID, OccurredAt: timestamppb.New(r.OccurredAt),
			PrevHash: r.PrevHash, RecordHash: r.RecordHash, LegalBasisExempt: r.LegalBasisExempt,
		}
	}
	return out
}

// pageSize keeps a requested page size in 1 to 200, defaulting to 50.
func pageSize(requested int32) int32 {
	if requested <= 0 || requested > 200 {
		return 50
	}
	return requested
}

func toInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(n) // #nosec G115 -- bounded above, and counts are never negative
}
