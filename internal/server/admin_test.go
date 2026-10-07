// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	stewardauthz "github.com/Steward-GRC/steward-authz"

	auditv1 "github.com/Steward-GRC/steward-audit/gen/go/steward/audit/v1"
	"github.com/Steward-GRC/steward-audit/internal/chain"
	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/shred"
	"github.com/Steward-GRC/steward-audit/internal/store"
)

type fakeHolds struct {
	holds []store.LegalHold
	err   error
}

func (f *fakeHolds) CreateLegalHold(_ context.Context, in store.LegalHoldInput) (store.LegalHold, error) {
	if f.err != nil {
		return store.LegalHold{}, f.err
	}
	h := store.LegalHold{UUID: "hold-1", SubjectFilter: in.SubjectFilter, GroupFilter: in.GroupFilter,
		Reason: in.Reason, HeldBy: in.HeldBy, CreatedAt: time.Now().UTC()}
	f.holds = append(f.holds, h)
	return h, nil
}

func (f *fakeHolds) ListLegalHolds(_ context.Context, includeReleased bool) ([]store.LegalHold, error) {
	var out []store.LegalHold
	for _, h := range f.holds {
		if includeReleased || h.ReleasedAt == nil {
			out = append(out, h)
		}
	}
	return out, f.err
}

func (f *fakeHolds) ReleaseLegalHold(_ context.Context, id string) (store.LegalHold, error) {
	for i, h := range f.holds {
		if h.UUID == id && h.ReleasedAt == nil {
			now := time.Now().UTC()
			f.holds[i].ReleasedAt = &now
			return f.holds[i], nil
		}
	}
	return store.LegalHold{}, store.ErrHoldNotFound
}

type fakeShredder struct {
	calls []string
	err   error
}

func (f *fakeShredder) ShredSubject(_ context.Context, subjectKey, reason, actor string) (shred.ShredResult, error) {
	f.calls = append(f.calls, subjectKey+"|"+reason+"|"+actor)
	if f.err != nil {
		return shred.ShredResult{}, f.err
	}
	return shred.ShredResult{SubjectKey: subjectKey, RowsTombstoned: 3, MetaRecordID: 42}, nil
}

func adminServer() (*AuditServer, *fakeQueryStore, *fakeHolds, *fakeShredder) {
	fs, holds, sh := &fakeQueryStore{}, &fakeHolds{}, &fakeShredder{}
	return NewAuditServer(fs).WithRetention(holds).WithShredder(sh), fs, holds, sh
}

var complianceAdmin = requester(fixture.Grace, string(stewardauthz.RoleComplianceAdmin), "")

func TestAdminRPCsNeedComplianceManage(t *testing.T) {
	for _, who := range []*auditv1.RequesterIdentity{
		plainReader, groupManager, requester(fixture.Erin, string(stewardauthz.RoleTemplateAdmin), ""),
		requester(fixture.Erin, "compliance_officer", ""),
	} {
		svc, fs, holds, sh := adminServer()
		ctx := context.Background()
		_, err := svc.ShredSubject(ctx, &auditv1.ShredSubjectRequest{SubjectKey: fixture.ErinKeyAlias, Reason: "erasure request", Requester: who})
		require.Equal(t, "AUDIT_MANAGE_FORBIDDEN", symbolOf(err), "shred")
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		_, err = svc.CreateLegalHold(ctx, &auditv1.CreateLegalHoldRequest{SubjectFilter: fixture.DeskBookingPolicy, Reason: "litigation", Requester: who})
		require.Equal(t, "AUDIT_MANAGE_FORBIDDEN", symbolOf(err), "create hold")
		_, err = svc.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{Requester: who})
		require.Equal(t, "AUDIT_MANAGE_FORBIDDEN", symbolOf(err), "list holds")
		_, err = svc.ReleaseLegalHold(ctx, &auditv1.ReleaseLegalHoldRequest{HoldUuid: "hold-1", Requester: who})
		require.Equal(t, "AUDIT_MANAGE_FORBIDDEN", symbolOf(err), "release hold")
		require.Empty(t, sh.calls)
		require.Empty(t, holds.holds)
		require.Empty(t, fs.appended, "a refusal changes nothing")
	}
}

func TestAdminRPCsNeedARequester(t *testing.T) {
	svc, _, _, _ := adminServer()
	ctx := context.Background()
	_, err := svc.ShredSubject(ctx, &auditv1.ShredSubjectRequest{SubjectKey: "k", Reason: "r"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = svc.CreateLegalHold(ctx, &auditv1.CreateLegalHoldRequest{Reason: "r"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = svc.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = svc.ReleaseLegalHold(ctx, &auditv1.ReleaseLegalHoldRequest{HoldUuid: "hold-1"})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestShredSubject(t *testing.T) {
	svc, _, _, sh := adminServer()
	resp, err := svc.ShredSubject(context.Background(), &auditv1.ShredSubjectRequest{
		SubjectKey: fixture.ErinKeyAlias, Reason: "erasure request", Requester: complianceAdmin})
	require.NoError(t, err)
	require.Equal(t, int32(3), resp.GetRecordsTombstoned())
	require.Equal(t, int64(42), resp.GetRecordId(), "the subject.shredded record the shred wrote")
	require.Equal(t, []string{fixture.ErinKeyAlias + "|erasure request|" + fixture.Grace}, sh.calls)
}

func TestShredSubjectRefusesAMissingKeyOrReason(t *testing.T) {
	svc, _, _, sh := adminServer()
	ctx := context.Background()
	_, err := svc.ShredSubject(ctx, &auditv1.ShredSubjectRequest{Reason: "r", Requester: complianceAdmin})
	require.Equal(t, "AUDIT_INVALID_ARGUMENT", symbolOf(err))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = svc.ShredSubject(ctx, &auditv1.ShredSubjectRequest{SubjectKey: "k", Requester: complianceAdmin})
	require.Equal(t, "AUDIT_INVALID_ARGUMENT", symbolOf(err))
	require.Empty(t, sh.calls)
}

func TestShredSubjectReportsAPartialShred(t *testing.T) {
	svc, _, _, sh := adminServer()
	sh.err = errors.Join(shred.ErrPartialShred, errors.New("db down"))
	_, err := svc.ShredSubject(context.Background(), &auditv1.ShredSubjectRequest{
		SubjectKey: fixture.ErinKeyAlias, Reason: "erasure request", Requester: complianceAdmin})
	require.Equal(t, "AUDIT_SHRED_INCOMPLETE", symbolOf(err), "the key is gone; the caller retries the rest")
	require.NotContains(t, status.Convert(err).Message(), "db down")
}

func TestLegalHoldLifecycleIsAudited(t *testing.T) {
	svc, fs, _, _ := adminServer()
	ctx := context.Background()
	created, err := svc.CreateLegalHold(ctx, &auditv1.CreateLegalHoldRequest{
		SubjectFilter: fixture.DeskBookingPolicy, GroupFilter: fixture.FacilitiesTeam, Reason: "litigation", Requester: complianceAdmin})
	require.NoError(t, err)
	h := created.GetHold()
	require.Equal(t, "hold-1", h.GetHoldUuid())
	require.Equal(t, fixture.Grace, h.GetHeldBy(), "the hold names the real user")
	require.Equal(t, fixture.DeskBookingPolicy, h.GetSubjectFilter())
	require.Nil(t, h.GetReleasedAt())

	listed, err := svc.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{Requester: complianceAdmin})
	require.NoError(t, err)
	require.Len(t, listed.GetHolds(), 1)

	released, err := svc.ReleaseLegalHold(ctx, &auditv1.ReleaseLegalHoldRequest{HoldUuid: "hold-1", Requester: complianceAdmin})
	require.NoError(t, err)
	require.NotNil(t, released.GetHold().GetReleasedAt())

	listed, err = svc.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{Requester: complianceAdmin})
	require.NoError(t, err)
	require.Empty(t, listed.GetHolds())
	listed, err = svc.ListLegalHolds(ctx, &auditv1.ListLegalHoldsRequest{IncludeReleased: true, Requester: complianceAdmin})
	require.NoError(t, err)
	require.Len(t, listed.GetHolds(), 1)

	require.Len(t, fs.appended, 5)
	want := []string{"legal_hold.created", "legal_hold.listed", "legal_hold.released", "legal_hold.listed", "legal_hold.listed"}
	for i, rec := range fs.appended {
		require.Equal(t, want[i], rec.Action)
		require.Equal(t, "audit", rec.Tier)
		require.True(t, rec.LegalBasisExempt, "the record of a hold is never purged")
		require.Equal(t, fixture.Grace, rec.ActorUserID)
		require.False(t, rec.OccurredAt.IsZero())
	}
	require.Equal(t, "legal_hold:hold-1", fs.appended[0].Subject)
	require.Equal(t, map[string]string{"subject_filter": fixture.DeskBookingPolicy, "group_filter": fixture.FacilitiesTeam,
		"reason": "litigation"}, fs.appended[0].Attributes)
	require.Equal(t, "legal_hold:hold-1", fs.appended[2].Subject)
}

func TestCreateLegalHoldNeedsAReason(t *testing.T) {
	svc, fs, holds, _ := adminServer()
	_, err := svc.CreateLegalHold(context.Background(), &auditv1.CreateLegalHoldRequest{Requester: complianceAdmin})
	require.Equal(t, "AUDIT_INVALID_ARGUMENT", symbolOf(err))
	require.Empty(t, holds.holds)
	require.Empty(t, fs.appended)
}

func TestReleaseLegalHoldUnknownIsNotFound(t *testing.T) {
	svc, fs, _, _ := adminServer()
	_, err := svc.ReleaseLegalHold(context.Background(), &auditv1.ReleaseLegalHoldRequest{HoldUuid: "nope", Requester: complianceAdmin})
	require.Equal(t, "AUDIT_HOLD_NOT_FOUND", symbolOf(err))
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Empty(t, fs.appended)
}

func TestVerifyCountsPurgedRecords(t *testing.T) {
	recs := buildActivityChain(3, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	recs[1].Purged = true
	recs[1].Action, recs[1].ActorUserID, recs[1].Subject, recs[1].GroupID = "", "", "", ""
	resp, err := NewAuditServer(&fakeQueryStore{records: recs}).VerifyAuditChain(context.Background(),
		&auditv1.VerifyAuditChainRequest{FromRecordId: 1, ToRecordId: 3, Requester: auditor})
	require.NoError(t, err)
	require.True(t, resp.GetValid(), resp.GetErrors())
	require.Equal(t, int32(1), resp.GetRecordsPurged())

	got, err := NewAuditServer(&fakeQueryStore{records: recs}).ExportAuditSegment(context.Background(),
		&auditv1.ExportAuditSegmentRequest{FromRecordId: 1, ToRecordId: 3, Requester: auditor})
	require.NoError(t, err)
	require.True(t, got.GetRecords()[1].GetPurged(), "an export marks the tombstone for the offline verifier")
	require.False(t, got.GetRecords()[0].GetPurged())
}

func buildActivityChain(n int64, base time.Time) []store.Record {
	recs := make([]store.Record, 0, n)
	prev := ""
	for id := int64(1); id <= n; id++ {
		at := base.Add(time.Duration(id) * time.Second)
		h := chain.ComputeHash(prev, "activity", fixture.PolicyViewed, fixture.Erin, fixture.DeskBookingPolicy,
			fixture.FacilitiesTeam, chain.CanonicalTime(at), nil)
		recs = append(recs, store.Record{ID: id, PrevHash: prev, RecordHash: h, RecordInput: store.RecordInput{
			Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: fixture.DeskBookingPolicy,
			GroupID: fixture.FacilitiesTeam, OccurredAt: at}})
		prev = h
	}
	return recs
}
