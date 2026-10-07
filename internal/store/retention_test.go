// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/chain"
	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

func TestSetAndGetRetentionPolicy(t *testing.T) {
	ctx := context.Background()
	rs := NewRetentionStore(newTestDB(t))

	if err := rs.SetRetentionDays(ctx, "activity", 365); err != nil {
		t.Fatalf("SetRetentionDays: %v", err)
	}
	days, err := rs.GetRetentionDays(ctx, "activity")
	if err != nil {
		t.Fatalf("GetRetentionDays: %v", err)
	}
	if *days != 365 {
		t.Fatalf("expected 365, got %d", *days)
	}
}

func TestActivityTierRetentionDefaultsToTwoYears(t *testing.T) {
	days, err := NewRetentionStore(newTestDB(t)).GetRetentionDays(context.Background(), "activity")
	if err != nil || days == nil || *days != 730 {
		t.Fatalf("activity default = %v, %v; want 730", days, err)
	}
}

func TestAuditTierRetentionIsIndefinite(t *testing.T) {
	days, err := NewRetentionStore(newTestDB(t)).GetRetentionDays(context.Background(), "audit")
	if err != nil {
		t.Fatalf("GetRetentionDays audit: %v", err)
	}
	if days != nil {
		t.Fatalf("audit tier must have nil (indefinite) retention by default, got %d", *days)
	}
}

func expiring(tier, subject, group string, until time.Time, exempt bool) RecordInput {
	return RecordInput{Tier: tier, Action: fixture.PolicyViewed, ActorUserID: fixture.Erin, Subject: subject,
		GroupID: group, OccurredAt: until.Add(-time.Hour), RetainedUntil: &until, LegalBasisExempt: exempt}
}

func TestPurgeExpiredTombstonesEligibleActivityRecords(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	ret := NewRetentionStore(db)

	past := time.Now().UTC().Add(-24 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	expired := expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, false)
	expired.Attributes = map[string]string{"ip": "192.0.2.10"}
	expired.PIISubjectKey, expired.PIICiphertext = fixture.ErinKeyAlias, []byte("sealed")
	var ids []int64
	for _, in := range []RecordInput{
		expired,
		expiring("activity", fixture.TravelProcedure, fixture.FacilitiesTeam, future, false),
		expiring("audit", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, false),
		expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, true),
	} {
		r, err := rs.AppendRecord(ctx, in)
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		ids = append(ids, r.ID)
	}
	before, _ := rs.RecordsInRange(ctx, ids[0], ids[0])

	res, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if res.Purged != 1 || res.Skipped {
		t.Fatalf("expected 1 record purged, got %+v", res)
	}
	all, err := rs.RecordsInRange(ctx, ids[0], ids[len(ids)-1])
	if err != nil || len(all) != len(ids) {
		t.Fatalf("a purge keeps every row: %d rows, %v", len(all), err)
	}
	got := all[0]
	if !got.Purged || got.ID != before[0].ID || got.RecordUUID != before[0].RecordUUID ||
		got.PrevHash != before[0].PrevHash || got.RecordHash != before[0].RecordHash || got.Tier != "activity" {
		t.Fatalf("a tombstone keeps its id, link and hash: %+v", got)
	}
	if got.Action != "" || got.ActorUserID != "" || got.Subject != "" || got.GroupID != "" ||
		len(got.Attributes) != 0 || got.PIISubjectKey != "" || got.PIICiphertext != nil {
		t.Fatalf("a tombstone's content is cleared: %+v", got)
	}
	for _, r := range all[1:] {
		if r.Purged {
			t.Fatalf("record %d must be kept: %+v", r.ID, r)
		}
	}
	again, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil || again.Purged != 0 {
		t.Fatalf("a tombstone isn't purged twice: %+v, %v", again, err)
	}
	if report := chain.VerifyChain(toVerify(all), nil); !report.Valid || report.RecordsPurged != 1 {
		t.Fatalf("the chain verifies over the tombstone: %+v", report)
	}
}

func TestPurgeExpiredRespectsLegalHold(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	ret := NewRetentionStore(db)

	past := time.Now().UTC().Add(-24 * time.Hour)
	for _, in := range []RecordInput{
		expiring("activity", fixture.ExpenseClaimsPolicy, fixture.FacilitiesTeam, past, false),
		expiring("activity", fixture.DeskBookingPolicy, fixture.FinanceTeam, past, false),
		expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, false),
	} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if _, err := ret.CreateLegalHold(ctx, LegalHoldInput{SubjectFilter: fixture.ExpenseClaimsPolicy, Reason: "test hold", HeldBy: fixture.Grace}); err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}
	finance, err := ret.CreateLegalHold(ctx, LegalHoldInput{GroupFilter: fixture.FinanceTeam, Reason: "test hold", HeldBy: fixture.Grace})
	if err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}
	res, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if res.Purged != 1 {
		t.Fatalf("expected only the unheld record purged, got %d", res.Purged)
	}
	if _, err := ret.ReleaseLegalHold(ctx, finance.UUID); err != nil {
		t.Fatalf("ReleaseLegalHold: %v", err)
	}
	if res, _ := ret.PurgeExpired(ctx, time.Now().UTC()); res.Purged != 1 {
		t.Fatalf("a released hold no longer protects its records, got %d", res.Purged)
	}
}

// Purged records that bound checkpoints keep the foreign keys intact, and a
// verify across and inside the purged range still passes.
func TestPurgeAcrossACheckpointBoundaryStillVerifies(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	cps := NewCheckpointStore(db)
	ret := NewRetentionStore(db)

	past := time.Now().UTC().Add(-24 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	var recs []*Record
	for _, until := range []time.Time{future, past, past, future} {
		r, err := rs.AppendRecord(ctx, expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, until, false))
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		recs = append(recs, r)
	}
	for _, pair := range [][2]int{{0, 1}, {2, 3}} {
		root, _ := merkle.BuildTree([]string{recs[pair[0]].RecordHash, recs[pair[1]].RecordHash})
		if _, err := cps.SaveCheckpoint(ctx, CheckpointInput{FromRecordID: recs[pair[0]].ID, ToRecordID: recs[pair[1]].ID,
			MerkleRoot: root, AnchorType: "rfc3161", AnchoredAt: time.Now().UTC(), AnchorStatus: "anchored"}); err != nil {
			t.Fatalf("SaveCheckpoint: %v", err)
		}
	}

	res, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil || res.Purged != 2 {
		t.Fatalf("both checkpoint-bounding records are purged: %+v, %v", res, err)
	}

	verify := func(from, to int64) chain.VerifyReport {
		t.Helper()
		rows, err := rs.RecordsInRange(ctx, from, to)
		if err != nil {
			t.Fatalf("RecordsInRange: %v", err)
		}
		seed, err := rs.PrecedingHash(ctx, from)
		if err != nil {
			t.Fatalf("PrecedingHash: %v", err)
		}
		inRange, err := cps.CheckpointsInRange(ctx, from, to)
		if err != nil {
			t.Fatalf("CheckpointsInRange: %v", err)
		}
		vcps := make([]chain.VerifyCheckpoint, len(inRange))
		for i, cp := range inRange {
			vcps[i] = chain.VerifyCheckpoint{CheckpointUUID: cp.CheckpointUUID, FromRecordID: cp.FromRecordID,
				ToRecordID: cp.ToRecordID, MerkleRoot: cp.MerkleRoot}
		}
		return chain.VerifyChainFrom(seed, toVerify(rows), vcps)
	}
	if r := verify(recs[0].ID, recs[3].ID); !r.Valid || r.RecordsPurged != 2 || r.CheckpointsChecked != 2 {
		t.Fatalf("the whole range verifies across the boundary: %+v", r)
	}
	if r := verify(recs[1].ID, recs[2].ID); !r.Valid || r.RecordsChecked != 2 {
		t.Fatalf("a verify over the purged range alone passes: %+v", r)
	}
	if r := verify(recs[2].ID, recs[3].ID); !r.Valid || r.CheckpointsChecked != 1 {
		t.Fatalf("a checkpoint that starts on a purged record verifies: %+v", r)
	}
}

func TestPurgeExpiredSkipsWhileAnotherReplicaRunsIt(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	ret := NewRetentionStore(db)
	if _, err := NewRecordStore(db).AppendRecord(ctx, expiring("activity", fixture.DeskBookingPolicy, "", time.Now().UTC().Add(-time.Hour), false)); err != nil {
		t.Fatalf("insert: %v", err)
	}
	conn, err := db.Pool().Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, PurgeLockKey); err != nil {
		t.Fatalf("lock: %v", err)
	}
	res, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil || !res.Skipped || res.Purged != 0 {
		t.Fatalf("a held lock skips the run: %+v, %v", res, err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, PurgeLockKey); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if res, err := ret.PurgeExpired(ctx, time.Now().UTC()); err != nil || res.Skipped || res.Purged != 1 {
		t.Fatalf("the next run purges: %+v, %v", res, err)
	}
}

func TestLegalHoldPreventsExpiry(t *testing.T) {
	ctx := context.Background()
	rs := NewRetentionStore(newTestDB(t))

	hold, err := rs.CreateLegalHold(ctx, LegalHoldInput{SubjectFilter: fixture.TravelProcedure, Reason: "litigation hold", HeldBy: fixture.Grace})
	if err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}
	if hold.UUID == "" || hold.SubjectFilter != fixture.TravelProcedure || hold.HeldBy != fixture.Grace || hold.CreatedAt.IsZero() {
		t.Fatalf("hold: %+v", hold)
	}
	held, err := rs.IsUnderLegalHold(ctx, fixture.TravelProcedure, "")
	if err != nil || !held {
		t.Fatalf("expected record to be under legal hold: %v", err)
	}
	if held, _ := rs.IsUnderLegalHold(ctx, fixture.DeskBookingPolicy, ""); held {
		t.Fatal("a hold on one subject must not cover another")
	}
	released, err := rs.ReleaseLegalHold(ctx, hold.UUID)
	if err != nil || released.ReleasedAt == nil {
		t.Fatalf("ReleaseLegalHold: %+v, %v", released, err)
	}
	if held, _ := rs.IsUnderLegalHold(ctx, fixture.TravelProcedure, ""); held {
		t.Fatal("expected hold to be released")
	}
	if _, err := rs.ReleaseLegalHold(ctx, hold.UUID); !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("a released hold can't be released again: %v", err)
	}
	if _, err := rs.ReleaseLegalHold(ctx, "not-a-uuid"); !errors.Is(err, ErrHoldNotFound) {
		t.Fatalf("an unknown hold is not found: %v", err)
	}
}

func TestListLegalHolds(t *testing.T) {
	ctx := context.Background()
	rs := NewRetentionStore(newTestDB(t))
	a, _ := rs.CreateLegalHold(ctx, LegalHoldInput{SubjectFilter: fixture.TravelProcedure, Reason: "one", HeldBy: fixture.Grace})
	b, _ := rs.CreateLegalHold(ctx, LegalHoldInput{GroupFilter: fixture.FinanceTeam, Reason: "two", HeldBy: fixture.Grace})
	if _, err := rs.ReleaseLegalHold(ctx, a.UUID); err != nil {
		t.Fatalf("release: %v", err)
	}
	active, err := rs.ListLegalHolds(ctx, false)
	if err != nil || len(active) != 1 || active[0].UUID != b.UUID || active[0].GroupFilter != fixture.FinanceTeam {
		t.Fatalf("active holds: %+v, %v", active, err)
	}
	all, err := rs.ListLegalHolds(ctx, true)
	if err != nil || len(all) != 2 || all[0].UUID != a.UUID || all[0].ReleasedAt == nil {
		t.Fatalf("every hold, oldest first: %+v, %v", all, err)
	}
}

func TestQueryAndTailSkipTombstones(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	expired := expiring("activity", fixture.DeskBookingPolicy, "", time.Now().UTC().Add(-time.Minute), false)
	expired.OccurredAt = time.Now().UTC()
	kept := expiring("activity", fixture.TravelProcedure, "", time.Now().UTC().Add(time.Hour), false)
	kept.OccurredAt = time.Now().UTC()
	for _, in := range []RecordInput{expired, kept} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	if res, err := NewRetentionStore(db).PurgeExpired(ctx, time.Now().UTC()); err != nil || res.Purged != 1 {
		t.Fatalf("purge: %+v, %v", res, err)
	}
	got, err := rs.QueryRecords(ctx, QueryFilter{})
	if err != nil || len(got) != 1 || got[0].Subject != fixture.TravelProcedure {
		t.Fatalf("a query skips tombstones: %+v, %v", got, err)
	}
	got, err = rs.ListRecentRecords(ctx, RecentFilter{Since: time.Now().Add(-time.Hour)})
	if err != nil || len(got) != 1 || got[0].Subject != fixture.TravelProcedure {
		t.Fatalf("a tail skips tombstones: %+v, %v", got, err)
	}
	all, _ := rs.RecordsInRange(ctx, 1, 2)
	if len(all) != 2 || !all[0].Purged {
		t.Fatalf("a range read keeps tombstones for verify and export: %+v", all)
	}
}
