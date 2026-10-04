// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
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

func TestPurgeExpiredDeletesEligibleActivityRecords(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	ret := NewRetentionStore(db)

	past := time.Now().UTC().Add(-24 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	for _, in := range []RecordInput{
		expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, false),
		expiring("activity", fixture.TravelProcedure, fixture.FacilitiesTeam, future, false),
		expiring("audit", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, false),
		expiring("activity", fixture.DeskBookingPolicy, fixture.FacilitiesTeam, past, true),
	} {
		if _, err := rs.AppendRecord(ctx, in); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	deleted, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 row deleted, got %d", deleted)
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
	if _, err := ret.CreateLegalHold(ctx, LegalHoldInput{GroupFilter: fixture.FinanceTeam, Reason: "test hold", HeldBy: fixture.Grace}); err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}
	deleted, err := ret.PurgeExpired(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("PurgeExpired: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected only the unheld record deleted, got %d", deleted)
	}
}

func TestLegalHoldPreventsExpiry(t *testing.T) {
	ctx := context.Background()
	rs := NewRetentionStore(newTestDB(t))

	holdID, err := rs.CreateLegalHold(ctx, LegalHoldInput{SubjectFilter: fixture.TravelProcedure, Reason: "litigation hold", HeldBy: fixture.Grace})
	if err != nil {
		t.Fatalf("CreateLegalHold: %v", err)
	}
	if holdID == "" {
		t.Fatal("expected non-empty holdID")
	}
	held, err := rs.IsUnderLegalHold(ctx, fixture.TravelProcedure, "")
	if err != nil || !held {
		t.Fatalf("expected record to be under legal hold: %v", err)
	}
	if held, _ := rs.IsUnderLegalHold(ctx, fixture.DeskBookingPolicy, ""); held {
		t.Fatal("a hold on one subject must not cover another")
	}
	if err := rs.ReleaseLegalHold(ctx, holdID); err != nil {
		t.Fatalf("ReleaseLegalHold: %v", err)
	}
	if held, _ := rs.IsUnderLegalHold(ctx, fixture.TravelProcedure, ""); held {
		t.Fatal("expected hold to be released")
	}
}
