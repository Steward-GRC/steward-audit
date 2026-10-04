// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

func hashOf(r VerifyRecord) string {
	return ComputeHash(r.PrevHash, r.Tier, r.Action, r.ActorUserID, r.Subject, r.GroupID, r.OccurredAt.UTC().Format(time.RFC3339Nano), nil)
}

func TestVerifyChainPassesForValidChain(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1 := VerifyRecord{ID: 1, Tier: "audit", Action: fixture.PolicyPublished, ActorUserID: fixture.Bob,
		Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0}
	r1.RecordHash = hashOf(r1)
	r2 := VerifyRecord{ID: 2, PrevHash: r1.RecordHash, Tier: "activity", Action: fixture.PolicyViewed, ActorUserID: fixture.Erin,
		Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0.Add(time.Minute)}
	r2.RecordHash = hashOf(r2)

	report := VerifyChain([]VerifyRecord{r1, r2}, nil)
	if !report.Valid {
		t.Fatalf("expected valid chain, got errors: %v", report.Errors)
	}
	if report.RecordsChecked != 2 {
		t.Fatalf("expected 2 records checked, got %d", report.RecordsChecked)
	}
}

func TestVerifyChainDetectsTampering(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1 := VerifyRecord{ID: 1, RecordHash: "correcthash", Tier: "audit", Action: fixture.PolicyPublished, ActorUserID: fixture.Bob,
		Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0}
	r2 := VerifyRecord{ID: 2, PrevHash: "wronghash", RecordHash: "anything", Tier: "activity", Action: fixture.PolicyViewed,
		ActorUserID: fixture.Erin, Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0.Add(time.Minute)}
	report := VerifyChain([]VerifyRecord{r1, r2}, nil)
	if report.Valid {
		t.Fatal("expected invalid chain for tampered record")
	}
	if len(report.Errors) == 0 {
		t.Fatal("expected at least one error")
	}
}

func TestVerifyChainValidatesCheckpointMerkleRoot(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r1 := VerifyRecord{ID: 1, Tier: "audit", Action: "a", ActorUserID: fixture.Bob, Subject: fixture.DeskBookingPolicy,
		GroupID: fixture.FacilitiesTeam, OccurredAt: t0}
	r1.RecordHash = hashOf(r1)
	r2 := VerifyRecord{ID: 2, PrevHash: r1.RecordHash, Tier: "audit", Action: "b", ActorUserID: fixture.Bob,
		Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0.Add(time.Second)}
	r2.RecordHash = hashOf(r2)

	correctRoot, _ := merkle.BuildTree([]string{r1.RecordHash, r2.RecordHash})
	report := VerifyChain([]VerifyRecord{r1, r2}, []VerifyCheckpoint{{CheckpointUUID: "cp-1", FromRecordID: 1, ToRecordID: 2, MerkleRoot: correctRoot}})
	if !report.Valid {
		t.Fatalf("expected valid report, errors: %v", report.Errors)
	}
	if report.CheckpointsChecked != 1 {
		t.Fatalf("expected 1 checkpoint checked, got %d", report.CheckpointsChecked)
	}

	report2 := VerifyChain([]VerifyRecord{r1, r2}, []VerifyCheckpoint{{CheckpointUUID: "cp-1", FromRecordID: 1, ToRecordID: 2, MerkleRoot: "deadbeef"}})
	if report2.Valid {
		t.Fatal("expected invalid report for tampered Merkle root")
	}
}

// gappedChain has committed ids 1, 2, 4, 5: id 3 was a rolled-back insert or
// a serialization retry, which still consumes a sequence value.
func gappedChain(t *testing.T) [4]VerifyRecord {
	t.Helper()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mk := func(id int64, prev string, offset time.Duration) VerifyRecord {
		r := VerifyRecord{ID: id, PrevHash: prev, Tier: "audit", Action: "a", ActorUserID: fixture.Bob,
			Subject: fixture.DeskBookingPolicy, GroupID: fixture.FacilitiesTeam, OccurredAt: t0.Add(offset)}
		r.RecordHash = ComputeHash(r.PrevHash, r.Tier, r.Action, r.ActorUserID, r.Subject, r.GroupID, CanonicalTime(r.OccurredAt), nil)
		return r
	}
	r1 := mk(1, "", 0)
	r2 := mk(2, r1.RecordHash, time.Second)
	r4 := mk(4, r2.RecordHash, 2*time.Second)
	r5 := mk(5, r4.RecordHash, 3*time.Second)
	return [4]VerifyRecord{r1, r2, r4, r5}
}

func TestVerifyChainFromToleratesIDSequenceGapsInCheckpointRange(t *testing.T) {
	cpFor := func(recs [4]VerifyRecord) VerifyCheckpoint {
		root, _ := merkle.BuildTree([]string{recs[0].RecordHash, recs[1].RecordHash, recs[2].RecordHash, recs[3].RecordHash})
		return VerifyCheckpoint{CheckpointUUID: "cp-gap", FromRecordID: 1, ToRecordID: 5, MerkleRoot: root}
	}

	t.Run("gap inside checkpoint range verifies clean", func(t *testing.T) {
		recs := gappedChain(t)
		report := VerifyChainFrom("", recs[:], []VerifyCheckpoint{cpFor(recs)})
		if !report.Valid {
			t.Fatalf("expected valid report despite id gap, got errors: %v", report.Errors)
		}
		if report.CheckpointsChecked != 1 {
			t.Fatalf("expected 1 checkpoint checked, got %d", report.CheckpointsChecked)
		}
	})

	t.Run("tampered record still detected despite gap", func(t *testing.T) {
		recs := gappedChain(t)
		cp := cpFor(recs)
		recs[2].Subject = fixture.ExpenseClaimsPolicy
		if VerifyChainFrom("", recs[:], []VerifyCheckpoint{cp}).Valid {
			t.Fatal("expected invalid report for a mutated committed record")
		}
	})

	t.Run("linkage break still detected despite gap", func(t *testing.T) {
		recs := gappedChain(t)
		cp := cpFor(recs)
		recs[2].PrevHash = "deadbeef"
		if VerifyChainFrom("", recs[:], []VerifyCheckpoint{cp}).Valid {
			t.Fatal("expected invalid report for a broken prev_hash link")
		}
	})
}

// A deleted committed record breaks the next record's link.
func TestVerifyChainDetectsDeletedRecord(t *testing.T) {
	recs := gappedChain(t)
	withoutSecond := []VerifyRecord{recs[0], recs[2], recs[3]}
	if VerifyChain(withoutSecond, nil).Valid {
		t.Fatal("expected a removed record to break the chain")
	}
}

func TestVerifyChainFromSeedsTheBoundary(t *testing.T) {
	recs := gappedChain(t)
	if !VerifyChainFrom(recs[1].RecordHash, recs[2:], nil).Valid {
		t.Fatal("a sub-range seeded with the preceding hash must verify")
	}
	if VerifyChainFrom("", recs[2:], nil).Valid {
		t.Fatal("a sub-range seeded with the genesis must fail at its first link")
	}
}
