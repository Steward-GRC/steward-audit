// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
)

func TestSaveAndListCheckpoints(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	cs := NewCheckpointStore(db)

	r, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy))
	if err != nil {
		t.Fatalf("seed record: %v", err)
	}
	saved, err := cs.SaveCheckpoint(ctx, CheckpointInput{
		FromRecordID: r.ID, ToRecordID: r.ID, MerkleRoot: "abcdef1234", AnchorType: "rfc3161",
		AnchorURL: fixture.TSAURL, TSAToken: []byte("fake-token"), AnchoredAt: time.Now().UTC(), AnchorStatus: "anchored",
	})
	if err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	if saved.ID == 0 || saved.CheckpointUUID == "" || saved.CreatedAt.IsZero() {
		t.Fatalf("checkpoint not populated: %+v", saved)
	}

	list, err := cs.ListCheckpoints(ctx, 10)
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 checkpoint, got %d", len(list))
	}
	c := list[0]
	if c.MerkleRoot != "abcdef1234" || c.AnchorType != "rfc3161" || c.AnchorStatus != "anchored" || string(c.TSAToken) != "fake-token" || c.AnchorURL != fixture.TSAURL {
		t.Fatalf("checkpoint mismatch: %+v", c)
	}
}

func TestCheckpointsInRangeAndLastCheckpointed(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	rs := NewRecordStore(db)
	cs := NewCheckpointStore(db)

	last, err := cs.LastCheckpointedID(ctx)
	if err != nil || last != 0 {
		t.Fatalf("LastCheckpointedID on an empty store = %d, %v", last, err)
	}
	for range 6 {
		if _, err := rs.AppendRecord(ctx, published(fixture.Bob, fixture.DeskBookingPolicy)); err != nil {
			t.Fatalf("AppendRecord: %v", err)
		}
	}
	for _, rng := range [][2]int64{{1, 3}, {4, 6}} {
		if _, err := cs.SaveCheckpoint(ctx, CheckpointInput{FromRecordID: rng[0], ToRecordID: rng[1], MerkleRoot: "r",
			AnchorType: "rfc3161", AnchoredAt: time.Now().UTC(), AnchorStatus: "anchored"}); err != nil {
			t.Fatalf("SaveCheckpoint: %v", err)
		}
	}
	got, err := cs.CheckpointsInRange(ctx, 1, 4)
	if err != nil || len(got) != 1 || got[0].ToRecordID != 3 {
		t.Fatalf("CheckpointsInRange(1, 4) = %+v, %v; want only 1-3", got, err)
	}
	if got, _ := cs.CheckpointsInRange(ctx, 1, 6); len(got) != 2 {
		t.Fatalf("CheckpointsInRange(1, 6) = %d, want 2", len(got))
	}
	if last, _ := cs.LastCheckpointedID(ctx); last != 6 {
		t.Fatalf("LastCheckpointedID = %d, want 6", last)
	}
}
