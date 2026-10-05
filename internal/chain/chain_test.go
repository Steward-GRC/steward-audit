// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
)

const t0s = "2026-01-01T00:00:00Z"

func TestComputeHashDeterministic(t *testing.T) {
	attrs := map[string]string{"k": "v"}
	h1 := ComputeHash("", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, attrs)
	h2 := ComputeHash("", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, attrs)
	if h1 != h2 {
		t.Fatalf("hash not deterministic: %q vs %q", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64 hex chars, got %d: %q", len(h1), h1)
	}
	if _, err := hex.DecodeString(h1); err != nil {
		t.Fatalf("not valid hex: %v", err)
	}
}

func TestComputeHashChainDiffers(t *testing.T) {
	h1 := ComputeHash("aaa", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, nil)
	h2 := ComputeHash("bbb", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, nil)
	if h1 == h2 {
		t.Fatal("different prev_hash should produce different hash")
	}
}

func TestComputeHashAnyFieldDiffers(t *testing.T) {
	base := ComputeHash("prev", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, nil)
	changed := ComputeHash("prev", "audit", fixture.PolicyPublished, fixture.Carol, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, nil)
	if base == changed {
		t.Fatal("changing actor_user_id should change hash")
	}
}

func TestComputeHashAttributesDiffer(t *testing.T) {
	h1 := ComputeHash("prev", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, map[string]string{"a": "1"})
	h2 := ComputeHash("prev", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam, t0s, map[string]string{"a": "2"})
	if h1 == h2 {
		t.Fatal("different attributes must produce different hash")
	}
}

// The field separator stops one field's tail from passing as the next field's head.
func TestComputeHashFieldBoundaries(t *testing.T) {
	h1 := ComputeHash("", "audit", "ab", "c", "", "", t0s, nil)
	h2 := ComputeHash("", "audit", "a", "bc", "", "", t0s, nil)
	if h1 == h2 {
		t.Fatal("moving bytes across a field boundary must change the hash")
	}
}

func TestComputeHashAttributeOrderIrrelevant(t *testing.T) {
	a := map[string]string{"b": "2", "a": "1", "c": "3"}
	b := map[string]string{"c": "3", "a": "1", "b": "2"}
	if ComputeHash("", "audit", "x", "", "", "", t0s, a) != ComputeHash("", "audit", "x", "", "", "", t0s, b) {
		t.Fatal("attribute map order must not change the hash")
	}
	if ComputeHash("", "audit", "x", "", "", "", t0s, nil) != ComputeHash("", "audit", "x", "", "", "", t0s, map[string]string{}) {
		t.Fatal("nil and empty attributes must hash the same")
	}
}

// Postgres keeps microseconds, so the chain must commit to the truncated time.
func TestCanonicalTimeTruncatesToMicroseconds(t *testing.T) {
	ns := time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.FixedZone("x", 3600))
	got := CanonicalTime(ns)
	want := time.Date(2025, 12, 31, 23, 0, 0, 123456000, time.UTC).Format(time.RFC3339Nano)
	if got != want {
		t.Fatalf("CanonicalTime = %q, want %q", got, want)
	}
}
