// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"testing"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

// The values were produced by the service this one replaces. Chains and
// checkpoints migrated from it must keep verifying, so the hash and tree
// layouts may never drift from them.
func TestHashAndRootMatchTheMigratedLayout(t *testing.T) {
	at := time.Date(2026, 1, 1, 12, 30, 0, 123456789, time.UTC)
	h1 := ComputeHash("", "audit", fixture.PolicyPublished, fixture.Bob, fixture.DeskBookingPolicy, fixture.FacilitiesTeam,
		CanonicalTime(at), map[string]string{"b": "2", "a": "1 \"q\""})
	h2 := ComputeHash(h1, "activity", fixture.PolicyViewed, fixture.Erin, "", "", CanonicalTime(at), nil)
	root, _ := merkle.BuildTree([]string{h1, h2, "3f2a9c41"})

	if want := "2f07ee2c93d20d4084387c791954a20af4c5b841cc7fe057600bb63f90dc28de"; h1 != want {
		t.Fatalf("genesis hash %s, want %s", h1, want)
	}
	if want := "0ff952f4a94e21382265947e4c5674d6bc15f8e656d6157ccd209b0aa99425ce"; h2 != want {
		t.Fatalf("second hash %s, want %s", h2, want)
	}
	if want := "6494397cdee668d830de0e76500c9bdb537e616d524cb0f7829c86962f3a2b2f"; root != want {
		t.Fatalf("root %s, want %s", root, want)
	}
}
