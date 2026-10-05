// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/kms"
)

const testMaster = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

// Erase a key, start a new store and key provider on the same database, and
// the key stays erased.
func TestKeyErasureSurvivesARestart(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	before, err := kms.NewEnvKMS(testMaster, NewKeyRegistry(db))
	if err != nil {
		t.Fatalf("NewEnvKMS: %v", err)
	}
	if _, err := before.GetOrCreate(ctx, fixture.UserErin); err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if _, err := before.GetOrCreate(ctx, fixture.UserBob); err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if err := before.Delete(ctx, fixture.UserErin); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	after, _ := kms.NewEnvKMS(testMaster, NewKeyRegistry(db))
	if _, err := after.GetOrCreate(ctx, fixture.UserErin); !errors.Is(err, kms.ErrKeyErased) {
		t.Fatalf("expected ErrKeyErased after a restart, got %v", err)
	}
	if _, err := after.GetOrCreate(ctx, fixture.UserBob); err != nil {
		t.Fatalf("another subject's key must survive: %v", err)
	}

	var erased int
	if err := db.Querier().QueryRow(ctx,
		`SELECT COUNT(*) FROM subject_encryption_keys WHERE erased_at IS NOT NULL`).Scan(&erased); err != nil {
		t.Fatal(err)
	}
	if erased != 1 {
		t.Fatalf("want 1 erased key row, got %d", erased)
	}
}

// Erasing a key that was never handed out still records it, so it can never
// be handed out later.
func TestEraseBeforeFirstUse(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)
	k, _ := kms.NewEnvKMS(testMaster, NewKeyRegistry(db))
	if err := k.Delete(ctx, fixture.UserBob); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := k.Delete(ctx, fixture.UserBob); err != nil {
		t.Fatalf("Delete twice: %v", err)
	}
	restarted, _ := kms.NewEnvKMS(testMaster, NewKeyRegistry(db))
	if _, err := restarted.GetOrCreate(ctx, fixture.UserBob); !errors.Is(err, kms.ErrKeyErased) {
		t.Fatalf("expected ErrKeyErased, got %v", err)
	}
}
