// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// 32 zero bytes, base64. A test key only.
const testMaster = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

func TestEnvKMSGetOrCreateReturnsSameKey(t *testing.T) {
	k, err := NewEnvKMS(testMaster)
	if err != nil {
		t.Fatalf("NewEnvKMS: %v", err)
	}
	key1, err := k.GetOrCreate(context.Background(), "user:erin")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	key2, err := k.GetOrCreate(context.Background(), "user:erin")
	if err != nil {
		t.Fatalf("GetOrCreate 2nd: %v", err)
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("same alias must return same derived key")
	}
	if len(key1) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(key1))
	}
	other, _ := k.GetOrCreate(context.Background(), "user:bob")
	if bytes.Equal(key1, other) {
		t.Fatal("different aliases must derive different keys")
	}
}

func TestEnvKMSDeleteErasesTheKey(t *testing.T) {
	k, _ := NewEnvKMS(testMaster)
	if _, err := k.GetOrCreate(context.Background(), "user:bob"); err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if err := k.Delete(context.Background(), "user:bob"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := k.GetOrCreate(context.Background(), "user:bob"); !errors.Is(err, ErrKeyErased) {
		t.Fatalf("expected ErrKeyErased after deletion, got %v", err)
	}
}

func TestNewEnvKMSRejectsBadMasterKeys(t *testing.T) {
	for name, master := range map[string]string{
		"empty":      "",
		"not base64": "not base64!",
		"too short":  "AAAAAAAAAAAAAAAAAAAAAA==",
	} {
		if _, err := NewEnvKMS(master); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
