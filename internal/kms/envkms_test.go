// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

// 32 zero bytes, base64. A test key only.
const testMaster = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type memRegistry struct {
	mu     sync.Mutex
	known  map[string]bool
	erased map[string]bool
}

func newMemRegistry() *memRegistry {
	return &memRegistry{known: map[string]bool{}, erased: map[string]bool{}}
}

func (m *memRegistry) Register(_ context.Context, alias string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known[alias] = true
	return m.erased[alias], nil
}

func (m *memRegistry) MarkErased(_ context.Context, alias string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.known[alias] = true
	m.erased[alias] = true
	return nil
}

func TestEnvKMSGetOrCreateReturnsSameKey(t *testing.T) {
	reg := newMemRegistry()
	k, err := NewEnvKMS(testMaster, reg)
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
	if !reg.known["user:erin"] {
		t.Fatal("a key handed out must be registered")
	}
}

func TestEnvKMSDeleteErasesTheKey(t *testing.T) {
	k, _ := NewEnvKMS(testMaster, newMemRegistry())
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

// The erasure lives in the registry, so a new provider on the same registry
// (a restart) still refuses the key.
func TestEnvKMSErasureSurvivesARestart(t *testing.T) {
	reg := newMemRegistry()
	first, _ := NewEnvKMS(testMaster, reg)
	if err := first.Delete(context.Background(), "user:erin"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	restarted, _ := NewEnvKMS(testMaster, reg)
	if _, err := restarted.GetOrCreate(context.Background(), "user:erin"); !errors.Is(err, ErrKeyErased) {
		t.Fatalf("expected ErrKeyErased after a restart, got %v", err)
	}
}

func TestNewEnvKMSRejectsBadMasterKeys(t *testing.T) {
	for name, master := range map[string]string{
		"empty":      "",
		"not base64": "not base64!",
		"too short":  "AAAAAAAAAAAAAAAAAAAAAA==",
	} {
		if _, err := NewEnvKMS(master, newMemRegistry()); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
