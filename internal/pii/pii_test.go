// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package pii

import (
	"context"
	"errors"
	"testing"

	"github.com/Steward-GRC/steward-audit/internal/fixture"
	"github.com/Steward-GRC/steward-audit/internal/kms"
)

type fakeKMS struct{ erased map[string]bool }

func newFakeKMS() *fakeKMS { return &fakeKMS{erased: make(map[string]bool)} }

func (f *fakeKMS) GetOrCreate(_ context.Context, alias string) ([]byte, error) {
	if f.erased[alias] {
		return nil, kms.ErrKeyErased
	}
	key := make([]byte, 32)
	copy(key, alias)
	return key, nil
}

func (f *fakeKMS) Delete(_ context.Context, alias string) error {
	f.erased[alias] = true
	return nil
}

var plaintext = []byte(`{"ip":"` + fixture.DocAddress + `","ua":"ExampleBrowser/1.0"}`)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS()
	ct, err := Encrypt(ctx, k, fixture.UserErin, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("ciphertext must not be empty")
	}
	got, err := Decrypt(ctx, k, fixture.UserErin, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptUsesAFreshNonce(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS()
	a, _ := Encrypt(ctx, k, fixture.UserErin, plaintext)
	b, _ := Encrypt(ctx, k, fixture.UserErin, plaintext)
	if string(a) == string(b) {
		t.Fatal("two encryptions of the same data must differ")
	}
}

func TestDecryptAfterKeyErasureReturnsError(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS()
	ct, _ := Encrypt(ctx, k, fixture.UserBob, []byte("sensitive"))
	_ = k.Delete(ctx, fixture.UserBob)
	if _, err := Decrypt(ctx, k, fixture.UserBob, ct); !errors.Is(err, kms.ErrKeyErased) {
		t.Fatalf("expected ErrKeyErased after key erasure, got %v", err)
	}
}

func TestDecryptRejectsTamperedOrShortCiphertext(t *testing.T) {
	ctx := context.Background()
	k := newFakeKMS()
	ct, _ := Encrypt(ctx, k, fixture.UserErin, plaintext)
	ct[len(ct)-1] ^= 0xff
	if _, err := Decrypt(ctx, k, fixture.UserErin, ct); err == nil {
		t.Fatal("a tampered ciphertext must not decrypt")
	}
	if _, err := Decrypt(ctx, k, fixture.UserErin, []byte{1, 2, 3}); err == nil {
		t.Fatal("a short ciphertext must not decrypt")
	}
	good, _ := Encrypt(ctx, k, fixture.UserErin, plaintext)
	if _, err := Decrypt(ctx, k, fixture.UserBob, good); err == nil {
		t.Fatal("another subject's key must not decrypt")
	}
}
