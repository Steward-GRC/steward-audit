// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package kms provides the per-subject keys personal data is encrypted under.
// Destroying a subject's key is what crypto-shred means: everything encrypted
// under it, backups included, becomes unreadable.
package kms

import (
	"context"
	"errors"
)

// ErrKeyErased means the key was destroyed by a crypto-shred.
var ErrKeyErased = errors.New("kms: key has been erased (crypto-shredded)")

// KeyProvider gives out and destroys per-subject AES-256 keys.
type KeyProvider interface {
	// GetOrCreate returns the 32-byte key for alias, or ErrKeyErased.
	GetOrCreate(ctx context.Context, alias string) ([]byte, error)
	// Delete destroys alias; GetOrCreate then returns ErrKeyErased.
	Delete(ctx context.Context, alias string) error
}
