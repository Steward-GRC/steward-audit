// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"fmt"

	postgres "github.com/Bugs5382/go-postgres"
)

// KeyRegistry keeps the crypto-shred key aliases in subject_encryption_keys,
// one row per subject, so an erasure survives a restart. The alias is the
// subject key.
type KeyRegistry struct{ db *postgres.DB }

// NewKeyRegistry returns a KeyRegistry on db.
func NewKeyRegistry(db *postgres.DB) *KeyRegistry { return &KeyRegistry{db: db} }

// Register records alias if it is new and reports whether it is erased.
func (k *KeyRegistry) Register(ctx context.Context, alias string) (bool, error) {
	var erased bool
	err := k.db.Querier().QueryRow(ctx, `
		INSERT INTO subject_encryption_keys (subject_id, key_alias) VALUES ($1, $1)
		ON CONFLICT (key_alias) DO UPDATE SET key_alias = EXCLUDED.key_alias
		RETURNING erased_at IS NOT NULL`, alias).Scan(&erased)
	if err != nil {
		return false, fmt.Errorf("store: register key: %w", err)
	}
	return erased, nil
}

// MarkErased records alias as erased, keeping the first erasure time.
func (k *KeyRegistry) MarkErased(ctx context.Context, alias string) error {
	if _, err := k.db.Querier().Exec(ctx, `
		INSERT INTO subject_encryption_keys (subject_id, key_alias, erased_at) VALUES ($1, $1, now())
		ON CONFLICT (key_alias) DO UPDATE
		SET erased_at = COALESCE(subject_encryption_keys.erased_at, now())`, alias); err != nil {
		return fmt.Errorf("store: erase key: %w", err)
	}
	return nil
}
