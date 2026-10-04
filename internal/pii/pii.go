// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package pii encrypts a subject's personal data under that subject's key, so
// destroying the key erases the data.
package pii

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/Steward-GRC/steward-audit/internal/kms"
)

// KeyGetter is the part of kms.KeyProvider encryption needs.
type KeyGetter interface {
	GetOrCreate(ctx context.Context, alias string) ([]byte, error)
}

// Encrypt seals plaintext with AES-256-GCM under alias's key and returns
// nonce || ciphertext || tag.
func Encrypt(ctx context.Context, kp KeyGetter, alias string, plaintext []byte) ([]byte, error) {
	gcm, err := aead(ctx, kp, alias)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("pii: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt opens what Encrypt sealed. It wraps kms.ErrKeyErased when the
// subject has been shredded.
func Decrypt(ctx context.Context, kp KeyGetter, alias string, ciphertext []byte) ([]byte, error) {
	gcm, err := aead(ctx, kp, alias)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(ciphertext) < ns {
		return nil, errors.New("pii: ciphertext too short")
	}
	out, err := gcm.Open(nil, ciphertext[:ns], ciphertext[ns:], nil)
	if err != nil {
		return nil, fmt.Errorf("pii: open: %w", err)
	}
	return out, nil
}

func aead(ctx context.Context, kp KeyGetter, alias string) (cipher.AEAD, error) {
	key, err := kp.GetOrCreate(ctx, alias)
	if err != nil {
		return nil, fmt.Errorf("pii: key for %q: %w", alias, err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("pii: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

var _ KeyGetter = (kms.KeyProvider)(nil)
