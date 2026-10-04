// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package kms

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
)

// Registry records which aliases exist and which are erased. It is what makes
// an erasure outlast the process.
type Registry interface {
	// Register records alias if it is new and reports whether it is erased.
	Register(ctx context.Context, alias string) (erased bool, err error)
	// MarkErased records alias as erased, whether or not it was registered.
	MarkErased(ctx context.Context, alias string) error
}

// EnvKMS derives each alias's key as HMAC-SHA-256(master, alias) and keeps
// erasures in a Registry. It is for development and tests: anyone holding the
// master key can still derive an erased key, so production needs a key
// service that destroys the key material itself.
type EnvKMS struct {
	master []byte
	reg    Registry
}

// NewEnvKMS returns an EnvKMS for a base64 master key of at least 32 bytes.
func NewEnvKMS(masterB64 string, reg Registry) (*EnvKMS, error) {
	if masterB64 == "" {
		return nil, errors.New("kms: a master key is required")
	}
	master, err := base64.StdEncoding.DecodeString(masterB64)
	if err != nil {
		return nil, fmt.Errorf("kms: decode master key: %w", err)
	}
	if len(master) < 32 {
		return nil, errors.New("kms: the master key must be at least 32 bytes")
	}
	return &EnvKMS{master: master, reg: reg}, nil
}

// GetOrCreate returns alias's key, or ErrKeyErased.
func (e *EnvKMS) GetOrCreate(ctx context.Context, alias string) ([]byte, error) {
	erased, err := e.reg.Register(ctx, alias)
	if err != nil {
		return nil, fmt.Errorf("kms: register %q: %w", alias, err)
	}
	if erased {
		return nil, ErrKeyErased
	}
	mac := hmac.New(sha256.New, e.master)
	mac.Write([]byte(alias))
	return mac.Sum(nil), nil
}

// Delete marks alias erased in the registry.
func (e *EnvKMS) Delete(ctx context.Context, alias string) error {
	if err := e.reg.MarkErased(ctx, alias); err != nil {
		return fmt.Errorf("kms: erase %q: %w", alias, err)
	}
	return nil
}
