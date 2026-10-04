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
	"sync"
)

// EnvKMS derives each alias's key as HMAC-SHA-256(master, alias). It is for
// development and tests only: erasures live in memory and are forgotten on
// restart, so a shredded subject's key comes back.
type EnvKMS struct {
	master []byte
	mu     sync.RWMutex
	erased map[string]bool
}

// NewEnvKMS returns an EnvKMS for a base64 master key of at least 32 bytes.
func NewEnvKMS(masterB64 string) (*EnvKMS, error) {
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
	return &EnvKMS{master: master, erased: make(map[string]bool)}, nil
}

// GetOrCreate returns alias's key, or ErrKeyErased.
func (e *EnvKMS) GetOrCreate(_ context.Context, alias string) ([]byte, error) {
	e.mu.RLock()
	erased := e.erased[alias]
	e.mu.RUnlock()
	if erased {
		return nil, ErrKeyErased
	}
	mac := hmac.New(sha256.New, e.master)
	mac.Write([]byte(alias))
	return mac.Sum(nil), nil
}

// Delete marks alias erased.
func (e *EnvKMS) Delete(_ context.Context, alias string) error {
	e.mu.Lock()
	e.erased[alias] = true
	e.mu.Unlock()
	return nil
}
