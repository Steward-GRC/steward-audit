// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package chain is the SHA-256 hash chain of the audit log. Each record's hash
// commits to the previous record's hash and to its own canonical fields, so
// changing any stored row breaks every hash after it.
package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// CanonicalTime is the one form of an event time the chain commits to, on the
// write path and the verify path alike. It truncates to microseconds because
// that is all a Postgres TIMESTAMPTZ keeps: hashing nanoseconds at write time
// would never match the value read back.
func CanonicalTime(t time.Time) string {
	return t.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano)
}

// ComputeHash returns the hex SHA-256 of
//
//	prevHash \x00 tier \x00 action \x00 actor \x00 subject \x00 group \x00 occurredAt \x00 attrs \x00
//
// prevHash is empty for the genesis record. occurredAt must come from
// CanonicalTime. attrs is a JSON object with sorted keys, "{}" when empty.
// The NUL separators stop bytes moving across a field boundary unnoticed.
// Changing this layout invalidates every stored chain.
func ComputeHash(prevHash, tier, action, actorUserID, subject, groupID, occurredAt string, attributes map[string]string) string {
	h := sha256.New()
	for _, part := range []string{prevHash, tier, action, actorUserID, subject, groupID, occurredAt, sortedAttrsJSON(attributes)} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func sortedAttrsJSON(m map[string]string) string {
	if len(m) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(m[k])
		b.Write(kb)
		b.WriteByte(':')
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.String()
}
