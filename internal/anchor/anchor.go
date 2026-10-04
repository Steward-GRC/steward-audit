// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package anchor anchors a checkpoint's Merkle root to an outside source of
// time, so the chain can't be rewritten and re-checkpointed later unnoticed.
package anchor

import "context"

// AnchorResult is what an anchor returned for one root.
type AnchorResult struct {
	// RawToken is the provider's proof, stored as received (for RFC 3161, the
	// DER TimeStampResp).
	RawToken []byte
	// AnchoredAt is the local receipt time, RFC 3339 in UTC. The token's own
	// time is the authoritative one.
	AnchoredAt string
}

// Anchorer submits a hex Merkle root to an anchor provider.
type Anchorer interface {
	Anchor(ctx context.Context, merkleRoot string) (*AnchorResult, error)
	// Type names the anchor kind stored with the checkpoint, such as "rfc3161".
	Type() string
	// URL is the provider endpoint stored with the checkpoint.
	URL() string
}
