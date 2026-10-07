// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"fmt"
	"time"

	"github.com/Steward-GRC/steward-audit/internal/merkle"
)

// VerifyRecord is the part of a stored record the verifier needs. Attributes
// are re-canonicalised, so the key order JSONB hands back doesn't matter.
type VerifyRecord struct {
	ID          int64
	PrevHash    string
	RecordHash  string
	Tier        string
	Action      string
	ActorUserID string
	Subject     string
	GroupID     string
	OccurredAt  time.Time
	Attributes  map[string]string
	// Purged marks a record the retention purge tombstoned: its content is
	// cleared, so only its link is checked and its stored hash is trusted.
	// The checkpoint roots and the next record's link still cover that hash.
	Purged bool
}

// VerifyCheckpoint is a stored Merkle root over [FromRecordID, ToRecordID].
// The RFC 3161 token is not checked here: only the root is recomputed.
type VerifyCheckpoint struct {
	CheckpointUUID string
	FromRecordID   int64
	ToRecordID     int64
	MerkleRoot     string
	TSAToken       []byte
}

// VerifyReport is the outcome of a verification run.
type VerifyReport struct {
	Valid              bool
	RecordsChecked     int
	RecordsPurged      int
	CheckpointsChecked int
	Errors             []string
}

// VerifyChain verifies records that start at the genesis. See VerifyChainFrom.
func VerifyChain(records []VerifyRecord, checkpoints []VerifyCheckpoint) VerifyReport {
	return VerifyChainFrom("", records, checkpoints)
}

// VerifyChainFrom verifies a contiguous slice of the chain, in ascending id
// order, whose first prev_hash must equal initialPrevHash (the hash of the
// record before the slice, or "" at the genesis). It checks every record's
// link and recomputed hash, and every checkpoint's Merkle root. A purged
// record's hash can't be recomputed: only its link is checked, and it must be
// in the activity tier, the only tier the purge touches.
func VerifyChainFrom(initialPrevHash string, records []VerifyRecord, checkpoints []VerifyCheckpoint) VerifyReport {
	report := VerifyReport{Valid: true, RecordsChecked: len(records)}
	hashByID := make(map[int64]string, len(records))

	prevHash := initialPrevHash
	for i, r := range records {
		hashByID[r.ID] = r.RecordHash
		if r.PrevHash != prevHash {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf(
				"record id=%d: prev_hash %q != expected %q", r.ID, r.PrevHash, prevHash))
		}
		prevHash = r.RecordHash
		if r.Purged {
			report.RecordsPurged++
			if r.Tier != "activity" {
				report.Valid = false
				report.Errors = append(report.Errors, fmt.Sprintf(
					"record id=%d: purged but in the %q tier, which is never purged", r.ID, r.Tier))
			}
			continue
		}
		computed := ComputeHash(r.PrevHash, r.Tier, r.Action, r.ActorUserID, r.Subject, r.GroupID,
			CanonicalTime(r.OccurredAt), r.Attributes)
		if computed != r.RecordHash {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf(
				"record id=%d (index %d): stored hash %q != recomputed %q", r.ID, i, r.RecordHash, computed))
		}
	}

	// Record ids have gaps (a rolled-back insert still consumes a sequence
	// value) and the root was built over the records that exist, so a missing
	// id here is not tampering. A removed committed record is caught above by
	// the next record's link.
	for _, cp := range checkpoints {
		report.CheckpointsChecked++
		var hashes []string
		for id := cp.FromRecordID; id <= cp.ToRecordID; id++ {
			if h, ok := hashByID[id]; ok {
				hashes = append(hashes, h)
			}
		}
		if len(hashes) == 0 {
			continue
		}
		if root, _ := merkle.BuildTree(hashes); root != cp.MerkleRoot {
			report.Valid = false
			report.Errors = append(report.Errors, fmt.Sprintf(
				"checkpoint %s: stored merkle_root %q != recomputed %q", cp.CheckpointUUID, cp.MerkleRoot, root))
		}
	}
	return report
}
