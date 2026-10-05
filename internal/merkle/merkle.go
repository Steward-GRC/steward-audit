// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

// Package merkle builds the binary SHA-256 Merkle tree a checkpoint commits to,
// and checks inclusion proofs against its root. Nodes are hex strings: a leaf
// is SHA-256 of the record hash's hex text, a parent is SHA-256 of its two
// children's hex texts concatenated, and the last node of an odd level is
// paired with itself.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
)

// ProofStep is one sibling on the path from a leaf to the root.
type ProofStep struct {
	Hash string
	Left bool // the sibling is on the left
}

// BuildTree returns the root over leaves and an inclusion proof per leaf. It
// panics on no leaves: an empty checkpoint is a caller bug.
func BuildTree(leaves []string) (root string, proofs [][]ProofStep) {
	if len(leaves) == 0 {
		panic("merkle: no leaves")
	}
	nodes := make([]string, len(leaves))
	for i, l := range leaves {
		nodes[i] = hashNode(l)
	}
	proofs = make([][]ProofStep, len(leaves))
	leafPos := make([]int, len(leaves))
	for i := range leafPos {
		leafPos[i] = i
	}

	for len(nodes) > 1 {
		next := make([]string, 0, (len(nodes)+1)/2)
		for i := 0; i < len(nodes); i += 2 {
			right := nodes[i]
			if i+1 < len(nodes) {
				right = nodes[i+1]
			}
			next = append(next, hashNode(nodes[i]+right))
		}
		for li, pos := range leafPos {
			switch {
			case pos%2 == 1:
				proofs[li] = append(proofs[li], ProofStep{Hash: nodes[pos-1], Left: true})
			case pos+1 < len(nodes):
				proofs[li] = append(proofs[li], ProofStep{Hash: nodes[pos+1]})
			default:
				proofs[li] = append(proofs[li], ProofStep{Hash: nodes[pos]})
			}
			leafPos[li] = pos / 2
		}
		nodes = next
	}
	return nodes[0], proofs
}

// VerifyProof reports whether leaf is in the tree with the given root.
func VerifyProof(leaf string, proof []ProofStep, root string) bool {
	current := hashNode(leaf)
	for _, step := range proof {
		if step.Left {
			current = hashNode(step.Hash + current)
		} else {
			current = hashNode(current + step.Hash)
		}
	}
	return current == root
}

func hashNode(data string) string {
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:])
}
