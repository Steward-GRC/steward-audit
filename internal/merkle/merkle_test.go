// Copyright 2026 The Steward Authors
// SPDX-License-Identifier: Apache-2.0

package merkle

import "testing"

func TestBuildTreeEmptyPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on empty input")
		}
	}()
	BuildTree(nil)
}

func TestBuildTreeSingleLeaf(t *testing.T) {
	root, _ := BuildTree([]string{"3f2a9c41"})
	if root == "" {
		t.Fatal("root must not be empty")
	}
}

func TestBuildTreeRootChangesWithLeaf(t *testing.T) {
	root1, _ := BuildTree([]string{"aabb", "ccdd"})
	root2, _ := BuildTree([]string{"aabb", "eeff"})
	if root1 == root2 {
		t.Fatal("different leaves must produce different roots")
	}
}

func TestProofForVerifies(t *testing.T) {
	leaves := []string{"a1", "b2", "c3", "d4"}
	root, proofs := BuildTree(leaves)
	for i, p := range proofs {
		if !VerifyProof(leaves[i], p, root) {
			t.Fatalf("proof for leaf %d failed to verify", i)
		}
	}
}

// Odd levels duplicate the last node; every leaf still proves.
func TestProofForOddLeafCounts(t *testing.T) {
	for n := 1; n <= 9; n++ {
		leaves := make([]string, n)
		for i := range leaves {
			leaves[i] = string(rune('a' + i))
		}
		root, proofs := BuildTree(leaves)
		for i, p := range proofs {
			if !VerifyProof(leaves[i], p, root) {
				t.Fatalf("n=%d: proof for leaf %d failed to verify", n, i)
			}
		}
	}
}

func TestProofRejectsWrongLeafOrRoot(t *testing.T) {
	leaves := []string{"a1", "b2", "c3"}
	root, proofs := BuildTree(leaves)
	if VerifyProof("zz", proofs[0], root) {
		t.Fatal("a leaf not in the tree must not verify")
	}
	other, _ := BuildTree([]string{"a1", "b2", "c4"})
	if VerifyProof(leaves[0], proofs[0], other) {
		t.Fatal("a proof must not verify against another root")
	}
}
