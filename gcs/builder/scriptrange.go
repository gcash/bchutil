// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/gcash/bchd/chaincfg/chainhash"
)

// A peer shows what a block's entry tree holds without sending the block: a
// run of consecutive leaves, with the hashes on the run's edges, rebuilds the
// root. The run of leaves whose keys start with a prefix, with the leaf just
// before it and the leaf just after it, also shows that the tree holds no
// other leaf with that prefix. A run of one leaf is that leaf's branch.

var (
	// ErrScriptLeaf is returned for a serialized leaf of the wrong size or
	// of an unknown kind.
	ErrScriptLeaf = errors.New("a script filter leaf is 41 bytes, of kind 0 to 3")

	// ErrScriptPrefix is returned for a key prefix longer than 256 bits, or
	// with a bit set past its length.
	ErrScriptPrefix = errors.New("a key prefix is at most 256 bits, with " +
		"the bits past its length zero")

	// ErrScriptRange is returned when a run of leaves, its neighbours and its
	// edge hashes don't fit a tree of the given leaf count.
	ErrScriptRange = errors.New("the leaves and hashes do not fit the tree")

	// ErrScriptRangeLeaves is returned when the leaves of a range are out of
	// order, a leaf of the run lacks the prefix, or a neighbour has it.
	ErrScriptRangeLeaves = errors.New("the leaves are out of order or do " +
		"not bound the prefix")

	// ErrScriptRangeRoot is returned when the leaves and hashes rebuild
	// another root than the block's.
	ErrScriptRangeRoot = errors.New("the leaves and hashes rebuild another root")
)

// ParseScriptLeaf parses a leaf serialized by ScriptLeaf.Bytes.
func ParseScriptLeaf(b []byte) (ScriptLeaf, error) {
	if len(b) != ScriptLeafSize || b[40] > byte(ScriptLeafSpentCategory) {
		return ScriptLeaf{}, ErrScriptLeaf
	}
	var leaf ScriptLeaf
	copy(leaf.Key[:], b[:32])
	leaf.TxIndex = binary.LittleEndian.Uint32(b[32:36])
	leaf.Index = binary.LittleEndian.Uint32(b[36:40])
	leaf.Kind = ScriptLeafKind(b[40])
	return leaf, nil
}

// checkScriptPrefix checks that a prefix has at most 256 bits and that the
// bits past its length are zero, so that each prefix has one encoding.
func checkScriptPrefix(prefix *[32]byte, bits uint16) error {
	if bits > 256 {
		return ErrScriptPrefix
	}
	full := int(bits / 8)
	if rem := bits % 8; rem != 0 {
		if prefix[full]&(0xff>>rem) != 0 {
			return ErrScriptPrefix
		}
		full++
	}
	for _, b := range prefix[full:] {
		if b != 0 {
			return ErrScriptPrefix
		}
	}
	return nil
}

// compareScriptPrefix compares the first bits of a key with a prefix.
func compareScriptPrefix(key, prefix *[32]byte, bits uint16) int {
	full := int(bits / 8)
	if c := bytes.Compare(key[:full], prefix[:full]); c != 0 {
		return c
	}
	if rem := bits % 8; rem != 0 {
		k := key[full] & (0xff << (8 - rem))
		switch {
		case k < prefix[full]:
			return -1
		case k > prefix[full]:
			return 1
		}
	}
	return 0
}

// ScriptLeavesWithPrefix returns the run leaves[first:end] of sorted leaves
// whose keys start with the first bits of prefix. A length of 0 takes every
// leaf, and 256 one exact key. When no leaf has the prefix, first equals end,
// the place where such a leaf would sit.
func ScriptLeavesWithPrefix(leaves []ScriptLeaf, prefix *[32]byte, bits uint16) (first, end int, err error) {
	if err := checkScriptPrefix(prefix, bits); err != nil {
		return 0, 0, err
	}
	first = sort.Search(len(leaves), func(i int) bool {
		return compareScriptPrefix(&leaves[i].Key, prefix, bits) >= 0
	})
	end = sort.Search(len(leaves), func(i int) bool {
		return compareScriptPrefix(&leaves[i].Key, prefix, bits) > 0
	})
	return first, end, nil
}

// ScriptRangeHashes returns the hashes that, with the run leaves[lo:end],
// rebuild the root of the tree over leaves. Level by level from the leaves
// up, they are the node just left of the run's first node, then the node just
// right of its last node, wherever the run doesn't already reach it. A last
// node without a partner moves up unchanged and needs none.
func ScriptRangeHashes(leaves []ScriptLeaf, lo, end int) ([]chainhash.Hash, error) {
	if lo < 0 || lo >= end || end > len(leaves) {
		return nil, ErrScriptRange
	}
	level := make([]chainhash.Hash, len(leaves))
	for i := range leaves {
		level[i] = ScriptLeafHash(&leaves[i])
	}
	var hashes []chainhash.Hash
	a, b := lo, end-1
	for len(level) > 1 {
		if a%2 == 1 {
			hashes = append(hashes, level[a-1])
		}
		if b%2 == 0 && b+1 < len(level) {
			hashes = append(hashes, level[b+1])
		}
		level = scriptNextLevel(level)
		a, b = a/2, b/2
	}
	return hashes, nil
}

// ScriptRangeRoot rebuilds the root of a tree of count leaves from a run of
// consecutive leaves that starts at index lo and the hashes ScriptRangeHashes
// lists for it. It fails when the hashes are too few or too many.
func ScriptRangeRoot(count, lo uint32, run []ScriptLeaf, hashes []chainhash.Hash) (chainhash.Hash, error) {
	if len(run) == 0 || uint64(lo)+uint64(len(run)) > uint64(count) {
		return chainhash.Hash{}, ErrScriptRange
	}
	nodes := make([]chainhash.Hash, len(run))
	for i := range run {
		nodes[i] = ScriptLeafHash(&run[i])
	}
	a, b, width := uint64(lo), uint64(lo)+uint64(len(run))-1, uint64(count)
	for width > 1 {
		if a%2 == 1 {
			if len(hashes) == 0 {
				return chainhash.Hash{}, ErrScriptRange
			}
			nodes = append([]chainhash.Hash{hashes[0]}, nodes...)
			hashes = hashes[1:]
			a--
		}
		if b%2 == 0 && b+1 < width {
			if len(hashes) == 0 {
				return chainhash.Hash{}, ErrScriptRange
			}
			nodes = append(nodes, hashes[0])
			hashes = hashes[1:]
			b++
		}
		nodes = scriptNextLevel(nodes)
		a, b, width = a/2, b/2, (width+1)/2
	}
	if len(hashes) != 0 {
		return chainhash.Hash{}, ErrScriptRange
	}
	return nodes[0], nil
}

// CheckScriptRange checks a range of a block's entry tree against the root in
// front of the block's script filter. The tree has count leaves, and run is
// the run of them from index first whose keys start with the prefix. before
// and after are the leaves next to the run: before is given exactly when first
// is above 0, and after exactly when the run ends before the last leaf. When
// it returns nil, the tree holds no other leaf with the prefix.
//
// ErrScriptRangeRoot means the reply doesn't belong to that root.
// ErrScriptRangeLeaves means the leaves do rebuild the root, so they are the
// tree's own, but are out of order or don't bound the prefix: the peer serves
// a wrong tree or a wrong answer.
func CheckScriptRange(root chainhash.Hash, count, first uint32, run []ScriptLeaf,
	before, after *ScriptLeaf, hashes []chainhash.Hash, prefix *[32]byte, bits uint16) error {

	if err := checkScriptPrefix(prefix, bits); err != nil {
		return err
	}
	end := uint64(first) + uint64(len(run))
	if end > uint64(count) || (first > 0) != (before != nil) || (end < uint64(count)) != (after != nil) {
		return ErrScriptRange
	}
	if count == 0 {
		if len(hashes) != 0 {
			return ErrScriptRange
		}
		if root != (chainhash.Hash{}) {
			return ErrScriptRangeRoot
		}
		return nil
	}

	span := make([]ScriptLeaf, 0, len(run)+2)
	lo := first
	if before != nil {
		span = append(span, *before)
		lo--
	}
	span = append(span, run...)
	if after != nil {
		span = append(span, *after)
	}
	rebuilt, err := ScriptRangeRoot(count, lo, span, hashes)
	if err != nil {
		return err
	}
	if rebuilt != root {
		return ErrScriptRangeRoot
	}

	for i := range run {
		if compareScriptPrefix(&run[i].Key, prefix, bits) != 0 {
			return ErrScriptRangeLeaves
		}
	}
	if before != nil && compareScriptPrefix(&before.Key, prefix, bits) >= 0 {
		return ErrScriptRangeLeaves
	}
	if after != nil && compareScriptPrefix(&after.Key, prefix, bits) <= 0 {
		return ErrScriptRangeLeaves
	}
	for i := 1; i < len(span); i++ {
		if compareScriptLeaves(span[i-1], span[i]) >= 0 {
			return ErrScriptRangeLeaves
		}
	}
	return nil
}
