// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchutil/gcs/builder"
)

// scriptRangeTestLeaves returns the ten sorted leaves of the test block and
// their root.
func scriptRangeTestLeaves(t *testing.T) ([]builder.ScriptLeaf, chainhash.Hash) {
	t.Helper()
	block, prevOutScripts := scriptFilterBlock()
	leaves, err := builder.ScriptLeaves(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != 10 {
		t.Fatalf("got %d leaves, want 10", len(leaves))
	}
	return leaves, builder.ScriptLeavesRoot(leaves)
}

// TestScriptRangeHashes checks the edge hashes of runs of the test block's
// ten leaves against a separate implementation of the tree, which lists, level
// by level, every node whose partner the run covers.
func TestScriptRangeHashes(t *testing.T) {
	leaves, root := scriptRangeTestLeaves(t)
	tests := []struct {
		name    string
		lo, end int
		hashes  []string
	}{
		{"leaves 3 to 5", 3, 6, []string{
			"2512bd80ee8cef99a54e819ae61fdba6da828e4f874b8ecba5e47559c616c476",
			"e5c9cff033bb91a3f42a868728b860c8a4eb1e6047d483b7b3a066f694f2180e",
			"9321aa6706ebb15995fd96c21947d13ac08de5651b28424e013249562233b815",
			"a3906f23297e3c240c522789fe69efeb3f125de38ed0627c8a02458599b47fb2",
		}},
		// The last leaf has no partner at the first level, and moves up.
		{"leaf 9", 9, 10, []string{
			"93aba49a21f3ff1d74de4f2ddfd5996c106cced8d8271325333fd507c7580a29",
			"bc683ecc5d6d6a2e7a734da1f2d778330e467c2ef845e2ef04dbdb86dc4b90f3",
		}},
		{"leaf 0", 0, 1, []string{
			"2892d10bbf543b5b6acb23ef107edeb7ed945fdd1cb928a0ce4c5390c75b5ca0",
			"560371e2c34b9f6c70d4c978410b91dfa757234e81a4c7553690fa75f2fe20fd",
			"0c661e38a5a8a7b99ecc5a4ef8edf3ed232a443151a05da5feee0993377117c5",
			"a3906f23297e3c240c522789fe69efeb3f125de38ed0627c8a02458599b47fb2",
		}},
		{"leaves 3 to 7", 3, 8, []string{
			"2512bd80ee8cef99a54e819ae61fdba6da828e4f874b8ecba5e47559c616c476",
			"e5c9cff033bb91a3f42a868728b860c8a4eb1e6047d483b7b3a066f694f2180e",
			"a3906f23297e3c240c522789fe69efeb3f125de38ed0627c8a02458599b47fb2",
		}},
		{"leaves 6 and 7", 6, 8, []string{
			"7fa40cb37ecdbeaaf92ea60c633b2865db56d1491be3a35a362f10b37ff451dc",
			"1cbf127a61c9b772d854662f32960f9bf4c05934e10b3c3b69b4075d6ed5e964",
			"a3906f23297e3c240c522789fe69efeb3f125de38ed0627c8a02458599b47fb2",
		}},
		{"every leaf", 0, 10, nil},
	}
	for _, test := range tests {
		hashes, err := builder.ScriptRangeHashes(leaves, test.lo, test.end)
		if err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		if len(hashes) != len(test.hashes) {
			t.Fatalf("%s: got %d hashes, want %d", test.name, len(hashes), len(test.hashes))
		}
		for i := range hashes {
			if hex.EncodeToString(hashes[i][:]) != test.hashes[i] {
				t.Errorf("%s: hash %d is %x, want %s", test.name, i, hashes[i][:], test.hashes[i])
			}
		}
		got, err := builder.ScriptRangeRoot(10, uint32(test.lo), leaves[test.lo:test.end], hashes)
		if err != nil || got != root {
			t.Errorf("%s: rebuilt root %x, %v; want %x", test.name, got[:], err, root[:])
		}
	}

	for _, bad := range [][2]int{{-1, 1}, {3, 3}, {4, 3}, {0, 11}} {
		if _, err := builder.ScriptRangeHashes(leaves, bad[0], bad[1]); !errors.Is(err, builder.ErrScriptRange) {
			t.Errorf("run %d to %d: got %v", bad[0], bad[1], err)
		}
	}
}

// TestScriptRangeRootEveryRun rebuilds the root of trees of 1 to 40 leaves
// from every run of their leaves, and refuses one hash too few or too many.
func TestScriptRangeRootEveryRun(t *testing.T) {
	for n := 1; n <= 40; n++ {
		// Distinct keys in order, each used by two transactions.
		leaves := make([]builder.ScriptLeaf, n)
		for i := range leaves {
			binary.BigEndian.PutUint32(leaves[i].Key[:4], uint32(i/2))
			leaves[i].TxIndex = uint32(i % 2)
		}
		root := builder.ScriptLeavesRoot(leaves)
		for lo := 0; lo < n; lo++ {
			for end := lo + 1; end <= n; end++ {
				hashes, err := builder.ScriptRangeHashes(leaves, lo, end)
				if err != nil {
					t.Fatal(err)
				}
				run := leaves[lo:end]
				got, err := builder.ScriptRangeRoot(uint32(n), uint32(lo), run, hashes)
				if err != nil || got != root {
					t.Fatalf("%d leaves, run %d to %d: %x, %v; want %x", n, lo, end, got[:], err, root[:])
				}
				extra := append(append([]chainhash.Hash(nil), hashes...), chainhash.Hash{})
				if _, err := builder.ScriptRangeRoot(uint32(n), uint32(lo), run, extra); !errors.Is(err, builder.ErrScriptRange) {
					t.Fatalf("%d leaves, run %d to %d with a hash too many: %v", n, lo, end, err)
				}
				if len(hashes) > 0 {
					fewer := hashes[:len(hashes)-1]
					if _, err := builder.ScriptRangeRoot(uint32(n), uint32(lo), run, fewer); !errors.Is(err, builder.ErrScriptRange) {
						t.Fatalf("%d leaves, run %d to %d with a hash too few: %v", n, lo, end, err)
					}
				}
			}
		}
	}
	if _, err := builder.ScriptRangeRoot(3, 2, make([]builder.ScriptLeaf, 2), nil); !errors.Is(err, builder.ErrScriptRange) {
		t.Errorf("run past the last leaf: %v", err)
	}
}

// scriptRange is a range of the entry tree as a peer would send it.
type scriptRange struct {
	count, first  uint32
	run           []builder.ScriptLeaf
	before, after *builder.ScriptLeaf
	hashes        []chainhash.Hash
}

// honestScriptRange answers a prefix the way a node does.
func honestScriptRange(t *testing.T, leaves []builder.ScriptLeaf, prefix *[32]byte, bits uint16) scriptRange {
	t.Helper()
	first, end, err := builder.ScriptLeavesWithPrefix(leaves, prefix, bits)
	if err != nil {
		t.Fatal(err)
	}
	r := scriptRange{count: uint32(len(leaves)), first: uint32(first), run: leaves[first:end]}
	lo, hi := first, end
	if first > 0 {
		r.before = &leaves[first-1]
		lo--
	}
	if end < len(leaves) {
		r.after = &leaves[end]
		hi++
	}
	if lo < hi {
		if r.hashes, err = builder.ScriptRangeHashes(leaves, lo, hi); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

func (r scriptRange) check(root chainhash.Hash, prefix *[32]byte, bits uint16) error {
	return builder.CheckScriptRange(root, r.count, r.first, r.run, r.before, r.after, r.hashes, prefix, bits)
}

// TestCheckScriptRange checks honest answers for prefixes of the test block's
// keys, including one no key has, and refuses each way a peer could leave a
// leaf out, misplace one or answer for another tree.
func TestCheckScriptRange(t *testing.T) {
	leaves, root := scriptRangeTestLeaves(t)
	prefixOf := func(b ...byte) *[32]byte {
		var p [32]byte
		copy(p[:], b)
		return &p
	}
	exact := leaves[0].Key

	tests := []struct {
		name       string
		prefix     *[32]byte
		bits       uint16
		first, end int
	}{
		{"every leaf", prefixOf(), 0, 0, 10},
		{"first 4 bits 0001", prefixOf(0x10), 4, 0, 2},
		{"first byte 5c", prefixOf(0x5c), 8, 4, 7},
		{"first byte 80, which no key has", prefixOf(0x80), 8, 7, 7},
		{"first byte ff, past the last key", prefixOf(0xff), 8, 10, 10},
		{"the first leaf's whole key", &exact, 256, 0, 2},
	}
	for _, test := range tests {
		r := honestScriptRange(t, leaves, test.prefix, test.bits)
		if int(r.first) != test.first || int(r.first)+len(r.run) != test.end {
			t.Errorf("%s: run %d to %d, want %d to %d", test.name, r.first,
				int(r.first)+len(r.run), test.first, test.end)
		}
		if err := r.check(root, test.prefix, test.bits); err != nil {
			t.Errorf("%s: %v", test.name, err)
		}
	}

	p5c := prefixOf(0x5c)
	honest := honestScriptRange(t, leaves, p5c, 8)

	// Leaving out the run's last leaf: it becomes the after neighbour, which
	// has the prefix.
	shorter := scriptRange{count: 10, first: 4, run: leaves[4:6], before: &leaves[3], after: &leaves[6]}
	shorter.hashes, _ = builder.ScriptRangeHashes(leaves, 3, 7)
	if err := shorter.check(root, p5c, 8); !errors.Is(err, builder.ErrScriptRangeLeaves) {
		t.Errorf("a leaf left out: %v", err)
	}

	// Claiming no leaf has the prefix.
	absent := scriptRange{count: 10, first: 4, before: &leaves[3], after: &leaves[4]}
	absent.hashes, _ = builder.ScriptRangeHashes(leaves, 3, 5)
	if err := absent.check(root, p5c, 8); !errors.Is(err, builder.ErrScriptRangeLeaves) {
		t.Errorf("a key claimed absent: %v", err)
	}

	// The same range checked against another root.
	if err := honest.check(chainhash.Hash{1}, p5c, 8); !errors.Is(err, builder.ErrScriptRangeRoot) {
		t.Errorf("another root: %v", err)
	}

	// A neighbour missing, or one given where the tree has none.
	noBefore := honest
	noBefore.before = nil
	if err := noBefore.check(root, p5c, 8); !errors.Is(err, builder.ErrScriptRange) {
		t.Errorf("before neighbour missing: %v", err)
	}
	everything := honestScriptRange(t, leaves, prefixOf(), 0)
	everything.after = &leaves[0]
	if err := everything.check(root, prefixOf(), 0); !errors.Is(err, builder.ErrScriptRange) {
		t.Errorf("after neighbour past the last leaf: %v", err)
	}

	// An unsorted tree answers with its own leaves and root, out of order.
	unsorted := append([]builder.ScriptLeaf(nil), leaves...)
	unsorted[5], unsorted[8] = unsorted[8], unsorted[5]
	all := honestScriptRange(t, unsorted, prefixOf(), 0)
	if err := all.check(builder.ScriptLeavesRoot(unsorted), prefixOf(), 0); !errors.Is(err, builder.ErrScriptRangeLeaves) {
		t.Errorf("unsorted tree: %v", err)
	}

	// Prefixes with a bit set past their length, or longer than a key.
	if err := honest.check(root, prefixOf(0x5c), 4); !errors.Is(err, builder.ErrScriptPrefix) {
		t.Errorf("bits past the length: %v", err)
	}
	if _, _, err := builder.ScriptLeavesWithPrefix(leaves, prefixOf(), 257); !errors.Is(err, builder.ErrScriptPrefix) {
		t.Errorf("257 bits: %v", err)
	}

	// The tree of a block without leaves has the zero root.
	if err := builder.CheckScriptRange(chainhash.Hash{}, 0, 0, nil, nil, nil, nil, p5c, 8); err != nil {
		t.Errorf("empty tree: %v", err)
	}
	if err := builder.CheckScriptRange(root, 0, 0, nil, nil, nil, nil, p5c, 8); !errors.Is(err, builder.ErrScriptRangeRoot) {
		t.Errorf("empty tree with a root: %v", err)
	}
}

// TestParseScriptLeaf parses every leaf of the test block back, and refuses
// a leaf of the wrong size or of an unknown kind.
func TestParseScriptLeaf(t *testing.T) {
	leaves, _ := scriptRangeTestLeaves(t)
	for _, leaf := range leaves {
		b := leaf.Bytes()
		got, err := builder.ParseScriptLeaf(b[:])
		if err != nil || got != leaf {
			t.Errorf("leaf %x: got %+v, %v", b, got, err)
		}
	}
	b := leaves[0].Bytes()
	if _, err := builder.ParseScriptLeaf(b[:40]); !errors.Is(err, builder.ErrScriptLeaf) {
		t.Errorf("40 bytes: %v", err)
	}
	b[40] = 4
	if _, err := builder.ParseScriptLeaf(b[:]); !errors.Is(err, builder.ErrScriptLeaf) {
		t.Errorf("kind 4: %v", err)
	}
}
