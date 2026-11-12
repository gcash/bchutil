// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs"
)

// The script filter (filter type 1) lists the locking scripts of the outputs
// a block creates and of the outputs it spends, and the token categories of
// both. A wallet matches it with its own scripts and token categories only:
// spending one of its coins matches the script that received it, so it does
// not watch outpoints as it does on the basic filter.
//
// The filter cannot be rebuilt from the block alone, since the scripts of
// spent outputs sit in older blocks. So each block's entries are also kept as
// a sorted list of leaves under a Merkle root. The filter is served with that
// root in front of it, and its header is made the way the basic filter's is,
// over those bytes, so the header chain commits to the root too. A peer that
// serves a wrong filter can then be shown wrong with a few leaves and their
// branches instead of the whole block.

// ScriptLeafSize is the size of a serialized leaf of a script filter's
// entry tree: the key, the transaction's index in the block, the input or
// output index, and the kind.
const ScriptLeafSize = 32 + 4 + 4 + 1

// ScriptLeafKind says what a leaf's key comes from.
type ScriptLeafKind uint8

const (
	// ScriptLeafOutput is the locking script of an output the block
	// creates.
	ScriptLeafOutput ScriptLeafKind = 0

	// ScriptLeafSpent is the locking script of an output the block spends.
	ScriptLeafSpent ScriptLeafKind = 1

	// ScriptLeafOutputCategory is the token category of an output the block
	// creates.
	ScriptLeafOutputCategory ScriptLeafKind = 2

	// ScriptLeafSpentCategory is the token category of an output the block
	// spends.
	ScriptLeafSpentCategory ScriptLeafKind = 3
)

// ScriptLeaf is one occurrence of a key in a block: a script or a token
// category, and where in the block it occurs.
type ScriptLeaf struct {
	Key     [32]byte
	TxIndex uint32
	Index   uint32
	Kind    ScriptLeafKind
}

// Bytes returns the leaf serialized: the key, then the transaction index and
// the input or output index as little-endian uint32, then the kind.
func (l *ScriptLeaf) Bytes() [ScriptLeafSize]byte {
	var b [ScriptLeafSize]byte
	copy(b[:32], l.Key[:])
	binary.LittleEndian.PutUint32(b[32:36], l.TxIndex)
	binary.LittleEndian.PutUint32(b[36:40], l.Index)
	b[40] = byte(l.Kind)
	return b
}

// compareScriptLeaves orders leaves by key, then transaction index, then
// input or output index, then kind.
func compareScriptLeaves(a, b ScriptLeaf) int {
	if c := bytes.Compare(a.Key[:], b.Key[:]); c != 0 {
		return c
	}
	switch {
	case a.TxIndex != b.TxIndex:
		return cmpUint32(a.TxIndex, b.TxIndex)
	case a.Index != b.Index:
		return cmpUint32(a.Index, b.Index)
	default:
		return int(a.Kind) - int(b.Kind)
	}
}

func cmpUint32(a, b uint32) int {
	if a < b {
		return -1
	}
	return 1
}

// ScriptKey returns the key of a locking script: its SHA-256, the script hash
// the Electrum Cash protocol uses. The script is the bare locking script,
// without a token prefix.
func ScriptKey(script []byte) [32]byte {
	return sha256.Sum256(script)
}

// CategoryKey returns the key of a token category: the SHA-256 of 0x01
// followed by the category as it appears in a token prefix. The tag keeps a
// category key from ever equalling a script key.
func CategoryKey(category [32]byte) [32]byte {
	var b [33]byte
	b[0] = 0x01
	copy(b[1:], category[:])
	return sha256.Sum256(b[:])
}

// filtersScript reports whether a locking script gets a key: an empty script
// and one that starts with OP_RETURN do not, since no wallet watches them.
func filtersScript(script []byte) bool {
	return len(script) > 0 && script[0] != opReturn
}

// opReturn is the OP_RETURN opcode.
const opReturn = 0x6a

// ErrPrevOutScripts is returned when the scripts of the spent outputs do not
// line up with the block's inputs.
var ErrPrevOutScripts = errors.New("the spent output scripts do not match " +
	"the block's inputs")

// ScriptLeaves returns the leaves of a block's script filter, sorted.
// prevOutScripts holds the script of every output the block spends, as the
// spend journal keeps it, with any token prefix in front, one for each input
// of the block's transactions after the coinbase, in order.
//
// For every output the block creates, coinbase included, and every output it
// spends, the locking script gets a leaf unless it is empty or starts with
// OP_RETURN, and a token category gets a leaf of its own. A key that occurs
// more than once in the block gets one leaf for each occurrence.
func ScriptLeaves(block *wire.MsgBlock, prevOutScripts [][]byte) ([]ScriptLeaf, error) {
	var leaves []ScriptLeaf
	spent := 0
	for i, tx := range block.Transactions {
		txIndex := uint32(i)
		if i > 0 {
			for j := range tx.TxIn {
				if spent >= len(prevOutScripts) {
					return nil, ErrPrevOutScripts
				}
				tokenData, script := wire.SplitPkScript(prevOutScripts[spent])
				spent++
				if filtersScript(script) {
					leaves = append(leaves, ScriptLeaf{
						Key:     ScriptKey(script),
						TxIndex: txIndex,
						Index:   uint32(j),
						Kind:    ScriptLeafSpent,
					})
				}
				if !tokenData.IsEmpty() {
					leaves = append(leaves, ScriptLeaf{
						Key:     CategoryKey(tokenData.CategoryID),
						TxIndex: txIndex,
						Index:   uint32(j),
						Kind:    ScriptLeafSpentCategory,
					})
				}
			}
		}
		for j, txOut := range tx.TxOut {
			if filtersScript(txOut.PkScript) {
				leaves = append(leaves, ScriptLeaf{
					Key:     ScriptKey(txOut.PkScript),
					TxIndex: txIndex,
					Index:   uint32(j),
					Kind:    ScriptLeafOutput,
				})
			}
			if !txOut.TokenData.IsEmpty() {
				leaves = append(leaves, ScriptLeaf{
					Key:     CategoryKey(txOut.TokenData.CategoryID),
					TxIndex: txIndex,
					Index:   uint32(j),
					Kind:    ScriptLeafOutputCategory,
				})
			}
		}
	}
	if spent != len(prevOutScripts) {
		return nil, ErrPrevOutScripts
	}
	slices.SortFunc(leaves, compareScriptLeaves)
	return leaves, nil
}

// ScriptLeafHash returns the hash of a leaf in the entry tree: the SHA-256 of
// 0x00 followed by the serialized leaf.
func ScriptLeafHash(leaf *ScriptLeaf) chainhash.Hash {
	var b [1 + ScriptLeafSize]byte
	serialized := leaf.Bytes()
	copy(b[1:], serialized[:])
	return chainhash.Hash(sha256.Sum256(b[:]))
}

// ScriptNodeHash returns the hash of an inner node of the entry tree: the
// SHA-256 of 0x01 followed by its two children.
func ScriptNodeHash(left, right *chainhash.Hash) chainhash.Hash {
	var b [1 + 2*chainhash.HashSize]byte
	b[0] = 0x01
	copy(b[1:], left[:])
	copy(b[1+chainhash.HashSize:], right[:])
	return chainhash.Hash(sha256.Sum256(b[:]))
}

// ScriptLeavesRoot returns the Merkle root over sorted leaves. A node left
// without a partner at its level moves up unchanged, so no node is ever
// paired with itself. The root of no leaves is the zero hash.
func ScriptLeavesRoot(leaves []ScriptLeaf) chainhash.Hash {
	if len(leaves) == 0 {
		return chainhash.Hash{}
	}
	level := make([]chainhash.Hash, len(leaves))
	for i := range leaves {
		level[i] = ScriptLeafHash(&leaves[i])
	}
	for len(level) > 1 {
		next := level[:0]
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				next = append(next, level[i])
				continue
			}
			next = append(next, ScriptNodeHash(&level[i], &level[i+1]))
		}
		level = next
	}
	return level[0]
}

// BuildScriptFilter builds a block's script filter from its leaves: a GCS
// filter over the distinct keys, keyed by the block hash, with the same P, M
// and serialization as the basic filter. It returns the filter and the root
// of the leaves, which ScriptFilterBytes puts in front of it.
func BuildScriptFilter(block *wire.MsgBlock, prevOutScripts [][]byte) (*gcs.Filter, chainhash.Hash, error) {
	leaves, err := ScriptLeaves(block, prevOutScripts)
	if err != nil {
		return nil, chainhash.Hash{}, err
	}

	blockHash := block.BlockHash()
	b := WithKeyHash(&blockHash)
	if _, err := b.Key(); err != nil {
		return nil, chainhash.Hash{}, err
	}
	for i := range leaves {
		// The builder keeps each distinct key once.
		b.AddEntry(leaves[i].Key[:])
	}
	filter, err := b.Build()
	if err != nil {
		return nil, chainhash.Hash{}, err
	}
	return filter, ScriptLeavesRoot(leaves), nil
}

// ScriptFilterBytes returns a script filter as it is stored and served: the
// root of its leaves, then the filter's N-prefixed bytes.
func ScriptFilterBytes(filter *gcs.Filter, root chainhash.Hash) ([]byte, error) {
	filterBytes, err := filter.NBytes()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 0, chainhash.HashSize+len(filterBytes))
	b = append(b, root[:]...)
	return append(b, filterBytes...), nil
}

// ErrScriptFilterTooShort is returned for script filter bytes that cannot
// hold a root.
var ErrScriptFilterTooShort = errors.New("script filter shorter than its root")

// ParseScriptFilter splits a served script filter into its GCS filter and the
// root of its leaves.
func ParseScriptFilter(b []byte) (*gcs.Filter, chainhash.Hash, error) {
	if len(b) < chainhash.HashSize {
		return nil, chainhash.Hash{}, ErrScriptFilterTooShort
	}
	var root chainhash.Hash
	copy(root[:], b[:chainhash.HashSize])
	filter, err := gcs.FromNBytes(DefaultP, DefaultM, b[chainhash.HashSize:])
	if err != nil {
		return nil, chainhash.Hash{}, err
	}
	return filter, root, nil
}

// GetScriptFilterHash returns the double SHA-256 of a script filter's served
// bytes, the hash a cfheaders message lists for it.
func GetScriptFilterHash(filter *gcs.Filter, root chainhash.Hash) (chainhash.Hash, error) {
	b, err := ScriptFilterBytes(filter, root)
	if err != nil {
		return chainhash.Hash{}, err
	}
	return chainhash.DoubleHashH(b), nil
}

// MakeHeaderForScriptFilter makes a script filter's header the way
// MakeHeaderForFilter makes a basic filter's, over its served bytes: the
// double SHA-256 of their hash and the previous header. The header chain thus
// commits to the root of each block's leaves as well as to its filter.
func MakeHeaderForScriptFilter(filter *gcs.Filter, root, prevHeader chainhash.Hash) (chainhash.Hash, error) {
	filterHash, err := GetScriptFilterHash(filter, root)
	if err != nil {
		return chainhash.Hash{}, err
	}
	var b [2 * chainhash.HashSize]byte
	copy(b[:], filterHash[:])
	copy(b[chainhash.HashSize:], prevHeader[:])
	return chainhash.DoubleHashH(b[:]), nil
}
