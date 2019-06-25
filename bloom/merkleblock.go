// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom

import (
	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
)

// merkleBlock is used to house intermediate information needed to generate a
// wire.MsgMerkleBlock according to a filter.
type merkleBlock struct {
	numTx       uint32
	allHashes   []*chainhash.Hash
	finalHashes []*chainhash.Hash
	matchedBits []byte
	bits        []byte
}

// calcTreeWidth calculates and returns the the number of nodes (width) or a
// merkle tree at the given depth-first height.
func (m *merkleBlock) calcTreeWidth(height uint32) uint32 {
	return (m.numTx + (1 << height) - 1) >> height
}

// calcHash returns the hash for a sub-tree given a depth-first height and
// node position.
func (m *merkleBlock) calcHash(height, pos uint32) *chainhash.Hash {
	if height == 0 {
		return m.allHashes[pos]
	}

	var right *chainhash.Hash
	left := m.calcHash(height-1, pos*2)
	if pos*2+1 < m.calcTreeWidth(height-1) {
		right = m.calcHash(height-1, pos*2+1)
	} else {
		right = left
	}
	return blockchain.HashMerkleBranches(left, right)
}

// traverseAndBuild builds a partial merkle tree using a recursive depth-first
// approach.  As it calculates the hashes, it also saves whether or not each
// node is a parent node and a list of final hashes to be included in the
// merkle block.
func (m *merkleBlock) traverseAndBuild(height, pos uint32) {
	// Determine whether this node is a parent of a matched node.
	var isParent byte
	for i := pos << height; i < (pos+1)<<height && i < m.numTx; i++ {
		isParent |= m.matchedBits[i]
	}
	m.bits = append(m.bits, isParent)

	// When the node is a leaf node or not a parent of a matched node,
	// append the hash to the list that will be part of the final merkle
	// block.
	if height == 0 || isParent == 0x00 {
		m.finalHashes = append(m.finalHashes, m.calcHash(height, pos))
		return
	}

	// At this point, the node is an internal node and it is the parent of
	// of an included leaf node.

	// Descend into the left child and process its sub-tree.
	m.traverseAndBuild(height-1, pos*2)

	// Descend into the right child and process its sub-tree if
	// there is one.
	if pos*2+1 < m.calcTreeWidth(height-1) {
		m.traverseAndBuild(height-1, pos*2+1)
	}
}

type blockFilterer struct {
	filter         *Filter
	matchedIndices map[int]bool
}

type txWithIndex struct {
	tx    *bchutil.Tx
	index int
}

// checkFilterTx will check if the transaction is relevant and recursively loop through the
// inputs to double check transactions that are in the block but were already processed.
// This is necessary if the block is not sorted in topological order.
func (bf *blockFilterer) checkFilterTx(tx *bchutil.Tx, txIndex int, inputs map[chainhash.Hash][]*txWithIndex) {
	if bf.filter.MatchTxAndUpdate(tx) {
		bf.matchedIndices[txIndex] = true
		if dependentTxs, ok := inputs[tx.MsgTx().TxHash()]; ok {
			for _, dependentTx := range dependentTxs {
				bf.checkFilterTx(dependentTx.tx, dependentTx.index, inputs)
			}
		}
	}
}

// GetMatchedIndices returns the index of the transactions that match the filter.
// This works even with CTOR ordering.
func GetMatchedIndices(block *bchutil.Block, filter *Filter) map[int]bool {
	bf := blockFilterer{matchedIndices: make(map[int]bool), filter: filter}
	inputs := make(map[chainhash.Hash][]*txWithIndex)
	for txIndex, tx := range block.Transactions() {
		for _, in := range tx.MsgTx().TxIn {
			inputTxs := inputs[in.PreviousOutPoint.Hash]
			inputTxs = append(inputTxs, &txWithIndex{tx, txIndex})
			inputs[in.PreviousOutPoint.Hash] = inputTxs
		}

		bf.checkFilterTx(tx, txIndex, inputs)
	}
	return bf.matchedIndices
}

// NewMerkleBlock returns a new *wire.MsgMerkleBlock and an array of the matched
// transaction index numbers based on the passed block and filter.
func NewMerkleBlock(block *bchutil.Block, filter *Filter) (*wire.MsgMerkleBlock, []uint32) {
	numTx := uint32(len(block.Transactions()))
	mBlock := merkleBlock{
		numTx:       numTx,
		allHashes:   make([]*chainhash.Hash, 0, numTx),
		matchedBits: make([]byte, 0, numTx),
	}

	// Find and keep track of any transactions that match the filter.
	matchedMap := GetMatchedIndices(block, filter)

	var matchedIndices []uint32
	for txIndex, tx := range block.Transactions() {
		if matchedMap[txIndex] {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x01)
			matchedIndices = append(matchedIndices, uint32(txIndex))
		} else {
			mBlock.matchedBits = append(mBlock.matchedBits, 0x00)
		}
		mBlock.allHashes = append(mBlock.allHashes, tx.Hash())
	}

	// Calculate the number of merkle branches (height) in the tree.
	height := uint32(0)
	for mBlock.calcTreeWidth(height) > 1 {
		height++
	}

	// Build the depth-first partial merkle tree.
	mBlock.traverseAndBuild(height, 0)

	// Create and return the merkle block.
	msgMerkleBlock := wire.MsgMerkleBlock{
		Header:       block.MsgBlock().Header,
		Transactions: mBlock.numTx,
		Hashes:       make([]*chainhash.Hash, 0, len(mBlock.finalHashes)),
		Flags:        make([]byte, (len(mBlock.bits)+7)/8),
	}
	for _, hash := range mBlock.finalHashes {
		msgMerkleBlock.AddTxHash(hash)
	}
	for i := uint32(0); i < uint32(len(mBlock.bits)); i++ {
		msgMerkleBlock.Flags[i/8] |= mBlock.bits[i] << (i % 8)
	}
	return &msgMerkleBlock, matchedIndices
}
