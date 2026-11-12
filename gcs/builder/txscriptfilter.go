// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs"
)

// BuildTxScriptFilter builds the script filter of loose transactions, such as
// those a node admits to its mempool in a short interval: a GCS filter over
// the keys they would have in a block's script filter, keyed by hash, with the
// same P, M and serialization. A wallet matches it with its own scripts and
// token categories, as it matches a block's, and fetches the transactions
// only when it matches.
//
// prevOutScripts holds the scripts of the outputs the transactions spend,
// with any token prefix in front, in order of the transactions and of their
// inputs. No transaction is taken for a coinbase. Mempool transactions have no
// entry tree to prove anything against, so no root is built.
func BuildTxScriptFilter(hash *chainhash.Hash, txs []*wire.MsgTx, prevOutScripts [][]byte) (*gcs.Filter, error) {
	var leaves []ScriptLeaf
	spent := 0
	for i, tx := range txs {
		var err error
		leaves, spent, err = appendScriptLeaves(leaves, tx, uint32(i), false,
			prevOutScripts, spent)
		if err != nil {
			return nil, err
		}
	}
	if spent != len(prevOutScripts) {
		return nil, ErrPrevOutScripts
	}

	b := WithKeyHash(hash)
	if _, err := b.Key(); err != nil {
		return nil, err
	}
	for i := range leaves {
		// The builder keeps each distinct key once.
		b.AddEntry(leaves[i].Key[:])
	}
	return b.Build()
}
