// Copyright (c) 2026 The gcash developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom_test

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/gcash/bchd/blockchain"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/txscript"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/bloom"
)

// degenerateTx returns a transaction that spends the given outpoint and has a
// single output whose public key script pushes the passed data.
func degenerateTx(prevHash chainhash.Hash, pushData []byte) *wire.MsgTx {
	pkScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).
		AddData(pushData).Script()
	if err != nil {
		panic(err)
	}
	tx := wire.NewMsgTx(1)
	tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prevHash, 0), nil))
	tx.AddTxOut(wire.NewTxOut(0, pkScript, wire.TokenData{}))
	return tx
}

// decodeFilterLoad decodes a filterload message with the given fields from its
// wire encoding, so the tests use a filter exactly as a peer could send it.
func decodeFilterLoad(t *testing.T, data []byte, hashFuncs uint32,
	flags wire.BloomUpdateType) *wire.MsgFilterLoad {

	t.Helper()

	var buf bytes.Buffer
	orig := wire.NewMsgFilterLoad(data, hashFuncs, 0, flags)
	if err := orig.BchEncode(&buf, wire.ProtocolVersion, wire.BaseEncoding); err != nil {
		t.Fatalf("BchEncode: %v", err)
	}
	var msg wire.MsgFilterLoad
	if err := msg.BchDecode(&buf, wire.ProtocolVersion, wire.BaseEncoding); err != nil {
		t.Fatalf("BchDecode: %v", err)
	}
	return &msg
}

// runNoPanic runs the passed function and reports a test error instead of
// crashing the test binary when it panics.
func runNoPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("%s: unexpected panic: %v", name, r)
		}
	}()
	f()
}

// TestFilterEmptyData ensures a filter with an empty data array, which can be
// loaded with a filterload message, matches everything and ignores additions
// instead of panicking.  This mirrors the reference implementation, which
// treats a zero-size filter as a match-all filter.
func TestFilterEmptyData(t *testing.T) {
	tx := bchutil.NewTx(degenerateTx(chainhash.Hash{0x01}, []byte{0xaa}))
	outpoint := wire.NewOutPoint(&chainhash.Hash{0x02}, 1)

	tests := []struct {
		name string
		fn   func(t *testing.T, f *bloom.Filter)
	}{{
		name: "Matches",
		fn: func(t *testing.T, f *bloom.Filter) {
			if !f.Matches([]byte{1, 2, 3}) {
				t.Error("Matches: want true for an empty filter")
			}
		},
	}, {
		name: "MatchesOutPoint",
		fn: func(t *testing.T, f *bloom.Filter) {
			if !f.MatchesOutPoint(outpoint) {
				t.Error("MatchesOutPoint: want true for an empty filter")
			}
		},
	}, {
		name: "Add",
		fn: func(t *testing.T, f *bloom.Filter) {
			f.Add([]byte{1, 2, 3})
			f.AddHash(&chainhash.Hash{0x03})
			f.AddOutPoint(outpoint)
		},
	}, {
		name: "MatchTxAndUpdate",
		fn: func(t *testing.T, f *bloom.Filter) {
			if !f.MatchTxAndUpdate(tx) {
				t.Error("MatchTxAndUpdate: want true for an empty filter")
			}
		},
	}}

	for _, flags := range []wire.BloomUpdateType{wire.BloomUpdateNone,
		wire.BloomUpdateAll, wire.BloomUpdateP2PubkeyOnly} {

		for _, test := range tests {
			// Use a new filter for each case and inspect the message
			// directly afterwards, so a case that fails while holding
			// the filter lock cannot block the others.
			msg := decodeFilterLoad(t, nil, wire.MaxFilterLoadHashFuncs,
				flags)
			f := bloom.LoadFilter(msg)
			runNoPanic(t, fmt.Sprintf("%s (flags %d)", test.name, flags),
				func() { test.fn(t, f) })
			if n := len(msg.Filter); n != 0 {
				t.Errorf("%s (flags %d): filter grew to %d bytes",
					test.name, flags, n)
			}
		}
	}
}

// TestFilterZeroHashFuncs ensures a filter with a non-empty data array and no
// hash functions matches everything and leaves its data unchanged on
// additions, as in the reference implementation.
func TestFilterZeroHashFuncs(t *testing.T) {
	msg := decodeFilterLoad(t, make([]byte, 8), 0, wire.BloomUpdateAll)
	f := bloom.LoadFilter(msg)

	runNoPanic(t, "zero hash functions", func() {
		f.Add([]byte{1, 2, 3})
		f.AddOutPoint(wire.NewOutPoint(&chainhash.Hash{0x04}, 0))
		if !f.Matches([]byte{4, 5, 6}) {
			t.Error("Matches: want true with no hash functions")
		}
		tx := bchutil.NewTx(degenerateTx(chainhash.Hash{0x05}, []byte{0xbb}))
		if !f.MatchTxAndUpdate(tx) {
			t.Error("MatchTxAndUpdate: want true with no hash functions")
		}
	})
	if !bytes.Equal(msg.Filter, make([]byte, 8)) {
		t.Errorf("filter data changed: %x", msg.Filter)
	}
}

// TestMerkleBlockEmptyFilter ensures a merkle block built with a filter that
// has an empty data array includes every transaction in the block.
func TestMerkleBlockEmptyFilter(t *testing.T) {
	var txs []*wire.MsgTx
	for i := byte(0); i < 5; i++ {
		txs = append(txs, degenerateTx(chainhash.Hash{0x10 + i}, []byte{i}))
	}
	btxs := make([]*bchutil.Tx, 0, len(txs))
	for _, tx := range txs {
		btxs = append(btxs, bchutil.NewTx(tx))
	}
	store := blockchain.BuildMerkleTreeStore(btxs)
	block := bchutil.NewBlock(&wire.MsgBlock{
		Header:       wire.BlockHeader{MerkleRoot: *store[len(store)-1]},
		Transactions: txs,
	})

	f := bloom.LoadFilter(decodeFilterLoad(t, nil, 10, wire.BloomUpdateAll))
	runNoPanic(t, "NewMerkleBlock", func() {
		mBlock, matched := bloom.NewMerkleBlock(block, f)
		if len(matched) != len(txs) {
			t.Fatalf("matched %d transactions, want %d", len(matched),
				len(txs))
		}
		for i, idx := range matched {
			if idx != uint32(i) {
				t.Errorf("matched index %d is %d", i, idx)
			}
		}
		if len(mBlock.Hashes) != len(txs) {
			t.Errorf("merkle block has %d hashes, want %d",
				len(mBlock.Hashes), len(txs))
		}
	})
}

// TestFilterUnlocksAfterPanic ensures the filter lock is released when an
// operation panics, so later calls on the same filter do not block.
func TestFilterUnlocksAfterPanic(t *testing.T) {
	f := bloom.NewFilter(10, 0, 0.0001, wire.BloomUpdateAll)

	// A nil transaction panics while the lock is held.
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MatchTxAndUpdate(nil) did not panic")
			}
		}()
		f.MatchTxAndUpdate(nil)
	}()

	done := make(chan struct{})
	go func() {
		f.IsLoaded()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("filter lock still held after a panic")
	}
}
