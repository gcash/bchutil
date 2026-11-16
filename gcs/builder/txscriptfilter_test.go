// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs/builder"
)

// TestBuildTxScriptFilter builds the script filter of the test block's two
// transactions after the coinbase, as loose transactions, and checks that it
// is the filter of the keys their leaves have in the block, keyed by the hash
// given, with each key once.
func TestBuildTxScriptFilter(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	txs := block.Transactions[1:]
	hash := chainhash.Hash{0x42}

	filter, err := builder.BuildTxScriptFilter(&hash, txs, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}

	leaves, err := builder.ScriptLeaves(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	want := builder.WithKeyHash(&hash)
	keys := make(map[[32]byte]struct{})
	for _, leaf := range leaves {
		if leaf.TxIndex > 0 {
			want.AddEntry(leaf.Key[:])
			keys[leaf.Key] = struct{}{}
		}
	}
	wantFilter, err := want.Build()
	if err != nil {
		t.Fatal(err)
	}
	got, _ := filter.NBytes()
	wantBytes, _ := wantFilter.NBytes()
	if !bytes.Equal(got, wantBytes) {
		t.Fatalf("filter %x, want %x", got, wantBytes)
	}
	if filter.N() != uint32(len(keys)) {
		t.Errorf("filter has %d keys, want %d", filter.N(), len(keys))
	}

	key := builder.DeriveKey(&hash)
	for k := range keys {
		if match, err := filter.Match(key, k[:]); err != nil || !match {
			t.Errorf("key %x does not match: %v", k, err)
		}
	}
	other := builder.ScriptKey([]byte{0x51, 0x52})
	if match, _ := filter.Match(key, other[:]); match {
		t.Error("a script none of the transactions has matches")
	}

	// The scripts of the spent outputs must line up with the inputs.
	for _, scripts := range [][][]byte{prevOutScripts[:2], append(prevOutScripts, nil)} {
		if _, err := builder.BuildTxScriptFilter(&hash, txs, scripts); !errors.Is(err, builder.ErrPrevOutScripts) {
			t.Errorf("%d spent output scripts: %v", len(scripts), err)
		}
	}

	// Each transaction is in it by the key of its ID, and the filter is
	// the one worked out apart from this package.
	for i, tx := range txs {
		k := builder.TxidKey(tx.TxHash())
		if _, ok := keys[k]; !ok {
			t.Errorf("transaction %d: no leaf of its ID among the block's", i)
		}
	}
	const wantHex = "0617ae8a5598e5c0fb85a9d946a2c972d0"
	if hex.EncodeToString(got) != wantHex {
		t.Errorf("filter %x, want %s", got, wantHex)
	}

	// A transaction that pays only OP_RETURN and spends an empty script
	// gives a filter of its ID alone.
	burn := wire.NewMsgTx(2)
	burn.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{7}, 0), nil))
	burn.AddTxOut(wire.NewTxOut(0, []byte{0x6a}, wire.TokenData{}))
	onlyID, err := builder.BuildTxScriptFilter(&hash, []*wire.MsgTx{burn}, [][]byte{nil})
	if err != nil || onlyID.N() != 1 {
		t.Fatalf("filter of the ID alone: %v", err)
	}
	burnKey := builder.TxidKey(burn.TxHash())
	if match, err := onlyID.Match(key, burnKey[:]); err != nil || !match {
		t.Errorf("the ID of the transaction does not match: %v", err)
	}

	// No transactions give a filter without keys.
	empty, err := builder.BuildTxScriptFilter(&hash, nil, nil)
	if err != nil || empty.N() != 0 {
		t.Errorf("filter without keys: %v", err)
	}
}
