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

var (
	scriptA = append(append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{0x11}, 20)...), 0x88, 0xac)
	scriptB = append(append([]byte{0x76, 0xa9, 0x14}, bytes.Repeat([]byte{0x33}, 20)...), 0x88, 0xac)
	scriptD = append(append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0x44}, 20)...), 0x87)

	categoryC = [32]byte{
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	}
)

func fungible(category [32]byte, amount uint64) wire.TokenData {
	return wire.TokenData{CategoryID: category, Amount: amount, BitField: wire.HAS_AMOUNT}
}

// prefixed returns script with the token prefix of token in front, as the
// spend journal keeps a spent output's script.
func prefixed(token wire.TokenData, script []byte) []byte {
	buf := token.TokenDataBuffer()
	return append(buf.Bytes(), script...)
}

func spend(index uint32) *wire.TxIn {
	return wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{0x99}, index), nil)
}

// scriptFilterBlock is a coinbase paying script A, with an OP_RETURN output
// and an empty one; a transaction that spends a token coin locked by A and a
// coin locked by B, and pays tokens to D and coins to A; and a transaction
// that spends D and pays B. Its spent output scripts follow it.
func scriptFilterBlock() (*wire.MsgBlock, [][]byte) {
	coinbase := wire.NewMsgTx(1)
	coinbase.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{}, wire.MaxPrevOutIndex), []byte{0x51}))
	coinbase.AddTxOut(wire.NewTxOut(5000, scriptA, wire.TokenData{}))
	coinbase.AddTxOut(wire.NewTxOut(0, []byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef}, wire.TokenData{}))
	coinbase.AddTxOut(wire.NewTxOut(0, nil, wire.TokenData{}))

	tokens := wire.NewMsgTx(2)
	tokens.AddTxIn(spend(0))
	tokens.AddTxIn(spend(1))
	tokens.AddTxOut(wire.NewTxOut(1000, scriptD, fungible(categoryC, 40)))
	tokens.AddTxOut(wire.NewTxOut(2000, scriptA, wire.TokenData{}))

	last := wire.NewMsgTx(2)
	last.AddTxIn(spend(2))
	last.AddTxOut(wire.NewTxOut(900, scriptB, wire.TokenData{}))

	block := wire.NewMsgBlock(&wire.BlockHeader{Version: 4, Timestamp: TestBlock.Header.Timestamp})
	block.AddTransaction(coinbase)
	block.AddTransaction(tokens)
	block.AddTransaction(last)

	prevOutScripts := [][]byte{
		prefixed(fungible(categoryC, 100), scriptA),
		scriptB,
		prefixed(fungible(categoryC, 40), scriptD),
	}
	return block, prevOutScripts
}

// The leaves and roots below come from an independent implementation of the
// script filter written from its specification (gcash/bchd#767).
var scriptFilterLeaves = []string{
	"11633077d74aa1a6958c6f1162c9e935c628c6b004d167165f0a4cccd020eecb010000000000000000",
	"11633077d74aa1a6958c6f1162c9e935c628c6b004d167165f0a4cccd020eecb020000000000000001",
	"46402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e010000000100000001",
	"46402f61b3239cd80b93294e10b552d66a31b79c8fe7fdd92a832d00f832e82e020000000000000000",
	"5c1b924542fecd099a9568826bce5018476b3c2a29944c9c7ff6e47f80d21d24010000000000000002",
	"5c1b924542fecd099a9568826bce5018476b3c2a29944c9c7ff6e47f80d21d24010000000000000003",
	"5c1b924542fecd099a9568826bce5018476b3c2a29944c9c7ff6e47f80d21d24020000000000000003",
	"e2f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e000000000000000000",
	"e2f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e010000000000000001",
	"e2f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e010000000100000000",
}

func TestScriptLeaves(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	leaves, err := builder.ScriptLeaves(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	if len(leaves) != len(scriptFilterLeaves) {
		t.Fatalf("got %d leaves, want %d", len(leaves), len(scriptFilterLeaves))
	}
	for i := range leaves {
		got := leaves[i].Bytes()
		if hex.EncodeToString(got[:]) != scriptFilterLeaves[i] {
			t.Errorf("leaf %d: got %x, want %s", i, got, scriptFilterLeaves[i])
		}
	}

	// The key of a script is its Electrum script hash, and the token prefix
	// of a spent coin is not part of it.
	keyA := builder.ScriptKey(scriptA)
	if hex.EncodeToString(keyA[:]) != "e2f6c234985456932db846b2bf1a2fed2cb98b5b0f246f30711ea6148a76860e" {
		t.Fatalf("key of A: %x", keyA)
	}
	keyC := builder.CategoryKey(categoryC)
	if hex.EncodeToString(keyC[:]) != "5c1b924542fecd099a9568826bce5018476b3c2a29944c9c7ff6e47f80d21d24" {
		t.Fatalf("key of category C: %x", keyC)
	}
}

func TestScriptLeavesRoot(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	leaves, err := builder.ScriptLeaves(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	// Odd counts check that a node without a partner moves up unchanged.
	tests := []struct {
		n    int
		root string
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000"},
		{1, "9d1f540224023621706bc5c9a4cb19c21abb295d62aebaa75137bbcb44dadfb5"},
		{2, "e5c9cff033bb91a3f42a868728b860c8a4eb1e6047d483b7b3a066f694f2180e"},
		{3, "bbf4f9772400cd1355cfd4c39fb37e5f03a63e2452b1ca97deba45d475771dc2"},
		{5, "378bce73f320bd2b71796e5731f6e91d71e42ecf0513d1912f0e9439fb52a2b9"},
		{10, "f66125233da123c29e93f9510c96557d5edfc071225ea7796c86e6deba8c23fd"},
	}
	for _, test := range tests {
		root := builder.ScriptLeavesRoot(leaves[:test.n])
		// The leaves are hashed in the order they are serialized, so the
		// root is compared as raw bytes rather than as a displayed hash.
		if hex.EncodeToString(root[:]) != test.root {
			t.Errorf("root of %d leaves: got %x, want %s", test.n, root[:], test.root)
		}
	}
}

func TestBuildScriptFilterMatches(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	filter, root, err := builder.BuildScriptFilter(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	leaves, _ := builder.ScriptLeaves(block, prevOutScripts)
	if root != builder.ScriptLeavesRoot(leaves) {
		t.Fatalf("root %v is not the root of the block's leaves", root)
	}

	// A, B, D and the category, each once.
	if filter.N() != 4 {
		t.Fatalf("filter has %d entries, want 4", filter.N())
	}

	blockHash := block.BlockHash()
	key := builder.DeriveKey(&blockHash)
	keyB := builder.ScriptKey(scriptB)
	keyC := builder.CategoryKey(categoryC)
	keyD := builder.ScriptKey(scriptD)
	keyA := builder.ScriptKey(scriptA)
	for _, item := range [][32]byte{keyA, keyB, keyC, keyD} {
		match, err := filter.Match(key, item[:])
		if err != nil {
			t.Fatal(err)
		}
		if !match {
			t.Errorf("filter does not match %x", item)
		}
	}

	// Neither the OP_RETURN output nor the empty one is in it, and nothing
	// about the spent outpoints is: a wallet watches its scripts only.
	opReturn := builder.ScriptKey([]byte{0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef})
	empty := builder.ScriptKey(nil)
	var outpoint bytes.Buffer
	if err := block.Transactions[1].TxIn[0].PreviousOutPoint.Serialize(&outpoint); err != nil {
		t.Fatal(err)
	}
	for _, item := range [][]byte{opReturn[:], empty[:], outpoint.Bytes(), scriptA} {
		match, err := filter.Match(key, item)
		if err != nil {
			t.Fatal(err)
		}
		if match {
			t.Errorf("filter matches %x", item)
		}
	}
}

// A coin is found where it is spent by the script that received it, so a
// block that only spends a wallet's coin still matches the wallet.
func TestBuildScriptFilterSpendOnly(t *testing.T) {
	block, _ := scriptFilterBlock()
	spender := wire.NewMsgTx(2)
	spender.AddTxIn(spend(7))
	spender.AddTxOut(wire.NewTxOut(100, scriptB, wire.TokenData{}))
	only := wire.NewMsgBlock(&block.Header)
	only.AddTransaction(block.Transactions[0])
	only.AddTransaction(spender)

	wallet := append([]byte{0xa9, 0x14}, bytes.Repeat([]byte{0x77}, 20)...)
	wallet = append(wallet, 0x87)
	filter, _, err := builder.BuildScriptFilter(only, [][]byte{wallet})
	if err != nil {
		t.Fatal(err)
	}
	blockHash := only.BlockHash()
	walletKey := builder.ScriptKey(wallet)
	match, err := filter.Match(builder.DeriveKey(&blockHash), walletKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("a block spending the wallet's coin does not match the wallet's script")
	}
}

func TestScriptLeavesPrevOutScripts(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	for _, scripts := range [][][]byte{prevOutScripts[:2], append(prevOutScripts, scriptA), nil} {
		if _, err := builder.ScriptLeaves(block, scripts); !errors.Is(err, builder.ErrPrevOutScripts) {
			t.Errorf("%d spent scripts for 3 inputs: got %v", len(scripts), err)
		}
		if _, _, err := builder.BuildScriptFilter(block, scripts); !errors.Is(err, builder.ErrPrevOutScripts) {
			t.Errorf("%d spent scripts for 3 inputs: filter got %v", len(scripts), err)
		}
	}
}

// The served bytes, their hash and the headers come from the same
// independent implementation.
func TestMakeHeaderForScriptFilter(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	filter, root, err := builder.BuildScriptFilter(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	filterBytes, err := filter.NBytes()
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(filterBytes) != "0499ff80bec18387496fab00" {
		t.Fatalf("filter %x", filterBytes)
	}

	// Served: the root, then the filter.
	served, err := builder.ScriptFilterBytes(filter, root)
	if err != nil {
		t.Fatal(err)
	}
	const wantServed = "f66125233da123c29e93f9510c96557d5edfc071225ea7796c86e6deba8c23fd" +
		"0499ff80bec18387496fab00"
	if hex.EncodeToString(served) != wantServed {
		t.Fatalf("served %x", served)
	}
	filterHash, err := builder.GetScriptFilterHash(filter, root)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(filterHash[:]) != "4ddf591081b2cf7e4ed907dd61b4626d45aa34a1d6c34ef3d475e97b4fc1745f" {
		t.Fatalf("filter hash %x", filterHash[:])
	}

	var counting chainhash.Hash
	for i := range counting {
		counting[i] = byte(i)
	}
	tests := []struct {
		prev   chainhash.Hash
		header string
	}{
		{chainhash.Hash{}, "a92dc54cdf66fdf505a4c7acdb432becbc5f2756fb3ba0bc0fa74694888f6829"},
		{counting, "1a234486b2eec2c3c45e871a2ccb3f12ad9e8a0755fc1a42e6dffbebd5f09f26"},
	}
	for _, test := range tests {
		header, err := builder.MakeHeaderForScriptFilter(filter, root, test.prev)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(header[:]) != test.header {
			t.Errorf("header after %x: got %x, want %s", test.prev[:], header[:], test.header)
		}
	}

	// The root is part of the header: the same filter under another root
	// gives another header.
	other, err := builder.MakeHeaderForScriptFilter(filter, chainhash.Hash{}, chainhash.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(other[:]) == tests[0].header {
		t.Fatal("the header does not depend on the root")
	}
}

// A client splits the served bytes back into the filter it matches with and
// the root it checks proofs against.
func TestParseScriptFilter(t *testing.T) {
	block, prevOutScripts := scriptFilterBlock()
	filter, root, err := builder.BuildScriptFilter(block, prevOutScripts)
	if err != nil {
		t.Fatal(err)
	}
	served, err := builder.ScriptFilterBytes(filter, root)
	if err != nil {
		t.Fatal(err)
	}
	parsed, parsedRoot, err := builder.ParseScriptFilter(served)
	if err != nil {
		t.Fatal(err)
	}
	if parsedRoot != root {
		t.Fatalf("root %v, want %v", parsedRoot, root)
	}
	blockHash := block.BlockHash()
	keyA := builder.ScriptKey(scriptA)
	match, err := parsed.Match(builder.DeriveKey(&blockHash), keyA[:])
	if err != nil {
		t.Fatal(err)
	}
	if !match || parsed.N() != filter.N() {
		t.Fatalf("parsed filter: match %v, N %d, want true and %d", match, parsed.N(), filter.N())
	}

	for _, short := range [][]byte{nil, served[:31]} {
		if _, _, err := builder.ParseScriptFilter(short); !errors.Is(err, builder.ErrScriptFilterTooShort) {
			t.Errorf("%d bytes: got %v", len(short), err)
		}
	}
}
