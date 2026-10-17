// Copyright (c) 2013-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bloom_test

import (
	"bytes"
	"encoding/hex"
	"slices"
	"testing"
	"time"

	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil"
	"github.com/gcash/bchutil/bloom"
)

func TestMerkleBlock3(t *testing.T) {
	blockStr := "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b" +
		"4b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdc" +
		"c96b2c3ff60abe184f196367291b4d4c86041b8fa45d630101000000010" +
		"00000000000000000000000000000000000000000000000000000000000" +
		"0000ffffffff08044c86041b020a02ffffffff0100f2052a01000000434" +
		"104ecd3229b0571c3be876feaac0442a9f13c5a572742927af1dc623353" +
		"ecf8c202225f64868137a18cdd85cbbb4c74fbccfd4f49639cf1bdc94a5" +
		"672bb15ad5d4cac00000000"
	blockBytes, err := hex.DecodeString(blockStr)
	if err != nil {
		t.Errorf("TestMerkleBlock3 DecodeString failed: %v", err)
		return
	}
	blk, err := bchutil.NewBlockFromBytes(blockBytes)
	if err != nil {
		t.Errorf("TestMerkleBlock3 NewBlockFromBytes failed: %v", err)
		return
	}

	f := bloom.NewFilter(10, 0, 0.000001, wire.BloomUpdateAll)

	inputStr := "63194f18be0af63f2c6bc9dc0f777cbefed3d9415c4af83f3ee3a3d669c00cb5"
	hash, err := chainhash.NewHashFromStr(inputStr)
	if err != nil {
		t.Errorf("TestMerkleBlock3 NewHashFromStr failed: %v", err)
		return
	}

	f.AddHash(hash)

	mBlock, _ := bloom.NewMerkleBlock(blk, f)

	wantStr := "0100000079cda856b143d9db2c1caff01d1aecc8630d30625d10e8b4" +
		"b8b0000000000000b50cc069d6a3e33e3ff84a5c41d9d3febe7c770fdcc" +
		"96b2c3ff60abe184f196367291b4d4c86041b8fa45d630100000001b50c" +
		"c069d6a3e33e3ff84a5c41d9d3febe7c770fdcc96b2c3ff60abe184f196" +
		"30101"
	want, err := hex.DecodeString(wantStr)
	if err != nil {
		t.Errorf("TestMerkleBlock3 DecodeString failed: %v", err)
		return
	}

	got := bytes.NewBuffer(nil)
	err = mBlock.BchEncode(got, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		t.Errorf("TestMerkleBlock3 BchEncode failed: %v", err)
		return
	}

	if !bytes.Equal(want, got.Bytes()) {
		t.Errorf("TestMerkleBlock3 failed merkle block comparison: "+
			"got %v want %v", got.Bytes(), want)
		return
	}
}

func TestMerkleBlockOutOfOrder(t *testing.T) {
	blockStr := `0100000050120119172a610421a6c3011dd330d9df07b63616c2cc1f1cd00200000000006657a9252aacd5c0b2940996ecff952228c3067cc38d4885efb5a4ac4247e9f337221b4d4c86041b0f2b5710030100000001c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff010000008a4730440220032d30df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942ae90a3231e0ba333e02203deee8060fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81e26b4fe014104ae31c31bf91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0ba403ff96c9deeb680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420f00000000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d211000000001976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac000000000100000001c40297f730dd7b5a99567eb8d27b78758f607507c52292d02d4031895b52f2ff000000008a4730440220032d30df5ee6f57fa46cddb5eb8d0d9fe8de6b342d27942ae90a3231e0ba333e02203deee8060fdc70230a7f5b4ad7d7bc3e628cbe219a886b84269eaeb81e26b4fe014104ae31c31bf91278d99b8377a35bbce5b27d9fff15456839e919453fc7b3f721f0ba403ff96c9deeb680e5fd341c0fc3a7b90da4631ee39560639db462e9cb850fffffffff0240420f00000000001976a914b0dcbf97eabf4404e31d952477ce822dadbe7e1088acc060d211000000001976a9146b1281eec25ab4e1e0793ff4e08ab1abb3409cd988ac000000000100000001032e38e9c0a84c6046d687d10556dcacc41d275ec55fc00779ac88fdf357a187000000008c493046022100c352d3dd993a981beba4a63ad15c209275ca9470abfcd57da93b58e4eb5dce82022100840792bc1f456062819f15d33ee7055cf7b5ee1af1ebcc6028d9cdb1c3af7748014104f46db5e9d61a9dc27b8d64ad23e7383a4e6ca164593c2527c038c0857eb67ee8e825dca65046b82c9331586c82e0fd1f633f25f87c161bc6f8a630121df2b3d3ffffffff0200e32321000000001976a914c398efa9c392ba6013c5e04ee729755ef7f58b3288ac000fe208010000001976a914948c765a6914d43f2a7ac177da2c2f6b52de3d7c88ac00000000`
	blockBytes, err := hex.DecodeString(blockStr)
	if err != nil {
		t.Errorf("TestMerkleBlock3 DecodeString failed: %v", err)
		return
	}
	blk, err := bchutil.NewBlockFromBytes(blockBytes)
	if err != nil {
		t.Errorf("TestMerkleBlock3 NewBlockFromBytes failed: %v", err)
		return
	}

	f := bloom.NewFilter(10, 0, 0.000001, wire.BloomUpdateAll)

	addr, err := bchutil.DecodeAddress("qz2gcaj6dy2dg0e20tqh0k3v9a449h3a0s8t2kgggp", &chaincfg.SimNetParams)
	if err != nil {
		t.Fatal(err)
	}
	addr2, err := bchutil.DecodeAddress("qrpe3mafcwft5cqnchsyaeefw4000avtxg7jh5geku", &chaincfg.SimNetParams)
	if err != nil {
		t.Fatal(err)
	}

	f.Add(addr.ScriptAddress())
	f.Add(addr2.ScriptAddress())

	mBlock, _ := bloom.NewMerkleBlock(blk, f)
	if mBlock.Transactions != 3 {
		t.Fatalf("Returned incorrect number of transactions. Expected %d, got %d", 3, mBlock.Transactions)
	}
}

// TestMerkleBlockMatchingWorkBounded ensures matching a block costs work in
// proportion to its transactions.  The block has layers of two transactions
// that each spend both transactions of the next layer and push the filtered
// data, listed in reverse, so re-checking the spenders of every matched
// transaction would take time exponential in the number of layers.  It also
// ensures spenders listed before the transaction they spend still match.
func TestMerkleBlockMatchingWorkBounded(t *testing.T) {
	const layers = 40
	item := bytes.Repeat([]byte{0xab}, 20)
	pkScript := append([]byte{0x6a, 20}, item...)

	// Build the layers from the bottom up; layer 0 spends outside coins.
	var below [2]chainhash.Hash
	var txs []*wire.MsgTx
	for layer := range layers {
		var hashes [2]chainhash.Hash
		for j := range 2 {
			tx := wire.NewMsgTx(1)
			if layer == 0 {
				prev := chainhash.Hash{byte(j + 1)}
				tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&prev, 0), nil))
			} else {
				for k := range 2 {
					tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&below[k],
						uint32(j)), nil))
				}
			}
			tx.AddTxOut(wire.NewTxOut(1, pkScript, wire.TokenData{}))
			tx.AddTxOut(wire.NewTxOut(1, pkScript, wire.TokenData{}))
			hashes[j] = tx.TxHash()
			txs = append(txs, tx)
		}
		below = hashes
	}
	slices.Reverse(txs)
	block := bchutil.NewBlock(&wire.MsgBlock{Transactions: txs})

	done := make(chan []uint32, 1)
	go func() {
		f := bloom.NewFilter(10, 0, 0.0001, wire.BloomUpdateAll)
		f.Add(item)
		_, matched := bloom.NewMerkleBlock(block, f)
		done <- matched
	}()
	select {
	case matched := <-done:
		if len(matched) != len(txs) {
			t.Fatalf("matched %d of %d transactions", len(matched),
				len(txs))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("matching the block did not finish")
	}

	// A spender listed before the transaction it spends matches through
	// the output added for the later transaction.
	parent := wire.NewMsgTx(1)
	parent.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&chainhash.Hash{9}, 0), nil))
	parent.AddTxOut(wire.NewTxOut(1, pkScript, wire.TokenData{}))
	parentHash := parent.TxHash()
	child := wire.NewMsgTx(1)
	child.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&parentHash, 0), nil))
	child.AddTxOut(wire.NewTxOut(1, []byte{0x51}, wire.TokenData{}))
	block = bchutil.NewBlock(&wire.MsgBlock{
		Transactions: []*wire.MsgTx{child, parent}})
	f := bloom.NewFilter(10, 0, 0.0001, wire.BloomUpdateAll)
	f.Add(item)
	if _, matched := bloom.NewMerkleBlock(block, f); len(matched) != 2 {
		t.Fatalf("matched %v, want both transactions", matched)
	}
}
