// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder_test

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
	"github.com/gcash/bchutil/gcs/builder"
)

// The vectors below were made with a reference written from the filter's
// specification alone (BitcoinCash1/knuth-bch-startos,
// scripts/rpa_filter_vectors.py), which knuth checks its implementation
// against too. Each block's header chains from the one before, the first
// from 32 zero bytes.
var rpaFilterBlocks = []struct {
	name        string
	block       string
	values      []uint16
	inputValues [][]uint16
	k           uint8
	filter      string
	filterHash  string
	header      string
}{
	{
		name: "empty",
		block: "0000002000000000000000000000000000000000000000000000000000000000000000009d6475cc74d5e2c36a9c5fa5" +
			"64b25676a0442a86eff51081bd077a9fc0919d2b00f15365ffff7f200000000001010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010003727061ffffffff0100f2052a010000000151" +
			"00000000",
		values:      []uint16{},
		inputValues: [][]uint16{},
		k:           0,
		filter:      "00",
		filterHash:  "1406e05881e299367766d313e26c05564ec91bf721d31726bd6e46e60689539a",
		header:      "a80ba8d54948ed417954508791bcf9321bcda26c160b77ab695258281c0d3e75",
	},
	{
		name: "one input",
		block: "00000020679d3aae7bad61757b5e1e3e225764d3a90a72d6f383e104953f82f36c7d5235382edb97970c0e4c882a3736" +
			"d227780325ae84c0fdf065b1402c61a949e6ced658f35365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010103727061ffffffff0100f2052a010000000151" +
			"0000000002000000011111111111111111111111111111111111111111111111111111111111111111000000000151ff" +
			"ffffff01e803000000000000015100000000",
		values:      []uint16{0x9408},
		inputValues: [][]uint16{{0x9408}},
		k:           15,
		filter:      "010f8a0400",
		filterHash:  "e1452af78ceb4f079714cb094c3f5c69bbb1a0d38bb90fd4fc63365649474fce",
		header:      "1c0123a83da1787bd17ee2b07312e3a2769ab6d6fd2963b97fcd28e595b75c6f",
	},
	{
		name: "two inputs sharing a prefix",
		block: "000000208c3745485793913b4370e90cfc2edba60842edfc107f116fa447338bf101f23ab67e94cdd0d6a920578271a0" +
			"c13997f863e77ae4346962950e36c392dfdc1f56b0f55365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010203727061ffffffff0100f2052a010000000151" +
			"0000000002000000022222222222222222222222222222222222222222222222222222222222222222000000000151ff" +
			"ffffff222222222222222222222222222222222222222222222222222222222222222201000000015186ed000001e803" +
			"000000000000015100000000",
		values:      []uint16{0xc3ed},
		inputValues: [][]uint16{{0xc3ed, 0xc3ed}},
		k:           15,
		filter:      "010fa1f680",
		filterHash:  "f423f13e1b97819945f324ed136d136f15a71656b4ae0fd031ff6e287257879c",
		header:      "8f18899a3f80fdbf3ca6f15203b5c016fb0577cf5853ee912d4c88e6685192ca",
	},
	{
		name: "several transactions",
		block: "00000020747869088322e048c5f4dd87ec0a1b1eef99b91b78d8c06b2291e41bad869a2c48e727a0229de260837dba40" +
			"8a3a308097fce37f6b7950954f250f60aa61d74708f85365ffff7f200000000003010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010303727061ffffffff0100f2052a010000000151" +
			"00000000020000000233333333333333333333333333333333333333333333333333333333333333330000000000ffff" +
			"ffff33333333333333333333333333333333333333333333333333333333333333330100000000ffffffff01e8030000" +
			"000000000151000000000200000003444444444444444444444444444444444444444444444444444444444444444400" +
			"00000015140000000000000000000000000000000000000000feffffff44444444444444444444444444444444444444" +
			"444444444444444444444444440100000015140101010101010101010101010101010101010101fdffffff4444444444" +
			"444444444444444444444444444444444444444444444444444444020000001514020202020202020202020202020202" +
			"0202020202fcffffff01e803000000000000015100000000",
		values:      []uint16{0x0c06, 0x231f, 0x5e33, 0xa8e6, 0xc535},
		inputValues: [][]uint16{{0xc535, 0xa8e6}, {0x5e33, 0x0c06, 0x231f}},
		k:           13,
		filter:      "050d3019719b6299566e2780",
		filterHash:  "eea30a94c8acfa84935aa0a4a2a442a3e709ae60b21ed77e108831a5a9d1565d",
		header:      "6e50997c60f71d3ceb2905e2ed7cec28d294c0c51b645e5508356b42f67b3a3b",
	},
	{
		name: "31 inputs",
		block: "00000020ceac327bc87e749b35938b61e9e0d5b82c37ceaf1c22545e16ad35ee047a5026fa0e9a584e95dcc70d048c79" +
			"8bc45f3c4f25c88bb3b03db97deafda47640d88d60fa5365ffff7f200000000002010000000100000000000000000000" +
			"00000000000000000000000000000000000000000000ffffffff06010403727061ffffffff0100f2052a010000000151" +
			"00000000020000001f55555555555555555555555555555555555555555555555555555555555555550000000000ffff" +
			"ffff55555555555555555555555555555555555555555555555555555555555555550100000000ffffffff5555555555" +
			"5555555555555555555555555555555555555555555555555555550200000000ffffffff555555555555555555555555" +
			"55555555555555555555555555555555555555550300000000ffffffff55555555555555555555555555555555555555" +
			"555555555555555555555555550400000000ffffffff5555555555555555555555555555555555555555555555555555" +
			"5555555555550500000000ffffffff555555555555555555555555555555555555555555555555555555555555555506" +
			"00000000ffffffff55555555555555555555555555555555555555555555555555555555555555550700000000ffffff" +
			"ff55555555555555555555555555555555555555555555555555555555555555550800000000ffffffff555555555555" +
			"55555555555555555555555555555555555555555555555555550900000000ffffffff55555555555555555555555555" +
			"555555555555555555555555555555555555550a00000000ffffffff5555555555555555555555555555555555555555" +
			"5555555555555555555555550b00000000ffffffff555555555555555555555555555555555555555555555555555555" +
			"55555555550c00000000ffffffff55555555555555555555555555555555555555555555555555555555555555550d00" +
			"000000ffffffff55555555555555555555555555555555555555555555555555555555555555550e00000000ffffffff" +
			"55555555555555555555555555555555555555555555555555555555555555550f00000000ffffffff55555555555555" +
			"555555555555555555555555555555555555555555555555551000000000ffffffff5555555555555555555555555555" +
			"5555555555555555555555555555555555551100000000ffffffff555555555555555555555555555555555555555555" +
			"55555555555555555555551200000000ffffffff55555555555555555555555555555555555555555555555555555555" +
			"555555551300000000ffffffff5555555555555555555555555555555555555555555555555555555555555555140000" +
			"0000ffffffff55555555555555555555555555555555555555555555555555555555555555551500000000ffffffff55" +
			"555555555555555555555555555555555555555555555555555555555555551600000000ffffffff5555555555555555" +
			"5555555555555555555555555555555555555555555555551700000000ffffffff555555555555555555555555555555" +
			"55555555555555555555555555555555551800000000ffffffff55555555555555555555555555555555555555555555" +
			"555555555555555555551900000000ffffffff5555555555555555555555555555555555555555555555555555555555" +
			"5555551a00000000ffffffff55555555555555555555555555555555555555555555555555555555555555551b000000" +
			"00ffffffff55555555555555555555555555555555555555555555555555555555555555551c00000000ffffffff5555" +
			"5555555555555555555555555555555555555555555555555555555555551d00000000ffffffff555555555555555555" +
			"55555555555555555555555555555555555555555555551e00000000ffffffff01e803000000000000015100000000",
		values:      []uint16{0x02ed, 0x1013, 0x171b, 0x1874, 0x1d3c, 0x3542, 0x4d39, 0x51de, 0x54bf, 0x5c3e, 0x6ce7, 0x7e8e, 0x81ef, 0x8ffe, 0x9376, 0x96aa, 0x9798, 0x9885, 0xaf16, 0xb033, 0xb08d, 0xb75a, 0xc3ac, 0xd207, 0xd2fd, 0xde98, 0xe39d, 0xebfa, 0xed4c, 0xfc15},
		inputValues: [][]uint16{{0xd2fd, 0x51de, 0xebfa, 0x9376, 0x54bf, 0x96aa, 0xaf16, 0x4d39, 0xb033, 0x8ffe, 0x9885, 0x81ef, 0x1d3c, 0xb75a, 0x171b, 0xb08d, 0x1013, 0x1874, 0xe39d, 0xfc15, 0xed4c, 0x3542, 0x7e8e, 0x02ed, 0x6ce7, 0xc3ac, 0xde98, 0x5c3e, 0x9798, 0xd207, 0xa938}},
		k:           10,
		filter: "1e0a5dbc935841598c8fc037dfbc52ae1b7ff153e69db0f41ede19a0ee1dbf5224742d566f0a5d2d8f6dcdc82e174a97" +
			"5920",
		filterHash: "5773e5c29f136644b9f88d2d3df1cd527d9ed5a68a6773d25b113dc50930f8c0",
		header:     "4b595d03261b964c360e1d9f39a670ada0dd94c5a6298ef947334b7026792489",
	},
}

func rpaHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRPAFilterBlocks builds each vector block's filter from the block, and
// checks its values, the values of each transaction's inputs, the Rice
// parameter, the bytes, their hash and the header chain, and that the bytes
// decode back to the values.
func TestRPAFilterBlocks(t *testing.T) {
	var prev chainhash.Hash
	for _, test := range rpaFilterBlocks {
		var block wire.MsgBlock
		if err := block.Deserialize(bytes.NewReader(rpaHex(t, test.block))); err != nil {
			t.Fatalf("%s: %v", test.name, err)
		}
		values := builder.RPABlockValues(&block)
		if !slices.Equal(values, test.values) {
			t.Errorf("%s: values %04x, want %04x", test.name, values, test.values)
		}
		for i, want := range test.inputValues {
			tx := block.Transactions[i+1]
			if len(tx.TxIn) != len(want) {
				t.Fatalf("%s: transaction %d has %d inputs, want %d", test.name, i+1, len(tx.TxIn), len(want))
			}
			for j, txIn := range tx.TxIn {
				if v := builder.RPAInputValue(txIn); v != want[j] {
					t.Errorf("%s: transaction %d input %d: value %04x, want %04x", test.name, i+1, j, v, want[j])
				}
			}
		}
		if len(test.values) > 0 {
			if k := builder.RPAFilterK(len(test.values)); k != test.k {
				t.Errorf("%s: k %d, want %d", test.name, k, test.k)
			}
		}

		filter := builder.BuildRPAFilter(&block)
		if hex.EncodeToString(filter) != test.filter {
			t.Errorf("%s: filter %x, want %s", test.name, filter, test.filter)
		}
		hash := builder.GetRPAFilterHash(filter)
		if hex.EncodeToString(hash[:]) != test.filterHash {
			t.Errorf("%s: filter hash %x, want %s", test.name, hash[:], test.filterHash)
		}
		header := builder.MakeHeaderForRPAFilter(filter, prev)
		if hex.EncodeToString(header[:]) != test.header {
			t.Errorf("%s: header %x, want %s", test.name, header[:], test.header)
		}
		prev = header

		decoded, err := builder.DecodeRPAFilter(filter)
		if err != nil || !slices.Equal(decoded, test.values) {
			t.Errorf("%s: decoded %04x, %v", test.name, decoded, err)
		}
		if !builder.RPAFilterCanonical(filter, decoded) {
			t.Errorf("%s: the filter a block gives is not canonical", test.name)
		}
	}

	// Only the first 30 inputs of a transaction count: the 31st input's
	// value is not among the first 30's, and is not in the filter.
	last := rpaFilterBlocks[len(rpaFilterBlocks)-1]
	inputs := last.inputValues[0]
	if len(inputs) != 31 || slices.Contains(inputs[:30], inputs[30]) ||
		slices.Contains(last.values, inputs[30]) {
		t.Errorf("the 31st input's value %04x is in the filter", inputs[30])
	}
}

// TestRPAFilterLarge builds the filter of 1,000 transactions of 30 inputs
// each: transaction j spends outpoints whose txid is j as four little-endian
// bytes and 28 zero bytes, indexes 0 to 29, with empty scripts and sequence
// 0xffffffff. There are enough values for k = 0.
func TestRPAFilterLarge(t *testing.T) {
	txs := make([]*wire.MsgTx, 0, 1000)
	for j := uint32(1); j <= 1000; j++ {
		var txid chainhash.Hash
		binary.LittleEndian.PutUint32(txid[:4], j)
		tx := wire.NewMsgTx(2)
		for i := uint32(0); i < 30; i++ {
			tx.AddTxIn(wire.NewTxIn(wire.NewOutPoint(&txid, i), nil))
		}
		txs = append(txs, tx)
	}
	values := builder.RPAValues(txs)
	if len(values) != 24051 || builder.RPAFilterK(len(values)) != 0 {
		t.Fatalf("%d values, k %d, want 24051 and 0", len(values), builder.RPAFilterK(len(values)))
	}
	if !slices.Equal(values[:4], []uint16{0x0001, 0x0002, 0x000e, 0x000f}) ||
		!slices.Equal(values[len(values)-4:], []uint16{0xfff9, 0xfffa, 0xfffc, 0xfffd}) {
		t.Errorf("first values %04x, last %04x", values[:4], values[len(values)-4:])
	}
	filter := builder.EncodeRPAFilter(values)
	hash := builder.GetRPAFilterHash(filter)
	if len(filter) != 11202 || hex.EncodeToString(filter[:16]) != "fdf35d00afff55d56d7fead57d56bdeb" ||
		hex.EncodeToString(filter[len(filter)-8:]) != "6aeddf5b7bd7dd5a" ||
		hex.EncodeToString(hash[:]) != "7ee4807b0bfc1fc3837492fabe13527d34e16489bb69f66c7fa54d04a1165746" {

		t.Errorf("filter of %d bytes, %x..%x, hash %x", len(filter), filter[:16], filter[len(filter)-8:], hash[:])
	}
	decoded, err := builder.DecodeRPAFilter(filter)
	if err != nil || !slices.Equal(decoded, values) {
		t.Errorf("decoded %d values, %v", len(decoded), err)
	}
}

// TestRPAFilterAccepted decodes encodings the decoder takes: single values
// at both ends, two values, every even value, every value, and one whose
// Rice parameter is not the one its count gives, which decodes but is not
// canonical and has another hash.
func TestRPAFilterAccepted(t *testing.T) {
	even := make([]uint16, 0, 32768)
	every := make([]uint16, 0, 65536)
	for v := 0; v < 65536; v++ {
		if v%2 == 0 {
			even = append(even, uint16(v))
		}
		every = append(every, uint16(v))
	}
	tests := []struct {
		name      string
		values    []uint16
		data      []byte
		canonical bool
		hash      string
	}{
		{"value 0", []uint16{0}, rpaHex(t, "010f0000"), true,
			"d765bddba686b5d7a4eee92e6da5c4cf23f3fb5d272b71b478d5e7b29beef01b"},
		{"value 65535", []uint16{65535}, rpaHex(t, "010fbfff80"), true,
			"f604888baa2af992bba2f2511bc214e31c272608c23092cb8bc63e0d0630122b"},
		{"two values", []uint16{1, 2}, rpaHex(t, "020e00020004"), true,
			"fc45657f3a482e5872d033a5c86387e5801c723c4c11caed079b92810a61b447"},
		{"even values, k = 0", even, builder.EncodeRPAFilter(even), true,
			"61071102674b83e66e64057ced5188a431ca43ab0809e21805a1d618ecfee3b5"},
		{"every value", every, builder.EncodeRPAFilter(every), true,
			"7a672451d57673b0da774463ee18c04e3fe1d9aef1ce602135644a144dd0182c"},
		{"k not the one N gives", []uint16{3}, rpaHex(t, "0100e0"), false,
			"6a1c6edee65da70f38e0e3980d31c6189b7e8a63f77d539da46279a3aa57562a"},
	}
	for _, test := range tests {
		got, err := builder.DecodeRPAFilter(test.data)
		if err != nil || !slices.Equal(got, test.values) {
			t.Errorf("%s: decoded %d values, %v", test.name, len(got), err)
			continue
		}
		if builder.RPAFilterCanonical(test.data, got) != test.canonical {
			t.Errorf("%s: canonical %v, want %v", test.name, !test.canonical, test.canonical)
		}
		hash := builder.GetRPAFilterHash(test.data)
		if hex.EncodeToString(hash[:]) != test.hash {
			t.Errorf("%s: hash %x, want %s", test.name, hash[:], test.hash)
		}
	}
}

// TestRPAFilterRefused checks that the decoder refuses each malformed
// encoding, for the reason the vectors give.
func TestRPAFilterRefused(t *testing.T) {
	tests := []struct {
		name string
		data string
		err  error
	}{
		{"empty", "", builder.ErrRPAFilterTruncated},
		{"count only", "01", builder.ErrRPAFilterTruncated},
		{"no stream", "010f", builder.ErrRPAFilterTruncated},
		{"k above 15", "0110000000", builder.ErrRPAFilterK},
		{"gap of 0", "020e000a0000", builder.ErrRPAFilterGap},
		{"value above 65535", "010fc00000", builder.ErrRPAFilterValue},
		{"sum above 65535", "020eefffc00080", builder.ErrRPAFilterValue},
		{"fewer values", "020e000a", builder.ErrRPAFilterTruncated},
		// One value and then the bytes of another: whether they are read
		// as a second value or as bytes after the last, they are refused.
		{"more values", "010f00070009", builder.ErrRPAFilterTrailing},
		{"padding", "020e00000005", builder.ErrRPAFilterPadding},
		{"trailing after none", "0000", builder.ErrRPAFilterTrailing},
		{"trailing after one", "010f000700", builder.ErrRPAFilterTrailing},
		{"long count", "fd01000f0007", builder.ErrRPAFilterCount},
		{"count above 65536", "fe010001000000", builder.ErrRPAFilterCount},
	}
	for _, test := range tests {
		if _, err := builder.DecodeRPAFilter(rpaHex(t, test.data)); !errors.Is(err, test.err) {
			t.Errorf("%s: got %v, want %v", test.name, err, test.err)
		}
	}
}

// TestRPAFilterK checks the Rice parameter at the counts where it changes
// and at both ends.
func TestRPAFilterK(t *testing.T) {
	tests := []struct {
		n int
		k uint8
	}{
		{1, 15}, {2, 14}, {3, 13}, {5, 13}, {6, 12}, {30, 10}, {45426, 0},
		{45427, 0}, {65536, 0}, {22713, 1}, {22714, 0}, {11356, 2}, {11357, 1},
	}
	for _, test := range tests {
		if k := builder.RPAFilterK(test.n); k != test.k {
			t.Errorf("%d values: k %d, want %d", test.n, k, test.k)
		}
	}
}

// TestRPAFilterMatch checks prefixes of 4, 8, 12 and 16 bits against values
// at the edges of their ranges.
func TestRPAFilterMatch(t *testing.T) {
	values := []uint16{0x0000, 0x12ff, 0x1300, 0xa5a5, 0xffff}
	tests := []struct {
		prefix uint16
		bits   uint8
		match  bool
	}{
		{0x0, 4, true}, {0x1, 4, true}, {0x2, 4, false}, {0xa, 4, true}, {0xf, 4, true},
		{0x12, 8, true}, {0x13, 8, true}, {0x14, 8, false}, {0xff, 8, true}, {0xfe, 8, false},
		{0x12f, 12, true}, {0x130, 12, true}, {0x131, 12, false}, {0xa5a, 12, true},
		{0x12ff, 16, true}, {0x1300, 16, true}, {0x1301, 16, false}, {0xffff, 16, true}, {0xfffe, 16, false},
		{0x0000, 16, true}, {0x0001, 16, false},
		// Not a prefix: no bits, more than 16, or bits set past its length.
		{0, 0, false}, {0x12ff, 17, false}, {0x1ff, 8, false},
	}
	for _, test := range tests {
		if got := builder.RPAFilterMatch(values, test.prefix, test.bits); got != test.match {
			t.Errorf("prefix %x/%d: match %v, want %v", test.prefix, test.bits, got, test.match)
		}
	}
	if builder.RPAFilterMatch(nil, 0, 4) {
		t.Error("an empty filter matches")
	}
}
