// Copyright (c) 2026 The bchd developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package builder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"

	"github.com/gcash/bchd/chaincfg/chainhash"
	"github.com/gcash/bchd/wire"
)

// The input prefix filter (filter type 2) lets a wallet that receives on a
// reusable payment address find the blocks that may pay it without telling
// anyone the prefix it looks for. A sender grinds one input among the first
// 30 of a transaction until the first bits of the double SHA-256 of that
// serialized input equal bits of the receiver's scan key, so a block may pay
// the wallet exactly when one of those inputs has the wallet's prefix.
//
// The filter is the set of the first two bytes of the double SHA-256 of each
// of the first 30 inputs of every transaction of the block but the coinbase,
// as 16-bit values, sorted and each kept once, Rice coded with a parameter
// that follows from their number, so that every node gives the same bytes. It
// is built from the block alone.

const (
	// RPAFilterInputs is how many of a transaction's first inputs the input
	// prefix filter takes.
	RPAFilterInputs = 30

	// RPAFilterMaxValues is the most values an input prefix filter can
	// hold: every 16-bit value.
	RPAFilterMaxValues = 1 << 16

	// rpaFilterKScale is round(65536 * ln 2), from which the Rice parameter
	// for a number of values follows.
	rpaFilterKScale = 45426
)

var (
	// ErrRPAFilterTruncated is returned for filter bytes that end before
	// the count, the parameter or the values they promise.
	ErrRPAFilterTruncated = errors.New("input prefix filter ends early")

	// ErrRPAFilterCount is returned for a count not in its shortest
	// CompactSize form, or above 65,536.
	ErrRPAFilterCount = errors.New("input prefix filter count is not in its " +
		"shortest form or is above 65,536")

	// ErrRPAFilterK is returned for a Rice parameter other than the one the
	// count gives, so that a set of values has one encoding.
	ErrRPAFilterK = errors.New("input prefix filter parameter is not the one " +
		"its count gives")

	// ErrRPAFilterGap is returned for a gap of 0 after the first value: a
	// value repeated, which the set holds once.
	ErrRPAFilterGap = errors.New("input prefix filter repeats a value")

	// ErrRPAFilterValue is returned for a value above 65,535.
	ErrRPAFilterValue = errors.New("input prefix filter value is above 65,535")

	// ErrRPAFilterPadding is returned for a set bit after the last value.
	ErrRPAFilterPadding = errors.New("input prefix filter padding is not zero")

	// ErrRPAFilterTrailing is returned for bytes after the last value's.
	ErrRPAFilterTrailing = errors.New("input prefix filter has trailing bytes")
)

// RPAInputValue returns the value of an input in the input prefix filter: the
// first two bytes, big-endian, of the double SHA-256 of the input as it is
// serialized in its transaction.
func RPAInputValue(txIn *wire.TxIn) uint16 {
	var b bytes.Buffer
	b.Grow(chainhash.HashSize + 4 + wire.MaxVarIntPayload + len(txIn.SignatureScript) + 4)
	b.Write(txIn.PreviousOutPoint.Hash[:])
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], txIn.PreviousOutPoint.Index)
	b.Write(u32[:])
	// Writing to a bytes.Buffer doesn't fail.
	_ = wire.WriteVarInt(&b, 0, uint64(len(txIn.SignatureScript)))
	b.Write(txIn.SignatureScript)
	binary.LittleEndian.PutUint32(u32[:], txIn.Sequence)
	b.Write(u32[:])
	h := chainhash.DoubleHashB(b.Bytes())
	return uint16(h[0])<<8 | uint16(h[1])
}

// RPAValues returns the values of the input prefix filter of transactions
// none of which is a coinbase: those of the first 30 inputs of each, sorted,
// each once.
func RPAValues(txs []*wire.MsgTx) []uint16 {
	var seen [RPAFilterMaxValues / 64]uint64
	n := 0
	for _, tx := range txs {
		ins := tx.TxIn
		if len(ins) > RPAFilterInputs {
			ins = ins[:RPAFilterInputs]
		}
		for _, txIn := range ins {
			v := RPAInputValue(txIn)
			if seen[v/64]&(1<<(v%64)) == 0 {
				seen[v/64] |= 1 << (v % 64)
				n++
			}
		}
	}
	values := make([]uint16, 0, n)
	for i, word := range seen {
		for word != 0 {
			b := bits.TrailingZeros64(word)
			values = append(values, uint16(i*64+b))
			word &= word - 1
		}
	}
	return values
}

// RPABlockValues returns the values of a block's input prefix filter: those
// of every transaction but the coinbase.
func RPABlockValues(block *wire.MsgBlock) []uint16 {
	if len(block.Transactions) < 2 {
		return nil
	}
	return RPAValues(block.Transactions[1:])
}

// RPAFilterK returns the Rice parameter of a filter of n values, n above 0:
// floor(log2(floor(45426 / n))), or 0 when that quotient is 0.
func RPAFilterK(n int) uint8 {
	q := rpaFilterKScale / n
	if q == 0 {
		return 0
	}
	return uint8(bits.Len(uint(q)) - 1)
}

// rpaBitWriter packs bits most significant first.
type rpaBitWriter struct {
	out  []byte
	cur  byte
	used uint
}

func (w *rpaBitWriter) bit(one bool) {
	if one {
		w.cur |= 0x80 >> w.used
	}
	w.used++
	if w.used == 8 {
		w.out = append(w.out, w.cur)
		w.cur, w.used = 0, 0
	}
}

func (w *rpaBitWriter) flush() []byte {
	if w.used > 0 {
		w.out = append(w.out, w.cur)
	}
	return w.out
}

// EncodeRPAFilter encodes the values of an input prefix filter, which must be
// sorted and distinct: their count as CompactSize, then, when there are any,
// the Rice parameter and each gap from the value before (the first from 0),
// Rice coded and packed most significant bit first.
func EncodeRPAFilter(values []uint16) []byte {
	var count bytes.Buffer
	_ = wire.WriteVarInt(&count, 0, uint64(len(values)))
	if len(values) == 0 {
		return count.Bytes()
	}
	k := RPAFilterK(len(values))
	w := rpaBitWriter{out: append(count.Bytes(), k)}
	var prev uint32
	for _, v := range values {
		d := uint32(v) - prev
		prev = uint32(v)
		for q := d >> k; q > 0; q-- {
			w.bit(true)
		}
		w.bit(false)
		for i := int(k) - 1; i >= 0; i-- {
			w.bit(d>>uint(i)&1 == 1)
		}
	}
	return w.flush()
}

// BuildRPAFilter returns a block's input prefix filter, encoded.
func BuildRPAFilter(block *wire.MsgBlock) []byte {
	return EncodeRPAFilter(RPABlockValues(block))
}

// rpaBitReader reads bits most significant first.
type rpaBitReader struct {
	b   []byte
	pos uint64
}

func (r *rpaBitReader) bit() (bool, bool) {
	if r.pos >= uint64(len(r.b))*8 {
		return false, false
	}
	one := r.b[r.pos/8]&(0x80>>(r.pos%8)) != 0
	r.pos++
	return one, true
}

// DecodeRPAFilter decodes an input prefix filter into its values, in order.
// It refuses a count not in its shortest form or above 65,536, a parameter
// other than the one the count gives, a value repeated or above 65,535, fewer
// values than the count, a set padding bit and trailing bytes, so that the
// bytes it takes are the one encoding of their values, the one
// EncodeRPAFilter gives.
func DecodeRPAFilter(b []byte) ([]uint16, error) {
	r := bytes.NewReader(b)
	n, err := wire.ReadVarInt(r, 0)
	if err != nil {
		// ReadVarInt also refuses a count not in its shortest form, with a
		// message error rather than an end of input.
		var msgErr *wire.MessageError
		if errors.As(err, &msgErr) {
			return nil, ErrRPAFilterCount
		}
		return nil, ErrRPAFilterTruncated
	}
	if n > RPAFilterMaxValues {
		return nil, ErrRPAFilterCount
	}
	rest := b[len(b)-r.Len():]
	if n == 0 {
		if len(rest) != 0 {
			return nil, ErrRPAFilterTrailing
		}
		return []uint16{}, nil
	}
	if len(rest) == 0 {
		return nil, ErrRPAFilterTruncated
	}
	k := rest[0]
	if k != RPAFilterK(int(n)) {
		return nil, ErrRPAFilterK
	}
	br := rpaBitReader{b: rest[1:]}
	values := make([]uint16, 0, n)
	var prev uint32
	for i := uint64(0); i < n; i++ {
		var q uint32
		for {
			one, ok := br.bit()
			if !ok {
				return nil, ErrRPAFilterTruncated
			}
			if !one {
				break
			}
			q++
			if q<<k > 0xffff {
				return nil, ErrRPAFilterValue
			}
		}
		d := q << k
		for j := int(k) - 1; j >= 0; j-- {
			one, ok := br.bit()
			if !ok {
				return nil, ErrRPAFilterTruncated
			}
			if one {
				d |= 1 << uint(j)
			}
		}
		if i > 0 && d == 0 {
			return nil, ErrRPAFilterGap
		}
		v := prev + d
		if v > 0xffff {
			return nil, ErrRPAFilterValue
		}
		values = append(values, uint16(v))
		prev = v
	}
	// The bits left in the last byte read must be zero, and no byte may
	// follow it.
	used := (br.pos + 7) / 8
	if used < uint64(len(br.b)) {
		return nil, ErrRPAFilterTrailing
	}
	for br.pos < used*8 {
		if one, _ := br.bit(); one {
			return nil, ErrRPAFilterPadding
		}
	}
	return values, nil
}

// RPAFilterMatch reports whether sorted values hold one whose first bits
// equal a prefix of 1 to 16 bits: a value in [prefix << (16 - bits),
// (prefix + 1) << (16 - bits)).
func RPAFilterMatch(values []uint16, prefix uint16, prefixBits uint8) bool {
	if prefixBits == 0 || prefixBits > 16 {
		return false
	}
	shift := 16 - uint(prefixBits)
	lo := uint32(prefix) << shift
	hi := (uint32(prefix) + 1) << shift
	i, _ := slices.BinarySearch(values, uint16(min(lo, 0xffff)))
	return lo <= 0xffff && i < len(values) && uint32(values[i]) < hi
}

// GetRPAFilterHash returns the double SHA-256 of an input prefix filter's
// bytes, the hash a cfheaders message lists for it.
func GetRPAFilterHash(filter []byte) chainhash.Hash {
	return chainhash.DoubleHashH(filter)
}

// MakeHeaderForRPAFilter returns an input prefix filter's header: the double
// SHA-256 of its hash and the previous block's filter header, as for the
// other filter types.
func MakeHeaderForRPAFilter(filter []byte, prevHeader chainhash.Hash) chainhash.Hash {
	filterHash := GetRPAFilterHash(filter)
	var b [2 * chainhash.HashSize]byte
	copy(b[:], filterHash[:])
	copy(b[chainhash.HashSize:], prevHeader[:])
	return chainhash.DoubleHashH(b[:])
}
