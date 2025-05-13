// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package bchutil_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/gcash/bchd/chaincfg"
	"github.com/gcash/bchutil"
	"golang.org/x/crypto/ripemd160"
)

func TestAddresses(t *testing.T) {
	tests := []struct {
		name    string
		addr    string
		encoded string
		valid   bool
		result  bchutil.Address
		f       func() (bchutil.Address, error)
		net     *chaincfg.Params
	}{
		// Positive cashaddr P2PKH tests.
		{
			name:    "cashaddr mainnet p2pkh",
			addr:    "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
			encoded: "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
			valid:   true,
			result: bchutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169},
				&chaincfg.MainNetParams),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169}
				return bchutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "cashaddr mainnet uppercase p2pkh",
			addr:    strings.ToUpper("qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy"),
			encoded: "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y0qverfuy",
			valid:   true,
			result: bchutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169},
				&chaincfg.MainNetParams),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169}
				return bchutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "cashaddr testnet p2pkh",
			addr:    "qr95sy3j9xwd2ap32xkykttr4cvcu7as4ytjg7p7mc",
			encoded: "qr95sy3j9xwd2ap32xkykttr4cvcu7as4ytjg7p7mc",
			valid:   true,
			result: bchutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169},
				&chaincfg.TestNet3Params),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169}
				return bchutil.NewAddressPubKeyHash(pkHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "cashaddr regtest p2pkh",
			addr:    "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y3w7lzdc7",
			encoded: "qr95sy3j9xwd2ap32xkykttr4cvcu7as4y3w7lzdc7",
			valid:   true,
			result: bchutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169},
				&chaincfg.RegressionNetParams),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{203, 72, 18, 50, 41, 156, 213, 116, 49, 81,
					172, 75, 45, 99, 174, 25, 142, 123, 176, 169}
				return bchutil.NewAddressPubKeyHash(pkHash, &chaincfg.RegressionNetParams)
			},
			net: &chaincfg.RegressionNetParams,
		},
		// Positive cashaddr P2SH tests.
		{
			name:    "cashaddr mainnet p2p2sh",
			addr:    "ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
			encoded: "ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq",
			valid:   true,
			result: bchutil.TstAddressScriptHash(
				[ripemd160.Size]byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115},
				&chaincfg.MainNetParams),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115}
				return bchutil.NewAddressScriptHashFromHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "cashaddr testnet p2p2sh",
			addr:    "ppm2qsznhks23z7629mms6s4cwef74vcwvhanqgjxu",
			encoded: "ppm2qsznhks23z7629mms6s4cwef74vcwvhanqgjxu",
			valid:   true,
			result: bchutil.TstAddressScriptHash(
				[ripemd160.Size]byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115},
				&chaincfg.TestNet3Params),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115}
				return bchutil.NewAddressScriptHashFromHash(pkHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "cashaddr regtest p2p2sh",
			addr:    "ppm2qsznhks23z7629mms6s4cwef74vcwvdp9ptp96",
			encoded: "ppm2qsznhks23z7629mms6s4cwef74vcwvdp9ptp96",
			valid:   true,
			result: bchutil.TstAddressScriptHash(
				[ripemd160.Size]byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115},
				&chaincfg.RegressionNetParams),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{118, 160, 64, 83, 189, 160, 168, 139, 218, 81, 119,
					184, 106, 21, 195, 178, 159, 85, 152, 115}
				return bchutil.NewAddressScriptHashFromHash(pkHash, &chaincfg.RegressionNetParams)
			},
			net: &chaincfg.RegressionNetParams,
		},
		// Positive legacy P2PKH tests.
		{
			name:    "legacy mainnet p2pkh",
			addr:    "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
			encoded: "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
			valid:   true,
			result: bchutil.TstLegacyAddressPubKeyHash(
				[ripemd160.Size]byte{
					0xe3, 0x4c, 0xce, 0x70, 0xc8, 0x63, 0x73, 0x27, 0x3e, 0xfc,
					0xc5, 0x4c, 0xe7, 0xd2, 0xa4, 0x91, 0xbb, 0x4a, 0x0e, 0x84},
				chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{
					0xe3, 0x4c, 0xce, 0x70, 0xc8, 0x63, 0x73, 0x27, 0x3e, 0xfc,
					0xc5, 0x4c, 0xe7, 0xd2, 0xa4, 0x91, 0xbb, 0x4a, 0x0e, 0x84}
				return bchutil.NewLegacyAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "legacy mainnet p2pkh 2",
			addr:    "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
			encoded: "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
			valid:   true,
			result: bchutil.TstLegacyAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b, 0xf4,
					0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad, 0xaa},
				chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{
					0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b, 0xf4,
					0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad, 0xaa}
				return bchutil.NewLegacyAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "legacy testnet p2pkh",
			addr:    "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			encoded: "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			valid:   true,
			result: bchutil.TstLegacyAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f},
				chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				pkHash := []byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f}
				return bchutil.NewLegacyAddressPubKeyHash(pkHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},

		// Negative legacy P2PKH tests.
		{
			name:  "legacy p2pkh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (bchutil.Address, error) {
				pkHash := []byte{
					0x00, 0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b,
					0xf4, 0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad,
					0xaa}
				return bchutil.NewLegacyAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:  "legacy p2pkh bad checksum",
			addr:  "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gY",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},

		// Positive legacy P2SH tests.
		{
			// Taken from transactions:
			// output: 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
			// input:  837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
			name:    "legacy mainnet p2sh",
			addr:    "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
			encoded: "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
			valid:   true,
			result: bchutil.TstLegacyAddressScriptHash(
				[ripemd160.Size]byte{
					0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9, 0xf2,
					0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55, 0x10},
				chaincfg.MainNetParams.LegacyScriptHashAddrID),
			f: func() (bchutil.Address, error) {
				script := []byte{
					0x52, 0x41, 0x04, 0x91, 0xbb, 0xa2, 0x51, 0x09, 0x12, 0xa5,
					0xbd, 0x37, 0xda, 0x1f, 0xb5, 0xb1, 0x67, 0x30, 0x10, 0xe4,
					0x3d, 0x2c, 0x6d, 0x81, 0x2c, 0x51, 0x4e, 0x91, 0xbf, 0xa9,
					0xf2, 0xeb, 0x12, 0x9e, 0x1c, 0x18, 0x33, 0x29, 0xdb, 0x55,
					0xbd, 0x86, 0x8e, 0x20, 0x9a, 0xac, 0x2f, 0xbc, 0x02, 0xcb,
					0x33, 0xd9, 0x8f, 0xe7, 0x4b, 0xf2, 0x3f, 0x0c, 0x23, 0x5d,
					0x61, 0x26, 0xb1, 0xd8, 0x33, 0x4f, 0x86, 0x41, 0x04, 0x86,
					0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7,
					0xb1, 0xe1, 0x06, 0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99,
					0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53, 0xe6, 0x92, 0x56, 0xda,
					0xc0, 0x9e, 0xf1, 0x22, 0xb1, 0xa9, 0x86, 0x81, 0x8a, 0x7c,
					0xb6, 0x24, 0x53, 0x2f, 0x06, 0x2c, 0x1d, 0x1f, 0x87, 0x22,
					0x08, 0x48, 0x61, 0xc5, 0xc3, 0x29, 0x1c, 0xcf, 0xfe, 0xf4,
					0xec, 0x68, 0x74, 0x41, 0x04, 0x8d, 0x24, 0x55, 0xd2, 0x40,
					0x3e, 0x08, 0x70, 0x8f, 0xc1, 0xf5, 0x56, 0x00, 0x2f, 0x1b,
					0x6c, 0xd8, 0x3f, 0x99, 0x2d, 0x08, 0x50, 0x97, 0xf9, 0x97,
					0x4a, 0xb0, 0x8a, 0x28, 0x83, 0x8f, 0x07, 0x89, 0x6f, 0xba,
					0xb0, 0x8f, 0x39, 0x49, 0x5e, 0x15, 0xfa, 0x6f, 0xad, 0x6e,
					0xdb, 0xfb, 0x1e, 0x75, 0x4e, 0x35, 0xfa, 0x1c, 0x78, 0x44,
					0xc4, 0x1f, 0x32, 0x2a, 0x18, 0x63, 0xd4, 0x62, 0x13, 0x53,
					0xae}
				return bchutil.NewLegacyAddressScriptHash(script, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			// Taken from transactions:
			// output: b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
			// input: (not yet redeemed at time test was written)
			name:    "legacy mainnet p2sh 2",
			addr:    "3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
			encoded: "3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
			valid:   true,
			result: bchutil.TstLegacyAddressScriptHash(
				[ripemd160.Size]byte{
					0xe8, 0xc3, 0x00, 0xc8, 0x79, 0x86, 0xef, 0xa8, 0x4c, 0x37,
					0xc0, 0x51, 0x99, 0x29, 0x01, 0x9e, 0xf8, 0x6e, 0xb5, 0xb4},
				chaincfg.MainNetParams.LegacyScriptHashAddrID),
			f: func() (bchutil.Address, error) {
				hash := []byte{
					0xe8, 0xc3, 0x00, 0xc8, 0x79, 0x86, 0xef, 0xa8, 0x4c, 0x37,
					0xc0, 0x51, 0x99, 0x29, 0x01, 0x9e, 0xf8, 0x6e, 0xb5, 0xb4}
				return bchutil.NewLegacyAddressScriptHashFromHash(hash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			// Taken from bitcoind base58_keys_valid.
			name:    "legacy testnet p2sh",
			addr:    "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
			encoded: "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
			valid:   true,
			result: bchutil.TstLegacyAddressScriptHash(
				[ripemd160.Size]byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a},
				chaincfg.TestNet3Params.LegacyScriptHashAddrID),
			f: func() (bchutil.Address, error) {
				hash := []byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a}
				return bchutil.NewLegacyAddressScriptHashFromHash(hash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "legacy testnet p2sh (reported issue)",
			addr:    "2MscXFWM3yfDTYxGGC2dXCZvcMd6ySyqgPt",
			encoded: "2MscXFWM3yfDTYxGGC2dXCZvcMd6ySyqgPt",
			valid:   true,
			result: bchutil.TstLegacyAddressScriptHash(
				[ripemd160.Size]byte{
					0x4, 0x7, 0x25, 0x2a, 0x3a, 0x2e, 0xb1, 0x5c, 0x8f, 0xc1,
					0x8d, 0xf4, 0xd, 0xf0, 0x5b, 0x34, 0xc8, 0xfe, 0x9e, 0x11},
				chaincfg.TestNet3Params.LegacyScriptHashAddrID),
			f: func() (bchutil.Address, error) {
				hash := []byte{
					0x4, 0x7, 0x25, 0x2a, 0x3a, 0x2e, 0xb1, 0x5c, 0x8f, 0xc1,
					0x8d, 0xf4, 0xd, 0xf0, 0x5b, 0x34, 0xc8, 0xfe, 0x9e, 0x11}
				return bchutil.NewLegacyAddressScriptHashFromHash(hash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		// Negative legacy P2SH tests.
		{
			name:  "legacy p2sh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (bchutil.Address, error) {
				hash := []byte{
					0x00, 0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9,
					0xf2, 0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55,
					0x10}
				return bchutil.NewLegacyAddressScriptHashFromHash(hash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},

		// Positive P2PK tests.
		{
			name:    "mainnet p2pk compressed (0x02)",
			addr:    "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
			encoded: "13CG6SJ3yHUXo4Cr2RY4THLLJrNFuG3gUg",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4},
				bchutil.PKFCompressed, chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "mainnet p2pk compressed (0x03)",
			addr:    "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
			encoded: "15sHANNUBSh6nDp8XkDPmQcW6n3EFwmvE6",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65},
				bchutil.PKFCompressed, chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name: "mainnet p2pk uncompressed (0x04)",
			addr: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5cb2" +
				"e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
			encoded: "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3},
				bchutil.PKFUncompressed, chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name: "mainnet p2pk hybrid (0x06)",
			addr: "06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4" +
				"0d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e",
			encoded: "1Ja5rs7XBZnK88EuLVcFqYGMEbBitzchmX",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x06, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4, 0x0d, 0x45, 0x26, 0x48, 0x38, 0xc0, 0xbd,
					0x96, 0x85, 0x26, 0x62, 0xce, 0x6a, 0x84, 0x7b, 0x19, 0x73,
					0x76, 0x83, 0x01, 0x60, 0xc6, 0xd2, 0xeb, 0x5e, 0x6a, 0x4c,
					0x44, 0xd3, 0x3f, 0x45, 0x3e},
				bchutil.PKFHybrid, chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x06, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4, 0x0d, 0x45, 0x26, 0x48, 0x38, 0xc0, 0xbd,
					0x96, 0x85, 0x26, 0x62, 0xce, 0x6a, 0x84, 0x7b, 0x19, 0x73,
					0x76, 0x83, 0x01, 0x60, 0xc6, 0xd2, 0xeb, 0x5e, 0x6a, 0x4c,
					0x44, 0xd3, 0x3f, 0x45, 0x3e}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name: "mainnet p2pk hybrid (0x07)",
			addr: "07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65" +
				"37a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b",
			encoded: "1ExqMmf6yMxcBMzHjbj41wbqYuqoX6uBLG",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x07, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65, 0x37, 0xa5, 0x76, 0x78, 0x2e, 0xba, 0x66,
					0x8a, 0x7e, 0xf8, 0xbd, 0x3b, 0x3c, 0xfb, 0x1e, 0xdb, 0x71,
					0x17, 0xab, 0x65, 0x12, 0x9b, 0x8a, 0x2e, 0x68, 0x1f, 0x3c,
					0x1e, 0x09, 0x08, 0xef, 0x7b},
				bchutil.PKFHybrid, chaincfg.MainNetParams.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x07, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65, 0x37, 0xa5, 0x76, 0x78, 0x2e, 0xba, 0x66,
					0x8a, 0x7e, 0xf8, 0xbd, 0x3b, 0x3c, 0xfb, 0x1e, 0xdb, 0x71,
					0x17, 0xab, 0x65, 0x12, 0x9b, 0x8a, 0x2e, 0x68, 0x1f, 0x3c,
					0x1e, 0x09, 0x08, 0xef, 0x7b}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "testnet p2pk compressed (0x02)",
			addr:    "02192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b4",
			encoded: "mhiDPVP2nJunaAgTjzWSHCYfAqxxrxzjmo",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4},
				bchutil.PKFCompressed, chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x02, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "testnet p2pk compressed (0x03)",
			addr:    "03b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e65",
			encoded: "mkPETRTSzU8MZLHkFKBmbKppxmdw9qT42t",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65},
				bchutil.PKFCompressed, chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x03, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name: "testnet p2pk uncompressed (0x04)",
			addr: "0411db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5" +
				"cb2e0eaddfb84ccf9744464f82e160bfa9b8b64f9d4c03f999b8643f656b412a3",
			encoded: "mh8YhPYEAYs3E7EVyKtB5xrcfMExkkdEMF",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3},
				bchutil.PKFUncompressed, chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x04, 0x11, 0xdb, 0x93, 0xe1, 0xdc, 0xdb, 0x8a, 0x01, 0x6b,
					0x49, 0x84, 0x0f, 0x8c, 0x53, 0xbc, 0x1e, 0xb6, 0x8a, 0x38,
					0x2e, 0x97, 0xb1, 0x48, 0x2e, 0xca, 0xd7, 0xb1, 0x48, 0xa6,
					0x90, 0x9a, 0x5c, 0xb2, 0xe0, 0xea, 0xdd, 0xfb, 0x84, 0xcc,
					0xf9, 0x74, 0x44, 0x64, 0xf8, 0x2e, 0x16, 0x0b, 0xfa, 0x9b,
					0x8b, 0x64, 0xf9, 0xd4, 0xc0, 0x3f, 0x99, 0x9b, 0x86, 0x43,
					0xf6, 0x56, 0xb4, 0x12, 0xa3}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name: "testnet p2pk hybrid (0x06)",
			addr: "06192d74d0cb94344c9569c2e77901573d8d7903c3ebec3a957724895dca52c6b" +
				"40d45264838c0bd96852662ce6a847b197376830160c6d2eb5e6a4c44d33f453e",
			encoded: "my639vCVzbDZuEiX44adfTUg6anRomZLEP",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x06, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4, 0x0d, 0x45, 0x26, 0x48, 0x38, 0xc0, 0xbd,
					0x96, 0x85, 0x26, 0x62, 0xce, 0x6a, 0x84, 0x7b, 0x19, 0x73,
					0x76, 0x83, 0x01, 0x60, 0xc6, 0xd2, 0xeb, 0x5e, 0x6a, 0x4c,
					0x44, 0xd3, 0x3f, 0x45, 0x3e},
				bchutil.PKFHybrid, chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x06, 0x19, 0x2d, 0x74, 0xd0, 0xcb, 0x94, 0x34, 0x4c, 0x95,
					0x69, 0xc2, 0xe7, 0x79, 0x01, 0x57, 0x3d, 0x8d, 0x79, 0x03,
					0xc3, 0xeb, 0xec, 0x3a, 0x95, 0x77, 0x24, 0x89, 0x5d, 0xca,
					0x52, 0xc6, 0xb4, 0x0d, 0x45, 0x26, 0x48, 0x38, 0xc0, 0xbd,
					0x96, 0x85, 0x26, 0x62, 0xce, 0x6a, 0x84, 0x7b, 0x19, 0x73,
					0x76, 0x83, 0x01, 0x60, 0xc6, 0xd2, 0xeb, 0x5e, 0x6a, 0x4c,
					0x44, 0xd3, 0x3f, 0x45, 0x3e}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name: "testnet p2pk hybrid (0x07)",
			addr: "07b0bd634234abbb1ba1e986e884185c61cf43e001f9137f23c2c409273eb16e6" +
				"537a576782eba668a7ef8bd3b3cfb1edb7117ab65129b8a2e681f3c1e0908ef7b",
			encoded: "muUnepk5nPPrxUTuTAhRqrpAQuSWS5fVii",
			valid:   true,
			result: bchutil.TstAddressPubKey(
				[]byte{
					0x07, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65, 0x37, 0xa5, 0x76, 0x78, 0x2e, 0xba, 0x66,
					0x8a, 0x7e, 0xf8, 0xbd, 0x3b, 0x3c, 0xfb, 0x1e, 0xdb, 0x71,
					0x17, 0xab, 0x65, 0x12, 0x9b, 0x8a, 0x2e, 0x68, 0x1f, 0x3c,
					0x1e, 0x09, 0x08, 0xef, 0x7b},
				bchutil.PKFHybrid, chaincfg.TestNet3Params.LegacyPubKeyHashAddrID),
			f: func() (bchutil.Address, error) {
				serializedPubKey := []byte{
					0x07, 0xb0, 0xbd, 0x63, 0x42, 0x34, 0xab, 0xbb, 0x1b, 0xa1,
					0xe9, 0x86, 0xe8, 0x84, 0x18, 0x5c, 0x61, 0xcf, 0x43, 0xe0,
					0x01, 0xf9, 0x13, 0x7f, 0x23, 0xc2, 0xc4, 0x09, 0x27, 0x3e,
					0xb1, 0x6e, 0x65, 0x37, 0xa5, 0x76, 0x78, 0x2e, 0xba, 0x66,
					0x8a, 0x7e, 0xf8, 0xbd, 0x3b, 0x3c, 0xfb, 0x1e, 0xdb, 0x71,
					0x17, 0xab, 0x65, 0x12, 0x9b, 0x8a, 0x2e, 0x68, 0x1f, 0x3c,
					0x1e, 0x09, 0x08, 0xef, 0x7b}
				return bchutil.NewAddressPubKey(serializedPubKey, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
	}

	for _, test := range tests {
		// Decode addr and compare error against valid.
		decoded, err := bchutil.DecodeAddress(test.addr, test.net)
		if (err == nil) != test.valid {
			t.Errorf("%v: decoding test failed: %v", test.name, err)
			return
		}

		if err == nil {
			// Ensure the stringer returns the same address as the
			// original.
			if decodedStringer, ok := decoded.(fmt.Stringer); ok {
				addr := test.addr

				if !strings.EqualFold(addr, decodedStringer.String()) {
					t.Errorf("%v: String on decoded value does not match expected value: %v != %v",
						test.name, test.addr, decodedStringer.String())
					return
				}
			}

			// Encode again and compare against the original.
			encoded := decoded.EncodeAddress()
			if test.encoded != encoded {
				t.Errorf("%v: decoding and encoding produced different addressess: %v != %v",
					test.name, test.encoded, encoded)
				return
			}

			// Perform type-specific calculations.
			var saddr []byte
			switch d := decoded.(type) {
			case *bchutil.AddressPubKeyHash:
				saddr = bchutil.TstAddressSAddr(encoded, test.net)

			case *bchutil.AddressScriptHash:
				saddr = bchutil.TstAddressSAddr(encoded, test.net)

			case *bchutil.LegacyAddressPubKeyHash:
				saddr = bchutil.TstLegacyAddressSAddr(encoded)

			case *bchutil.LegacyAddressScriptHash:
				saddr = bchutil.TstLegacyAddressSAddr(encoded)

			case *bchutil.AddressPubKey:
				// Ignore the error here since the script
				// address is checked below.
				saddr, _ = hex.DecodeString(d.String())
			}

			// Check script address, as well as the Hash160 method for P2PKH and
			// P2SH addresses.
			if !bytes.Equal(saddr, decoded.ScriptAddress()) {
				t.Errorf("%v: script addresses do not match:\n%x != \n%x",
					test.name, saddr, decoded.ScriptAddress())
				return
			}
			switch a := decoded.(type) {
			case *bchutil.AddressPubKeyHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *bchutil.AddressScriptHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}
			case *bchutil.LegacyAddressPubKeyHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *bchutil.LegacyAddressScriptHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}
			}

			// Ensure the address is for the expected network.
			if !decoded.IsForNet(test.net) {
				t.Errorf("%v: calculated network does not match expected",
					test.name)
				return
			}
		}

		if !test.valid {
			// If address is invalid, but a creation function exists,
			// verify that it returns a nil addr and non-nil error.
			if test.f != nil {
				_, err := test.f()
				if err == nil {
					t.Errorf("%v: address is invalid but creating new address succeeded",
						test.name)
					return
				}
			}
			continue
		}

		// Valid test, compare address created with f against expected result.
		addr, err := test.f()
		if err != nil {
			t.Errorf("%v: address is valid but creating new address failed with error %v",
				test.name, err)
			return
		}

		if !reflect.DeepEqual(addr, test.result) {
			t.Errorf("%v: created address does not match expected result",
				test.name)
			return
		}
	}
}

var validCashAddreTestVectors = []string{
	"prefix:x64nx6hz",
	"PREFIX:X64NX6HZ",
	"p:gpf8m4h7",
	"bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
	"bchtest:testnetaddress4d6njnut",
	"bchreg:555555555555555555555555555555555555555555555udxmlmrz",
}

func TestValidCashAddrTestVectors(t *testing.T) {
	for _, s := range validCashAddreTestVectors {
		_, _, err := bchutil.DecodeCashAddress(s)
		if err != nil {
			t.Error(err)
		}
	}
}

var invalidCashAddreTestVectors = []string{
	"prefix:x32nx6hz",
	"prEfix:x64nx6hz",
	"prefix:x64nx6Hz",
	"pref1x:6m8cxv73",
	"prefix:",
	":u9wsx07j",
	"bchreg:555555555555555555x55555555555555555555555555udxmlmrz",
	"bchreg:555555555555555555555555555555551555555555555udxmlmrz",
	"pre:fix:x32nx6hz",
	"prefixx64nx6hz",
}

func TestInvalidCashAddreTestVectors(t *testing.T) {
	for _, s := range invalidCashAddreTestVectors {
		_, _, err := bchutil.DecodeCashAddress(s)
		if err == nil {
			t.Error("Failed to error on invalid string")
		}
	}
}

func TestDecodeCashAddressSlpMainnet(t *testing.T) {
	addrStr := "simpleledger:qrkjty23a5yl7vcvcnyh4dpnxxzuzs4lzqvesp65yq"
	prefix, data, err := bchutil.DecodeCashAddress(addrStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	if prefix != "simpleledger" {
		t.Fatal("decode failed")
	}
	if len(data) != 34 {
		t.Fatal("data wrong length")
	}
}

func TestDecodeCashAddressSlpMainnetUpperCase(t *testing.T) {
	addrStr := "SIMPLELEDGER:QRKJTY23A5YL7VCVCNYH4DPNXXZUZS4LZQVESP65YQ"
	prefix, data, err := bchutil.DecodeCashAddress(addrStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	if prefix != "simpleledger" {
		t.Fatal("decode failed")
	}
	if len(data) != 34 {
		t.Fatal("data wrong length")
	}
}

func TestDecodeCashAddressSlpMainnetP2sh(t *testing.T) {
	addrStr := "simpleledger:pzxvc3k38r4rq2x2asmdpnz4wk92lqazpg9jh3j0k9"
	prefix, data, err := bchutil.DecodeCashAddress(addrStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	if prefix != "simpleledger" {
		t.Fatal("decode failed")
	}
	if len(data) != 34 {
		t.Fatal("data wrong length")
	}
}

func TestDecodeCashAddressSlpTestnet(t *testing.T) {
	addrStr := "slptest:qq69xxsfujh45g23dv8uwfv02fj3z262cgfda57wzl"
	prefix, data, err := bchutil.DecodeCashAddress(addrStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	if prefix != "slptest" {
		t.Fatal("decode failed")
	}
	if len(data) != 34 {
		t.Fatal("data wrong length")
	}
}

func TestDecodeCashAddressSlpTestnetP2sh(t *testing.T) {
	addrStr := "slptest:ppmuknuf0l2z38mkdnjcv76yhaeh6fqhluv3gffh99"
	prefix, data, err := bchutil.DecodeCashAddress(addrStr)
	if err != nil {
		t.Fatal(err.Error())
	}
	if prefix != "slptest" {
		t.Fatal("decode failed")
	}
	if len(data) != 34 {
		t.Fatal("data wrong length")
	}
}

func TestDecodeAddressSlpMainnet(t *testing.T) {
	slpAddrStr := "qrkjty23a5yl7vcvcnyh4dpnxxzuzs4lzqvesp65yq"
	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != slpAddrStr {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpMainnetWithPrefix(t *testing.T) {
	prefix := "simpleledger"
	slpAddrStr := "qrkjty23a5yl7vcvcnyh4dpnxxzuzs4lzqvesp65yq"
	addr, err := bchutil.DecodeAddress(prefix+":"+slpAddrStr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != slpAddrStr {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpMainnetWithWrongPrefix(t *testing.T) {
	prefix := "bitcoincash"
	slpAddrStr := "qrkjty23a5yl7vcvcnyh4dpnxxzuzs4lzqvesp65yq"
	_, err := bchutil.DecodeAddress(prefix+":"+slpAddrStr, &chaincfg.MainNetParams)
	if err != bchutil.ErrChecksumMismatch {
		t.Fatal(err)
	}
}

func TestDecodeAddressSlpMainnetWithUnknownPrefix(t *testing.T) {
	prefix := "xyz"
	slpAddrStr := "qrkjty23a5yl7vcvcnyh4dpnxxzuzs4lzqvesp65yq"
	_, err := bchutil.DecodeAddress(prefix+":"+slpAddrStr, &chaincfg.MainNetParams)
	if err != bchutil.ErrUnknownFormat {
		t.Fatal(err)
	}
}

func TestDecodeAddressSlpMainnetUpperCase(t *testing.T) {
	slpAddrStr := "QRKJTY23A5YL7VCVCNYH4DPNXXZUZS4LZQVESP65YQ"
	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != strings.ToLower(slpAddrStr) {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpMainnetWithPrefixUpper(t *testing.T) {
	prefix := "SIMPLELEDGER"
	slpAddrStr := "QRKJTY23A5YL7VCVCNYH4DPNXXZUZS4LZQVESP65YQ"
	addr, err := bchutil.DecodeAddress(prefix+":"+slpAddrStr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != strings.ToLower(slpAddrStr) {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpMainnetWithPrefixUpperWrongPrefix(t *testing.T) {
	prefix := "BITCOINCASH"
	slpAddrStr := "QRKJTY23A5YL7VCVCNYH4DPNXXZUZS4LZQVESP65YQ"
	_, err := bchutil.DecodeAddress(prefix+":"+slpAddrStr, &chaincfg.MainNetParams)
	if err != bchutil.ErrChecksumMismatch {
		t.Fatal(err)
	}
}

func TestDecodeAddressSlpMainnetP2sh(t *testing.T) {
	slpAddrStr := "pzxvc3k38r4rq2x2asmdpnz4wk92lqazpg9jh3j0k9"
	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != slpAddrStr {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpTestnet(t *testing.T) {
	slpAddrStr := "qq69xxsfujh45g23dv8uwfv02fj3z262cgfda57wzl"
	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != slpAddrStr {
		t.Fatal("decode failed")
	}
}

func TestDecodeAddressSlpTestnetP2sh(t *testing.T) {
	slpAddrStr := "ppmuknuf0l2z38mkdnjcv76yhaeh6fqhluv3gffh99"
	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	if addr.String() != slpAddrStr {
		t.Fatal("decode failed")
	}
}

// Not enabled on Regnet, chain params are in old version of BCHD.
// func TestDecodeAddressSlpRegnet(t *testing.T) {
// 	slpAddrStr := "qq69xxsfujh45g23dv8uwfv02fj3z262cgfda57wzl"
// 	addr, err := bchutil.DecodeAddress(slpAddrStr, &chaincfg.RegressionNetParams)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if addr.String() != slpAddrStr {
// 		t.Fatal("decode failed")
// 	}
// }

func TestConvertCashToSlpAddress(t *testing.T) {
	addrStr := "qprqzzhhve7sgysgf8h29tumywnaeyqm7y6e869uc6"
	params := &chaincfg.MainNetParams

	addr, err := bchutil.DecodeAddress(addrStr, params)
	if err != nil {
		t.Fatal(err)
	}
	slpAddr, err := bchutil.ConvertCashToSlpAddress(addr, params)
	if err != nil {
		t.Fatal(err)
	}
	if slpAddr.String() != "qprqzzhhve7sgysgf8h29tumywnaeyqm7ykzvpsuxy" {
		t.Fatal("incorrect conversion")
	}
}

func TestConvertCashToSlpAddressP2sh(t *testing.T) {
	addrStr := "pzmj0ueqasnsw80a26th5t2gsz5evcxsps2tavljvp"
	params := &chaincfg.MainNetParams

	addr, err := bchutil.DecodeAddress(addrStr, params)
	if err != nil {
		t.Fatal(err)
	}
	slpAddr, err := bchutil.ConvertCashToSlpAddress(addr, params)
	if err != nil {
		t.Fatal(err)
	}

	if slpAddr.String() != "pzmj0ueqasnsw80a26th5t2gsz5evcxspsxskh2jjl" {
		t.Fatal("incorrect conversion")
	}
}

func TestConvertSlpToCashAddress(t *testing.T) {
	addrStr := "qprqzzhhve7sgysgf8h29tumywnaeyqm7ykzvpsuxy"
	params := &chaincfg.MainNetParams

	addr, err := bchutil.DecodeAddress(addrStr, params)
	if err != nil {
		t.Fatal(err)
	}
	slpAddr, err := bchutil.ConvertSlpToCashAddress(addr, params)
	if err != nil {
		t.Fatal(err)
	}
	if slpAddr.String() != "qprqzzhhve7sgysgf8h29tumywnaeyqm7y6e869uc6" {
		t.Fatal("incorrect conversion")
	}
}

func TestConvertSlpToCashAddressP2sh(t *testing.T) {
	addrStr := "pzmj0ueqasnsw80a26th5t2gsz5evcxspsxskh2jjl"
	params := &chaincfg.MainNetParams

	addr, err := bchutil.DecodeAddress(addrStr, params)
	if err != nil {
		t.Fatal(err)
	}
	slpAddr, err := bchutil.ConvertSlpToCashAddress(addr, params)
	if err != nil {
		t.Fatal(err)
	}
	if slpAddr.String() != "pzmj0ueqasnsw80a26th5t2gsz5evcxsps2tavljvp" {
		t.Fatal("incorrect conversion")
	}
}

// Source: https://github.com/cashtokens/cashtokens/blob/master/test-vectors/cashaddr.json
var p2SH32CashAddreTestVectors = []string{
	"bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
	"bitcoincash:zr6m7j9njldwwzlg9v7v53unlr4jkmx6eycnjehshe",
	"bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
	"pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
	"bitcoincash:qr7fzmep8g7h7ymfxy74lgc0v950j3r2959lhtxxsl",
	"bitcoincash:zr7fzmep8g7h7ymfxy74lgc0v950j3r295z4y4gq0v",
	"bchtest:qr7fzmep8g7h7ymfxy74lgc0v950j3r295pdnvy3hr",
	"bchtest:zr7fzmep8g7h7ymfxy74lgc0v950j3r295x8qj2hgs",
	"bchreg:qr7fzmep8g7h7ymfxy74lgc0v950j3r295m39d8z59",
	"bchreg:zr7fzmep8g7h7ymfxy74lgc0v950j3r295umknfytk",
	"prefix:qr7fzmep8g7h7ymfxy74lgc0v950j3r295fu6e430r",
	"prefix:zr7fzmep8g7h7ymfxy74lgc0v950j3r295wkf8mhss",
	"bitcoincash:qpagr634w55t4wp56ftxx53xukhqgl24yse53qxdge",
	"bitcoincash:zpagr634w55t4wp56ftxx53xukhqgl24ys77z7gth2",
	"bitcoincash:qq9l9e2dgkx0hp43qm3c3h252e9euugrfc6vlt3r9e",
	"bitcoincash:zq9l9e2dgkx0hp43qm3c3h252e9euugrfcaxv4l962",
	"bitcoincash:qre24q38ghy6k3pegpyvtxahu8q8hqmxmqqn28z85p",
	"bitcoincash:zre24q38ghy6k3pegpyvtxahu8q8hqmxmq8eeevptj",
	"bitcoincash:qz7xc0vl85nck65ffrsx5wvewjznp9lflgktxc5878",
	"bitcoincash:zz7xc0vl85nck65ffrsx5wvewjznp9lflg3p4x6pp5",
	"bitcoincash:ppawqn2h74a4t50phuza84kdp3794pq3ccvm92p8sh",
	"bitcoincash:rpawqn2h74a4t50phuza84kdp3794pq3cct3k50p0y",
	"bitcoincash:pqv53dwyatxse2xh7nnlqhyr6ryjgfdtagkd4vc388",
	"bitcoincash:rqv53dwyatxse2xh7nnlqhyr6ryjgfdtag38xjkhc5",
	"bitcoincash:prseh0a4aejjcewhc665wjqhppgwrz2lw5txgn666a",
	"bitcoincash:rrseh0a4aejjcewhc665wjqhppgwrz2lw5vvmd5u9w",
	"bitcoincash:pzltaslh7xnrsxeqm7qtvh0v53n3gfk0v5wwf6d7j4",
	"bitcoincash:rzltaslh7xnrsxeqm7qtvh0v53n3gfk0v5fy6yrcdx",
	"bitcoincash:pvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqpkp7fqn0",
	"bitcoincash:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqn9alsp2y",
	"bitcoincash:pdzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3jh2p5nn",
	"bitcoincash:rdzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygrpttc42c",
	"bitcoincash:pwyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsh3sujgcr",
	"bitcoincash:rwyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs9zvatfpg",
	"bitcoincash:p0xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvcm6gz4t77",
	"bitcoincash:r0xvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvcff5rv284",
	"bitcoincash:p0llllllllllllllllllllllllllllllllllllllllllllllllll7x3vthu35",
	"bitcoincash:r0llllllllllllllllllllllllllllllllllllllllllllllllll75zs2wagl",
	"bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
	"pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
}

func TestP2SH32CashAddreTestVectors(t *testing.T) {
	for _, s := range p2SH32CashAddreTestVectors {
		result := strings.Split(s, ":")
		params := &chaincfg.MainNetParams
		switch result[0] {
		case "bchtest":
			params = &chaincfg.TestNet4Params
		case "bchreg":
			params = &chaincfg.RegressionNetParams
		case "prefix", "pref":
			continue

		}
		_, err := bchutil.DecodeAddress(s, params)
		if err != nil {
			t.Error(err)
		}
	}
}

var invalidAddreTestVectors = []string{
	"bitcoincash:prseh0a4aejjcewhc665wjqhppgwrz2lw5txgn676a",
	"bitcoincash:rrseh0a4aejjcewhc665wjqhppgwrz2lw5vVmd5u9w",
	"bitcoincash:izltaslh7xnrsxeqm7qtvh0v53n3gfk0v5wwf6d7j4",
	"bitcoincash:pvqqqqqqqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqpkp7fqn0",
	"bitcoincash:rv0qqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqn9alsp2y",
}

func TestInvalidCashAddressTestVectors(t *testing.T) {
	for _, s := range invalidAddreTestVectors {
		params := &chaincfg.MainNetParams
		_, err := bchutil.DecodeAddress(s, params)
		if err == nil {
			t.Fatalf("Failed to error on invalid address string: %s", s)
		}
	}
}
