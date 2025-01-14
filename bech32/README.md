bech32
==========

[![Build Status](https://github.com/gcash/bchutil/actions/workflows/main.yml/badge.svg?branch=master)](https://github.com/gcash/bchutil/actions/workflows/main.yml)
[![ISC License](http://img.shields.io/badge/license-ISC-blue.svg)](http://copyfree.org)
[![GoDoc](https://godoc.org/github.com/gcash/bchutil/bech32?status.png)](http://godoc.org/github.com/gcash/bchutil/bech32)

Package bech32 provides a Go implementation of the bech32 format specified in
[BIP 173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).

Test vectors from BIP 173 are added to ensure compatibility with the BIP.

Note this package is NOT use by the CashAddress format as that uses a different bech32 encoding.
It's left here for the sheer utility of having that package.

## Installation and Updating

```bash
$ go get -u github.com/gcash/bchutil/bech32
```

## Examples

* [Bech32 decode Example](http://godoc.org/github.com/gcash/bchutil/bech32#example-Bech32Decode)
  Demonstrates how to decode a bech32 encoded string.
* [Bech32 encode Example](http://godoc.org/github.com/gcash/bchutil/bech32#example-BechEncode)
  Demonstrates how to encode data into a bech32 string.

## License

Package bech32 is licensed under the [copyfree](http://copyfree.org) ISC
License.
