// Copyright (c) 2024 the bchd developers.

package bchutil

import (
	"crypto/sha256"
)

// Hash256 calculates the hash sha256(sha256(b)).
func Hash256(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), sha256.New())
}
