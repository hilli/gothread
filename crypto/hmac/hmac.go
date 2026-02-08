// Package hmac provides HMAC-SHA-256 with an incremental API matching
// OpenThread's HmacSha256 class.
//
// Reference: openthread/src/core/crypto/hmac_sha256.hpp
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// HashSize is the HMAC-SHA-256 output size in bytes.
const HashSize = 32

// Hash is a 32-byte HMAC-SHA-256 output.
type Hash [HashSize]byte

// Sha256 computes HMAC-SHA-256 incrementally.
type Sha256 struct {
	h hash.Hash
}

// Start begins a new HMAC computation with the given key.
func (h *Sha256) Start(key []byte) {
	h.h = hmac.New(sha256.New, key)
}

// Update feeds data into the HMAC computation.
func (h *Sha256) Update(data []byte) {
	h.h.Write(data)
}

// Finish completes the HMAC computation and writes the result to hash.
func (h *Sha256) Finish(hash *Hash) {
	sum := h.h.Sum(nil)
	copy(hash[:], sum)
}

// Sum is a convenience function that computes HMAC-SHA-256 in one call.
func Sum(key, data []byte) Hash {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	var out Hash
	copy(out[:], mac.Sum(nil))
	return out
}
