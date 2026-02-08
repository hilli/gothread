// Package sha256 provides SHA-256 hashing with an incremental API matching
// OpenThread's Sha256 class.
//
// Reference: openthread/src/core/crypto/sha256.hpp
package sha256

import (
	"crypto/sha256"
	"hash"
)

// HashSize is the SHA-256 output size in bytes.
const HashSize = 32

// Hash is a 32-byte SHA-256 hash value.
type Hash [HashSize]byte

// Sha256 computes SHA-256 hashes incrementally.
type Sha256 struct {
	h hash.Hash
}

// Start begins a new hash computation, resetting any previous state.
func (s *Sha256) Start() {
	s.h = sha256.New()
}

// Update feeds data into the hash computation.
func (s *Sha256) Update(data []byte) {
	s.h.Write(data)
}

// Finish completes the hash computation and writes the result to h.
func (s *Sha256) Finish(h *Hash) {
	sum := s.h.Sum(nil)
	copy(h[:], sum)
}

// Sum256 is a convenience function that computes the SHA-256 hash of data in
// one call.
func Sum256(data []byte) Hash {
	return Hash(sha256.Sum256(data))
}
