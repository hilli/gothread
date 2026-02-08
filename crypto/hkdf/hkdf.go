// Package hkdf provides HKDF-SHA-256 (RFC 5869) with a two-phase Extract/Expand
// API matching OpenThread's HkdfSha256 class.
//
// Reference: openthread/src/core/crypto/hkdf_sha256.hpp
package hkdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
)

// Sha256 implements HKDF using SHA-256 as the hash function.
type Sha256 struct {
	prk []byte
}

// Extract performs the HKDF-Extract step. salt can be nil.
func (h *Sha256) Extract(salt, inputKey []byte) {
	prk, _ := hkdf.Extract(sha256.New, inputKey, salt)
	h.prk = prk
}

// Expand performs the HKDF-Expand step.
// info can be nil. outputLen is the desired output key length.
func (h *Sha256) Expand(info []byte, outputLen int) ([]byte, error) {
	if h.prk == nil {
		return nil, errors.New("hkdf: Extract must be called before Expand")
	}
	return hkdf.Expand(sha256.New, h.prk, string(info), outputLen)
}
