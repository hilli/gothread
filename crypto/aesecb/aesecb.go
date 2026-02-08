// Package aesecb provides AES-128-ECB single-block encryption.
//
// This is a thin wrapper around Go's crypto/aes providing the same API surface
// as OpenThread's AesEcb class.
//
// Reference: openthread/src/core/crypto/aes_ecb.hpp
package aesecb

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// BlockSize is the AES-128 block size in bytes.
const BlockSize = 16

// AesEcb performs AES-128-ECB single-block encryption.
type AesEcb struct {
	block cipher.Block
}

// SetKey sets the 16-byte AES-128 key.
func (a *AesEcb) SetKey(key []byte) error {
	if len(key) != BlockSize {
		return fmt.Errorf("aesecb: invalid key size %d, must be %d", len(key), BlockSize)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	a.block = block
	return nil
}

// Encrypt encrypts a single 16-byte block. Input and output must be exactly
// BlockSize bytes. In-place operation (input == output) is supported.
//
// Encrypt panics if input or output is not exactly BlockSize bytes, matching
// the behavior of crypto/aes.
func (a *AesEcb) Encrypt(input, output []byte) {
	if len(input) < BlockSize {
		panic("aesecb: input not full block")
	}
	if len(output) < BlockSize {
		panic("aesecb: output not full block")
	}

	a.block.Encrypt(output, input)
}
