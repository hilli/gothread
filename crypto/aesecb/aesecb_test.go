package aesecb

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// NIST FIPS 197 Appendix B test vector.
var (
	nistKey        = mustHex("2b7e151628aed2a6abf7158809cf4f3c")
	nistPlaintext  = mustHex("3243f6a8885a308d313198a2e0370734")
	nistCiphertext = mustHex("3925841d02dc09fbdc118597196a0b32")
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestEncryptNISTVector(t *testing.T) {
	var ecb AesEcb
	if err := ecb.SetKey(nistKey); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	output := make([]byte, BlockSize)
	ecb.Encrypt(nistPlaintext, output)

	if !bytes.Equal(output, nistCiphertext) {
		t.Errorf("ciphertext mismatch\ngot:  %x\nwant: %x", output, nistCiphertext)
	}
}

func TestEncryptInPlace(t *testing.T) {
	var ecb AesEcb
	if err := ecb.SetKey(nistKey); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	buf := make([]byte, BlockSize)
	copy(buf, nistPlaintext)

	ecb.Encrypt(buf, buf)

	if !bytes.Equal(buf, nistCiphertext) {
		t.Errorf("in-place ciphertext mismatch\ngot:  %x\nwant: %x", buf, nistCiphertext)
	}
}

func TestSetKeyInvalidLength(t *testing.T) {
	var ecb AesEcb

	for _, size := range []int{0, 1, 8, 15, 17, 24, 32} {
		key := make([]byte, size)
		if err := ecb.SetKey(key); err == nil {
			t.Errorf("SetKey accepted %d-byte key, want error", size)
		}
	}
}

func TestEncryptMultipleBlocks(t *testing.T) {
	var ecb AesEcb
	if err := ecb.SetKey(nistKey); err != nil {
		t.Fatalf("SetKey: %v", err)
	}

	// Encrypt the NIST plaintext, then encrypt the resulting ciphertext again.
	// Each block is encrypted independently.
	first := make([]byte, BlockSize)
	ecb.Encrypt(nistPlaintext, first)

	if !bytes.Equal(first, nistCiphertext) {
		t.Fatalf("first encryption mismatch\ngot:  %x\nwant: %x", first, nistCiphertext)
	}

	second := make([]byte, BlockSize)
	ecb.Encrypt(first, second)

	// Encrypting the same input again must produce the same output (deterministic).
	second2 := make([]byte, BlockSize)
	ecb.Encrypt(first, second2)

	if !bytes.Equal(second, second2) {
		t.Errorf("sequential encryption not deterministic\nfirst:  %x\nsecond: %x", second, second2)
	}

	// The second encryption must differ from the first (different plaintext).
	if bytes.Equal(first, second) {
		t.Error("encrypting different plaintexts produced identical ciphertexts")
	}
}
