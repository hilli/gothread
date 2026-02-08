package hkdf

import (
	"encoding/hex"
	"testing"
)

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test vectors from RFC 5869 and OpenThread test_hkdf_sha256.cpp.
var hkdfTests = []struct {
	name      string
	ikm       []byte
	salt      []byte // nil means no salt
	info      []byte // nil means no info
	outputLen int
	okm       string // hex-encoded expected output
}{
	{
		name:      "RFC5869_A1",
		ikm:       mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
		salt:      mustHex("000102030405060708090a0b0c"),
		info:      mustHex("f0f1f2f3f4f5f6f7f8f9"),
		outputLen: 42,
		okm:       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
	},
	{
		name:      "RFC5869_A2",
		ikm:       mustHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"),
		salt:      mustHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
		info:      mustHex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
		outputLen: 82,
		okm:       "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87",
	},
	{
		name:      "RFC5869_A3_NilSaltAndInfo",
		ikm:       mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
		salt:      nil,
		info:      nil,
		outputLen: 42,
		okm:       "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
	},
	{
		name:      "OpenThread_Custom",
		ikm:       mustHex("68656c6c6f"),
		salt:      mustHex("8e94ef805b93e683ff18"),
		info:      nil,
		outputLen: 16,
		okm:       "13485067e21af17c0900f70d885f0259",
	},
}

func TestSha256Vectors(t *testing.T) {
	for _, tt := range hkdfTests {
		t.Run(tt.name, func(t *testing.T) {
			var h Sha256
			h.Extract(tt.salt, tt.ikm)

			okm, err := h.Expand(tt.info, tt.outputLen)
			if err != nil {
				t.Fatalf("Expand: %v", err)
			}

			got := hex.EncodeToString(okm)
			if got != tt.okm {
				t.Errorf("OKM mismatch\n got: %s\nwant: %s", got, tt.okm)
			}
		})
	}
}

func TestNilSaltAndInfo(t *testing.T) {
	// RFC 5869 Test Case 3: both salt and info are nil.
	var h Sha256
	h.Extract(nil, mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))

	okm, err := h.Expand(nil, 42)
	if err != nil {
		t.Fatalf("Expand: %v", err)
	}

	want := "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
	got := hex.EncodeToString(okm)
	if got != want {
		t.Errorf("OKM mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestExtractExpandSeparately(t *testing.T) {
	// Verify the two-phase API: Extract stores the PRK, Expand uses it.
	ikm := mustHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex("000102030405060708090a0b0c")

	var h Sha256
	h.Extract(salt, ikm)

	// First Expand with one info context.
	info1 := mustHex("f0f1f2f3f4f5f6f7f8f9")
	okm1, err := h.Expand(info1, 42)
	if err != nil {
		t.Fatalf("Expand(info1): %v", err)
	}
	want1 := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if hex.EncodeToString(okm1) != want1 {
		t.Errorf("Expand(info1) mismatch\n got: %s\nwant: %s", hex.EncodeToString(okm1), want1)
	}

	// Second Expand with the same PRK but different info should produce
	// different output, demonstrating that the PRK is reusable.
	info2 := []byte("different-context")
	okm2, err := h.Expand(info2, 32)
	if err != nil {
		t.Fatalf("Expand(info2): %v", err)
	}
	if hex.EncodeToString(okm2) == hex.EncodeToString(okm1[:32]) {
		t.Error("Expand with different info produced the same output")
	}
}

func TestExpandWithoutExtract(t *testing.T) {
	var h Sha256
	_, err := h.Expand(nil, 32)
	if err == nil {
		t.Error("Expand without Extract should return an error")
	}
}
