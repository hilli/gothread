package aesccm

import (
	"bytes"
	"testing"
)

// IEEE 802.15.4-2006 Annex C test vectors (from OpenThread test_aes.cpp).

func TestMacBeaconFrame(t *testing.T) {
	key := []byte{
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	}
	nonce := []byte{
		0xac, 0xde, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x05, 0x02,
	}
	header := []byte{
		0x08, 0xd0, 0x84, 0x21, 0x43, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x48, 0xde, 0xac, 0x02, 0x05, 0x00,
		0x00, 0x00, 0x55, 0xcf, 0x00, 0x00, 0x51, 0x52,
		0x53, 0x54,
	}
	expectedTag := []byte{0x22, 0x3b, 0xc1, 0xec, 0x84, 0x1a, 0xb5, 0x53}

	var c AesCcm
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, err := c.Seal(nonce, nil, header, 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != 0 {
		t.Fatalf("expected empty ciphertext, got %d bytes", len(ciphertext))
	}
	if !bytes.Equal(tag, expectedTag) {
		t.Fatalf("tag mismatch\n  got:  %x\n  want: %x", tag, expectedTag)
	}
}

func TestMacCommandFrame(t *testing.T) {
	key := []byte{
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	}
	nonce := []byte{
		0xac, 0xde, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x05, 0x06,
	}
	header := []byte{
		0x2b, 0xdc, 0x84, 0x21, 0x43, 0x02, 0x00, 0x00,
		0x00, 0x00, 0x48, 0xde, 0xac, 0xff, 0xff, 0x01,
		0x00, 0x00, 0x00, 0x00, 0x48, 0xde, 0xac, 0x06,
		0x05, 0x00, 0x00, 0x00, 0x01,
	}
	plaintext := []byte{0xce}
	expectedCiphertext := []byte{0xd8}
	expectedTag := []byte{0x4f, 0xde, 0x52, 0x90, 0x61, 0xf9, 0xc6, 0xf1}

	var c AesCcm
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}

	// Encrypt.
	ciphertext, tag, err := c.Seal(nonce, plaintext, header, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ciphertext, expectedCiphertext) {
		t.Fatalf("ciphertext mismatch\n  got:  %x\n  want: %x", ciphertext, expectedCiphertext)
	}
	if !bytes.Equal(tag, expectedTag) {
		t.Fatalf("tag mismatch\n  got:  %x\n  want: %x", tag, expectedTag)
	}

	// Decrypt and verify.
	recovered, err := c.Open(nonce, ciphertext, header, tag)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("plaintext mismatch\n  got:  %x\n  want: %x", recovered, plaintext)
	}
}

func TestRoundTrip(t *testing.T) {
	key := []byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	}
	nonce := []byte{
		0xac, 0xde, 0x48, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x05, 0x06,
	}
	const (
		tagLen    = 4
		headerLen = 19
	)

	// Generate a header.
	header := make([]byte, headerLen)
	for i := range header {
		header[i] = byte(i)
	}

	for _, msgLen := range []int{30, 400, 800} {
		t.Run("", func(t *testing.T) {
			// Generate payload: for i := msgLen; i > 0; i-- { payload[msgLen-i] = byte(i & 0xff) }
			payload := make([]byte, msgLen)
			for i := msgLen; i > 0; i-- {
				payload[msgLen-i] = byte(i & 0xff)
			}

			var c AesCcm
			if err := c.SetKey(key); err != nil {
				t.Fatal(err)
			}

			ciphertext, tag, err := c.Seal(nonce, payload, header, tagLen)
			if err != nil {
				t.Fatal(err)
			}
			if len(ciphertext) != msgLen {
				t.Fatalf("ciphertext length %d, want %d", len(ciphertext), msgLen)
			}
			if len(tag) != tagLen {
				t.Fatalf("tag length %d, want %d", len(tag), tagLen)
			}

			// Ciphertext should differ from plaintext (unless extremely unlikely).
			if msgLen > 0 && bytes.Equal(ciphertext, payload) {
				t.Fatal("ciphertext equals plaintext")
			}

			recovered, err := c.Open(nonce, ciphertext, header, tag)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recovered, payload) {
				t.Fatalf("round-trip failed for msgLen=%d", msgLen)
			}
		})
	}
}

func TestInvalidTagLength(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, NonceSize)

	var c AesCcm
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		tagLen int
	}{
		{"odd", 5},
		{"too_small", 2},
		{"too_large", 18},
		{"zero", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := c.Seal(nonce, nil, nil, tt.tagLen)
			if err == nil {
				t.Fatalf("expected error for tagLen=%d", tt.tagLen)
			}
		})
	}
}

func TestInvalidNonceLength(t *testing.T) {
	key := make([]byte, 16)

	var c AesCcm
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}

	for _, nonceLen := range []int{0, 7, 12, 14, 16} {
		t.Run("", func(t *testing.T) {
			nonce := make([]byte, nonceLen)
			_, _, err := c.Seal(nonce, nil, nil, 8)
			if err == nil {
				t.Fatalf("expected error for nonceLen=%d", nonceLen)
			}
		})
	}
}

func TestAuthenticationFailure(t *testing.T) {
	key := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(i + 0x10)
	}
	header := []byte{0x01, 0x02, 0x03}
	plaintext := []byte{0xaa, 0xbb, 0xcc, 0xdd}

	var c AesCcm
	if err := c.SetKey(key); err != nil {
		t.Fatal(err)
	}

	ciphertext, tag, err := c.Seal(nonce, plaintext, header, 8)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("tampered_ciphertext", func(t *testing.T) {
		bad := make([]byte, len(ciphertext))
		copy(bad, ciphertext)
		bad[0] ^= 0xff

		_, err := c.Open(nonce, bad, header, tag)
		if err != ErrAuth {
			t.Fatalf("expected ErrAuth, got %v", err)
		}
	})

	t.Run("tampered_tag", func(t *testing.T) {
		bad := make([]byte, len(tag))
		copy(bad, tag)
		bad[0] ^= 0xff

		_, err := c.Open(nonce, ciphertext, header, bad)
		if err != ErrAuth {
			t.Fatalf("expected ErrAuth, got %v", err)
		}
	})

	t.Run("tampered_header", func(t *testing.T) {
		badHeader := []byte{0x01, 0x02, 0x04} // changed last byte

		_, err := c.Open(nonce, ciphertext, badHeader, tag)
		if err != ErrAuth {
			t.Fatalf("expected ErrAuth, got %v", err)
		}
	})
}
