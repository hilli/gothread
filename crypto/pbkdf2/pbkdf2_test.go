package pbkdf2

import (
	"bytes"
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

// RFC 4493 Section 4 test vectors for AES-CMAC.
func TestAesCmac(t *testing.T) {
	key := mustHex("2b7e151628aed2a6abf7158809cf4f3c")

	tests := []struct {
		name string
		msg  string // hex
		cmac string // hex
	}{
		{
			name: "EmptyMessage",
			msg:  "",
			cmac: "bb1d6929e95937287fa37d129b756746",
		},
		{
			name: "16Bytes",
			msg:  "6bc1bee22e409f96e93d7e117393172a",
			cmac: "070a16b46b4d4144f79bdd9dd04a287c",
		},
		{
			name: "40Bytes",
			msg:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
			cmac: "dfa66747de9ae63030ca32611497c827",
		},
		{
			name: "64Bytes",
			msg:  "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
			cmac: "51f0bebf7e3b9d92fc49741779363cfe",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := mustHex(tc.msg)
			want := mustHex(tc.cmac)

			got := aesCmac(key, msg)
			if !bytes.Equal(got[:], want) {
				t.Errorf("got  %x\nwant %x", got[:], want)
			}
		})
	}
}

func TestGenerateKeyBasic(t *testing.T) {
	password := []byte("commissioning-passphrase")
	salt := []byte("Thread-NetworkName-0001")
	iterations := 16384
	keyLen := 16

	key, err := GenerateKey(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != keyLen {
		t.Errorf("key length = %d, want %d", len(key), keyLen)
	}
}

func TestGenerateKeyDeterministic(t *testing.T) {
	password := []byte("test-passphrase")
	salt := []byte("test-salt")
	iterations := 1000
	keyLen := 16

	key1, err := GenerateKey(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (1): %v", err)
	}

	key2, err := GenerateKey(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (2): %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Errorf("same inputs produced different keys\nkey1: %x\nkey2: %x", key1, key2)
	}
}

func TestGenerateKeyDifferentSalts(t *testing.T) {
	password := []byte("passphrase")
	iterations := 1000
	keyLen := 16

	key1, err := GenerateKey(password, []byte("salt-one"), iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (salt-one): %v", err)
	}

	key2, err := GenerateKey(password, []byte("salt-two"), iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (salt-two): %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Errorf("different salts produced identical keys: %x", key1)
	}
}

func TestGenerateKeyDifferentPasswords(t *testing.T) {
	salt := []byte("shared-salt")
	iterations := 1000
	keyLen := 16

	key1, err := GenerateKey([]byte("password-one"), salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (password-one): %v", err)
	}

	key2, err := GenerateKey([]byte("password-two"), salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey (password-two): %v", err)
	}

	if bytes.Equal(key1, key2) {
		t.Errorf("different passwords produced identical keys: %x", key1)
	}
}

func TestGenerateKeyInvalidIterations(t *testing.T) {
	password := []byte("test")
	salt := []byte("salt")

	for _, iter := range []int{0, -1, 3, 7, 101} {
		_, err := GenerateKey(password, salt, iter, 16)
		if err == nil {
			t.Errorf("GenerateKey accepted iterations=%d, want error", iter)
		}
	}
}

func TestGenerateKeyInvalidKeyLen(t *testing.T) {
	_, err := GenerateKey([]byte("test"), []byte("salt"), 2, 0)
	if err == nil {
		t.Error("GenerateKey accepted keyLen=0, want error")
	}

	_, err = GenerateKey([]byte("test"), []byte("salt"), 2, -1)
	if err == nil {
		t.Error("GenerateKey accepted keyLen=-1, want error")
	}
}

func TestGenerateKeyMultiBlock(t *testing.T) {
	// Request more than 16 bytes to exercise multi-block derivation.
	password := []byte("multi-block-test")
	salt := []byte("salt-value")
	iterations := 100
	keyLen := 32

	key, err := GenerateKey(password, salt, iterations, keyLen)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(key) != keyLen {
		t.Errorf("key length = %d, want %d", len(key), keyLen)
	}

	// Verify the two halves differ (different block indices produce different output).
	if bytes.Equal(key[:16], key[16:]) {
		t.Error("first and second blocks are identical, expected different values")
	}
}
