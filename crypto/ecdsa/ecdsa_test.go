package ecdsa

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

// DER-encoded key pair from RFC 6979 Section A.2.5 (SEC1 ECPrivateKey format).
const knownDERHex = "30770201010420" +
	"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721" +
	"A00A06082A8648CE3D030107A144034200" +
	"0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
	"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"

// Expected public key bytes (x || y).
const knownPubKeyHex = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6" +
	"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"

func loadKnownKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	der, err := hex.DecodeString(knownDERHex)
	if err != nil {
		t.Fatalf("decode DER hex: %v", err)
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		t.Fatalf("parse EC private key: %v", err)
	}
	kp, err := NewKeyPairFromPrivateKey(priv)
	if err != nil {
		t.Fatalf("new key pair: %v", err)
	}
	return kp
}

func TestGenerateAndVerify(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	hash := sha256.Sum256([]byte("test message"))
	sig, err := kp.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk := kp.GetPublicKey()
	if err := pk.Verify(hash, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsWrongHash(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	hash1 := sha256.Sum256([]byte("message one"))
	hash2 := sha256.Sum256([]byte("message two"))

	sig, err := kp.Sign(hash1)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk := kp.GetPublicKey()
	if err := pk.Verify(hash2, sig); err == nil {
		t.Fatal("expected verification to fail with wrong hash")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	kp1, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (1): %v", err)
	}
	kp2, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair (2): %v", err)
	}

	hash := sha256.Sum256([]byte("shared message"))
	sig, err := kp1.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk2 := kp2.GetPublicKey()
	if err := pk2.Verify(hash, sig); err == nil {
		t.Fatal("expected verification to fail with wrong public key")
	}
}

func TestPublicKeyFromKnownKeyPair(t *testing.T) {
	kp := loadKnownKeyPair(t)
	pk := kp.GetPublicKey()

	expected, err := hex.DecodeString(knownPubKeyHex)
	if err != nil {
		t.Fatalf("decode expected pub key hex: %v", err)
	}

	if len(expected) != PublicKeySize {
		t.Fatalf("expected public key size %d, got %d", PublicKeySize, len(expected))
	}

	for i := range pk {
		if pk[i] != expected[i] {
			t.Fatalf("public key mismatch at byte %d: got %02x, want %02x", i, pk[i], expected[i])
		}
	}
}

func TestSignAndVerifyWithKnownKey(t *testing.T) {
	kp := loadKnownKeyPair(t)

	hash := sha256.Sum256([]byte("sample"))
	sig, err := kp.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pk := kp.GetPublicKey()
	if err := pk.Verify(hash, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	hash := sha256.Sum256([]byte("round trip test"))
	sig, err := kp.Sign(hash)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Extract public key bytes and reconstruct via Verify.
	pk := kp.GetPublicKey()

	// Create a new PublicKey from the raw bytes to simulate round-trip.
	var pk2 PublicKey
	copy(pk2[:], pk[:])

	if err := pk2.Verify(hash, sig); err != nil {
		t.Fatalf("Verify after round trip: %v", err)
	}
}
