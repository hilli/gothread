package ecdsa

import (
	"bytes"
	"errors"
	"testing"
)

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func TestQualifiedReaderGenerationAndSigning(t *testing.T) {
	scalar := [32]byte{31: 7}
	key, err := GenerateKeyPairWithReader(bytes.NewReader(scalar[:]))
	if err != nil {
		t.Fatal(err)
	}
	if key.PrivateScalar() != scalar {
		t.Fatal("key generation ignored provided entropy")
	}
	exported := key.PrivateScalar()
	restored, err := NewKeyPairFromScalar(exported[:])
	if err != nil || restored.GetPublicKey() != key.GetPublicKey() {
		t.Fatal("strict scalar restoration changed identity")
	}
	hash := [32]byte{1, 2, 3}
	entropy := bytes.NewReader(bytes.Repeat([]byte{0x42}, 4096))
	signature, err := key.SignWithReader(hash, entropy)
	if err != nil {
		t.Fatal(err)
	}
	public := key.GetPublicKey()
	if err := public.Verify(hash, signature); err != nil || entropy.Len() == 4096 {
		t.Fatal("signature did not validate/use provided entropy")
	}
	failure := errors.New("qualified source failed")
	if _, err := key.SignWithReader(hash, errorReader{failure}); !errors.Is(err, failure) {
		t.Fatalf("signing entropy failure hidden: %v", err)
	}
	if _, err := GenerateKeyPairWithReader(errorReader{failure}); !errors.Is(err, failure) {
		t.Fatalf("generation entropy failure hidden: %v", err)
	}
}

func TestStrictScalarAndBoundedBrokenEntropy(t *testing.T) {
	for _, invalid := range [][]byte{nil, make([]byte, 31), make([]byte, 32), bytes.Repeat([]byte{0xff}, 32)} {
		if _, err := NewKeyPairFromScalar(invalid); err == nil {
			t.Fatal("invalid secret scalar accepted")
		}
	}
	reader := bytes.NewReader(make([]byte, 128*32+1))
	if _, err := GenerateKeyPairWithReader(reader); err == nil || reader.Len() != 1 {
		t.Fatal("invalid entropy was not bounded to 128 samples")
	}
}
