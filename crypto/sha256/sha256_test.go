package sha256

import (
	"encoding/hex"
	"testing"
)

// NIST standard test vectors (from OpenThread test_hmac_sha256.cpp, TestSha256).
var sha256Tests = []struct {
	input string
	hash  string // hex-encoded 32-byte hash
}{
	{"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	{"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
	{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
}

func TestSha256Vectors(t *testing.T) {
	for _, tt := range sha256Tests {
		t.Run(tt.input, func(t *testing.T) {
			var s Sha256
			s.Start()
			s.Update([]byte(tt.input))

			var h Hash
			s.Finish(&h)

			got := hex.EncodeToString(h[:])
			if got != tt.hash {
				t.Errorf("Sha256(%q) = %s, want %s", tt.input, got, tt.hash)
			}
		})
	}
}

func TestSum256Convenience(t *testing.T) {
	for _, tt := range sha256Tests {
		t.Run(tt.input, func(t *testing.T) {
			h := Sum256([]byte(tt.input))
			got := hex.EncodeToString(h[:])
			if got != tt.hash {
				t.Errorf("Sum256(%q) = %s, want %s", tt.input, got, tt.hash)
			}
		})
	}
}

func TestIncrementalUpdate(t *testing.T) {
	input := "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
	want := "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

	var s Sha256
	s.Start()

	// Feed one byte at a time.
	for i := range len(input) {
		s.Update([]byte{input[i]})
	}

	var h Hash
	s.Finish(&h)

	got := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("incremental Update = %s, want %s", got, want)
	}
}

func TestStartResets(t *testing.T) {
	var s Sha256

	// Partial hash of "abc".
	s.Start()
	s.Update([]byte("abc"))

	// Reset and hash empty string instead.
	s.Start()

	var h Hash
	s.Finish(&h)

	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	got := hex.EncodeToString(h[:])
	if got != want {
		t.Errorf("after Start reset = %s, want %s (empty hash)", got, want)
	}
}
