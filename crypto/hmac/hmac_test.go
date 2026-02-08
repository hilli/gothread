package hmac

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// RFC 4231 test vectors (matching OpenThread test_hmac_sha256.cpp).
var testVectors = []struct {
	name string
	key  string // hex
	data string // hex
	hash string // hex
}{
	{
		name: "RFC4231_TC2",
		key:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		data: "4869205468657265",
		hash: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
	},
	{
		name: "RFC4231_TC3",
		key:  "4a656665",
		data: "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
		hash: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
	},
	{
		name: "RFC4231_TC4",
		key:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		data: hex.EncodeToString(bytes.Repeat([]byte{0xdd}, 50)),
		hash: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
	},
	{
		name: "RFC4231_TC5",
		key:  "0102030405060708090a0b0c0d0e0f10111213141516171819",
		data: hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 50)),
		hash: "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b",
	},
	{
		name: "RFC4231_TC7",
		key:  hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 131)),
		data: hex.EncodeToString([]byte("This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.")),
		hash: "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
	},
}

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestSha256Vectors(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustDecode(tc.key)
			data := mustDecode(tc.data)
			want := mustDecode(tc.hash)

			var h Sha256
			h.Start(key)
			h.Update(data)

			var got Hash
			h.Finish(&got)

			if !bytes.Equal(got[:], want) {
				t.Errorf("got  %x\nwant %x", got[:], want)
			}
		})
	}
}

func TestSumConvenience(t *testing.T) {
	for _, tc := range testVectors {
		t.Run(tc.name, func(t *testing.T) {
			key := mustDecode(tc.key)
			data := mustDecode(tc.data)
			want := mustDecode(tc.hash)

			got := Sum(key, data)

			if !bytes.Equal(got[:], want) {
				t.Errorf("got  %x\nwant %x", got[:], want)
			}
		})
	}
}

func TestIncrementalUpdate(t *testing.T) {
	// Use RFC4231_TC3: key="Jefe", data="what do ya want for nothing?"
	key := mustDecode("4a656665")
	data := []byte("what do ya want for nothing?")
	want := mustDecode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

	var h Sha256
	h.Start(key)

	// Feed data one byte at a time.
	for i := range data {
		h.Update(data[i : i+1])
	}

	var got Hash
	h.Finish(&got)

	if !bytes.Equal(got[:], want) {
		t.Errorf("got  %x\nwant %x", got[:], want)
	}
}

func TestStartResets(t *testing.T) {
	key1 := mustDecode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	key2 := mustDecode("4a656665")
	want := mustDecode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")

	var h Sha256

	// Start with a different key and feed some data.
	h.Start(key1)
	h.Update([]byte("garbage that should be discarded"))

	// Restart with the real key; previous state must be gone.
	h.Start(key2)
	h.Update([]byte("what do ya want for nothing?"))

	var got Hash
	h.Finish(&got)

	if !bytes.Equal(got[:], want) {
		t.Errorf("Start did not reset state\ngot  %x\nwant %x", got[:], want)
	}
}
