package mle

import (
	"bytes"
	"testing"
)

func TestMLEFullSequenceHeaderLiteral(t *testing.T) {
	// Full 32-bit sequence is BIG endian, counter LITTLE endian, index is
	// (sequence & 0x7f)+1. The seven-bit index does not identify the epoch.
	want := []byte{0x15, 0x04, 0x03, 0x02, 0x01, 0, 0, 0x12, 0x34, 0x35}
	header := NewSecurityHeader(0x1234, 0x01020304)
	wire := header.Marshal()
	if !bytes.Equal(wire[:], want) {
		t.Fatalf("inner MLE header differs from literal: % x", wire)
	}
	var decoded SecurityHeader
	if err := decoded.Unmarshal(want); err != nil || decoded.KeySource != 0x1234 || decoded.KeyIndex != 0x35 {
		t.Fatal("literal full sequence lost")
	}
}
