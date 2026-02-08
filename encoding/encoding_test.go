// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package encoding

import (
	"math"
	"testing"
)

// --- Big-endian Read/Write round-trip tests ---

func TestBigEndianReadWriteUint16(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		bytes []byte
	}{
		{"zero", 0x0000, []byte{0x00, 0x00}},
		{"one", 0x0001, []byte{0x00, 0x01}},
		{"max", 0xFFFF, []byte{0xFF, 0xFF}},
		{"known pattern", 0x0102, []byte{0x01, 0x02}},
		{"high byte only", 0xFF00, []byte{0xFF, 0x00}},
		{"low byte only", 0x00FF, []byte{0x00, 0xFF}},
		{"byte boundary", 0x80FF, []byte{0x80, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Read
			got := BigEndianReadUint16(tt.bytes)
			if got != tt.value {
				t.Errorf("BigEndianReadUint16(%#v) = %#04x, want %#04x", tt.bytes, got, tt.value)
			}

			// Test Write
			buf := make([]byte, 2)
			BigEndianWriteUint16(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("BigEndianWriteUint16(%#04x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestBigEndianReadWriteUint24(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		bytes []byte
	}{
		{"zero", 0x000000, []byte{0x00, 0x00, 0x00}},
		{"one", 0x000001, []byte{0x00, 0x00, 0x01}},
		{"max 24-bit", 0xFFFFFF, []byte{0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x010203, []byte{0x01, 0x02, 0x03}},
		{"high byte only", 0xFF0000, []byte{0xFF, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BigEndianReadUint24(tt.bytes)
			if got != tt.value {
				t.Errorf("BigEndianReadUint24(%#v) = %#06x, want %#06x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 3)
			BigEndianWriteUint24(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("BigEndianWriteUint24(%#06x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestBigEndianReadWriteUint32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		bytes []byte
	}{
		{"zero", 0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{"one", 0x00000001, []byte{0x00, 0x00, 0x00, 0x01}},
		{"max", 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x01020304, []byte{0x01, 0x02, 0x03, 0x04}},
		{"high byte only", 0xFF000000, []byte{0xFF, 0x00, 0x00, 0x00}},
		{"low byte only", 0x000000FF, []byte{0x00, 0x00, 0x00, 0xFF}},
		{"alternating", 0xAABBCCDD, []byte{0xAA, 0xBB, 0xCC, 0xDD}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BigEndianReadUint32(tt.bytes)
			if got != tt.value {
				t.Errorf("BigEndianReadUint32(%#v) = %#08x, want %#08x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 4)
			BigEndianWriteUint32(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("BigEndianWriteUint32(%#08x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestBigEndianReadWriteUint64(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		bytes []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}},
		{"max", math.MaxUint64, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x0102030405060708, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"high byte only", 0xFF00000000000000, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"low byte only", 0x00000000000000FF, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BigEndianReadUint64(tt.bytes)
			if got != tt.value {
				t.Errorf("BigEndianReadUint64(%#v) = %#016x, want %#016x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 8)
			BigEndianWriteUint64(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("BigEndianWriteUint64(%#016x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

// --- Little-endian Read/Write round-trip tests ---

func TestLittleEndianReadWriteUint16(t *testing.T) {
	tests := []struct {
		name  string
		value uint16
		bytes []byte
	}{
		{"zero", 0x0000, []byte{0x00, 0x00}},
		{"one", 0x0001, []byte{0x01, 0x00}},
		{"max", 0xFFFF, []byte{0xFF, 0xFF}},
		{"known pattern", 0x0201, []byte{0x01, 0x02}},
		{"high byte set", 0xFF00, []byte{0x00, 0xFF}},
		{"low byte set", 0x00FF, []byte{0xFF, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LittleEndianReadUint16(tt.bytes)
			if got != tt.value {
				t.Errorf("LittleEndianReadUint16(%#v) = %#04x, want %#04x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 2)
			LittleEndianWriteUint16(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("LittleEndianWriteUint16(%#04x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestLittleEndianReadWriteUint24(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		bytes []byte
	}{
		{"zero", 0x000000, []byte{0x00, 0x00, 0x00}},
		{"one", 0x000001, []byte{0x01, 0x00, 0x00}},
		{"max 24-bit", 0xFFFFFF, []byte{0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x030201, []byte{0x01, 0x02, 0x03}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LittleEndianReadUint24(tt.bytes)
			if got != tt.value {
				t.Errorf("LittleEndianReadUint24(%#v) = %#06x, want %#06x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 3)
			LittleEndianWriteUint24(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("LittleEndianWriteUint24(%#06x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestLittleEndianReadWriteUint32(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		bytes []byte
	}{
		{"zero", 0x00000000, []byte{0x00, 0x00, 0x00, 0x00}},
		{"one", 0x00000001, []byte{0x01, 0x00, 0x00, 0x00}},
		{"max", 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x04030201, []byte{0x01, 0x02, 0x03, 0x04}},
		{"high byte only", 0xFF000000, []byte{0x00, 0x00, 0x00, 0xFF}},
		{"low byte only", 0x000000FF, []byte{0xFF, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LittleEndianReadUint32(tt.bytes)
			if got != tt.value {
				t.Errorf("LittleEndianReadUint32(%#v) = %#08x, want %#08x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 4)
			LittleEndianWriteUint32(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("LittleEndianWriteUint32(%#08x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

func TestLittleEndianReadWriteUint64(t *testing.T) {
	tests := []struct {
		name  string
		value uint64
		bytes []byte
	}{
		{"zero", 0, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"one", 1, []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		{"max", math.MaxUint64, []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		{"known pattern", 0x0807060504030201, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}},
		{"high byte only", 0xFF00000000000000, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF}},
		{"low byte only", 0x00000000000000FF, []byte{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := LittleEndianReadUint64(tt.bytes)
			if got != tt.value {
				t.Errorf("LittleEndianReadUint64(%#v) = %#016x, want %#016x", tt.bytes, got, tt.value)
			}

			buf := make([]byte, 8)
			LittleEndianWriteUint64(tt.value, buf)
			for i := range tt.bytes {
				if buf[i] != tt.bytes[i] {
					t.Errorf("LittleEndianWriteUint64(%#016x) = %#v, want %#v", tt.value, buf, tt.bytes)
					break
				}
			}
		})
	}
}

// --- Swap tests ---

func TestSwap16(t *testing.T) {
	tests := []struct {
		name string
		in   uint16
		want uint16
	}{
		{"zero", 0x0000, 0x0000},
		{"max", 0xFFFF, 0xFFFF},
		{"swap bytes", 0x0102, 0x0201},
		{"high byte", 0xFF00, 0x00FF},
		{"low byte", 0x00FF, 0xFF00},
		{"double swap is identity", 0xABCD, 0xCDAB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Swap16(tt.in)
			if got != tt.want {
				t.Errorf("Swap16(%#04x) = %#04x, want %#04x", tt.in, got, tt.want)
			}
		})
	}
}

func TestSwap16DoubleSwapIdentity(t *testing.T) {
	values := []uint16{0, 1, 0x0102, 0xABCD, 0xFFFF}
	for _, v := range values {
		if Swap16(Swap16(v)) != v {
			t.Errorf("Swap16(Swap16(%#04x)) != %#04x", v, v)
		}
	}
}

func TestSwap32(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want uint32
	}{
		{"zero", 0x00000000, 0x00000000},
		{"max", 0xFFFFFFFF, 0xFFFFFFFF},
		{"swap bytes", 0x01020304, 0x04030201},
		{"high byte", 0xFF000000, 0x000000FF},
		{"low byte", 0x000000FF, 0xFF000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Swap32(tt.in)
			if got != tt.want {
				t.Errorf("Swap32(%#08x) = %#08x, want %#08x", tt.in, got, tt.want)
			}
		})
	}
}

func TestSwap32DoubleSwapIdentity(t *testing.T) {
	values := []uint32{0, 1, 0x01020304, 0xAABBCCDD, 0xFFFFFFFF}
	for _, v := range values {
		if Swap32(Swap32(v)) != v {
			t.Errorf("Swap32(Swap32(%#08x)) != %#08x", v, v)
		}
	}
}

func TestSwap64(t *testing.T) {
	tests := []struct {
		name string
		in   uint64
		want uint64
	}{
		{"zero", 0, 0},
		{"max", math.MaxUint64, math.MaxUint64},
		{"swap bytes", 0x0102030405060708, 0x0807060504030201},
		{"high byte", 0xFF00000000000000, 0x00000000000000FF},
		{"low byte", 0x00000000000000FF, 0xFF00000000000000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Swap64(tt.in)
			if got != tt.want {
				t.Errorf("Swap64(%#016x) = %#016x, want %#016x", tt.in, got, tt.want)
			}
		})
	}
}

func TestSwap64DoubleSwapIdentity(t *testing.T) {
	values := []uint64{0, 1, 0x0102030405060708, math.MaxUint64}
	for _, v := range values {
		if Swap64(Swap64(v)) != v {
			t.Errorf("Swap64(Swap64(%#016x)) != %#016x", v, v)
		}
	}
}

// --- Reverse32 (bit-reversal) tests ---

func TestReverse32(t *testing.T) {
	tests := []struct {
		name string
		in   uint32
		want uint32
	}{
		{"zero", 0x00000000, 0x00000000},
		{"max", 0xFFFFFFFF, 0xFFFFFFFF},
		{"bit 0 set", 0x00000001, 0x80000000},
		{"bit 31 set", 0x80000000, 0x00000001},
		{"alternating", 0xAAAAAAAA, 0x55555555},
		{"known value", 0x01020304, 0x20C04080},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Reverse32(tt.in)
			if got != tt.want {
				t.Errorf("Reverse32(%#08x) = %#08x, want %#08x", tt.in, got, tt.want)
			}
		})
	}
}

func TestReverse32DoubleReverseIdentity(t *testing.T) {
	values := []uint32{0, 1, 0x01020304, 0xAABBCCDD, 0xFFFFFFFF, 0x80000000}
	for _, v := range values {
		if Reverse32(Reverse32(v)) != v {
			t.Errorf("Reverse32(Reverse32(%#08x)) != %#08x", v, v)
		}
	}
}

// --- Cross-endian consistency: same bytes produce expected different values ---

func TestCrossEndianConsistency(t *testing.T) {
	buf := []byte{0x01, 0x02}
	bigVal := BigEndianReadUint16(buf)
	littleVal := LittleEndianReadUint16(buf)

	if bigVal != 0x0102 {
		t.Errorf("BigEndianReadUint16({0x01, 0x02}) = %#04x, want 0x0102", bigVal)
	}
	if littleVal != 0x0201 {
		t.Errorf("LittleEndianReadUint16({0x01, 0x02}) = %#04x, want 0x0201", littleVal)
	}

	buf32 := []byte{0x01, 0x02, 0x03, 0x04}
	bigVal32 := BigEndianReadUint32(buf32)
	littleVal32 := LittleEndianReadUint32(buf32)

	if bigVal32 != 0x01020304 {
		t.Errorf("BigEndianReadUint32({0x01,0x02,0x03,0x04}) = %#08x, want 0x01020304", bigVal32)
	}
	if littleVal32 != 0x04030201 {
		t.Errorf("LittleEndianReadUint32({0x01,0x02,0x03,0x04}) = %#08x, want 0x04030201", littleVal32)
	}

	buf64 := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	bigVal64 := BigEndianReadUint64(buf64)
	littleVal64 := LittleEndianReadUint64(buf64)

	if bigVal64 != 0x0102030405060708 {
		t.Errorf("BigEndianReadUint64 = %#016x, want 0x0102030405060708", bigVal64)
	}
	if littleVal64 != 0x0807060504030201 {
		t.Errorf("LittleEndianReadUint64 = %#016x, want 0x0807060504030201", littleVal64)
	}
}

// --- Write/Read round-trip: write then read back should yield the original value ---

func TestBigEndianRoundTrip(t *testing.T) {
	var buf [8]byte

	BigEndianWriteUint16(0xCAFE, buf[:2])
	if v := BigEndianReadUint16(buf[:2]); v != 0xCAFE {
		t.Errorf("uint16 round-trip: got %#04x, want 0xCAFE", v)
	}

	BigEndianWriteUint32(0xDEADBEEF, buf[:4])
	if v := BigEndianReadUint32(buf[:4]); v != 0xDEADBEEF {
		t.Errorf("uint32 round-trip: got %#08x, want 0xDEADBEEF", v)
	}

	BigEndianWriteUint64(0x0123456789ABCDEF, buf[:8])
	if v := BigEndianReadUint64(buf[:8]); v != 0x0123456789ABCDEF {
		t.Errorf("uint64 round-trip: got %#016x, want 0x0123456789ABCDEF", v)
	}
}

func TestLittleEndianRoundTrip(t *testing.T) {
	var buf [8]byte

	LittleEndianWriteUint16(0xCAFE, buf[:2])
	if v := LittleEndianReadUint16(buf[:2]); v != 0xCAFE {
		t.Errorf("uint16 round-trip: got %#04x, want 0xCAFE", v)
	}

	LittleEndianWriteUint32(0xDEADBEEF, buf[:4])
	if v := LittleEndianReadUint32(buf[:4]); v != 0xDEADBEEF {
		t.Errorf("uint32 round-trip: got %#08x, want 0xDEADBEEF", v)
	}

	LittleEndianWriteUint64(0x0123456789ABCDEF, buf[:8])
	if v := LittleEndianReadUint64(buf[:8]); v != 0x0123456789ABCDEF {
		t.Errorf("uint64 round-trip: got %#016x, want 0x0123456789ABCDEF", v)
	}
}
