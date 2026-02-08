// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package types_test

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
)

// --- ExtAddress tests ------------------------------------------------------

func TestExtAddressGroupBit(t *testing.T) {
	tests := []struct {
		name    string
		initial byte
		set     bool
		wantBit bool
		wantB0  byte
	}{
		{"set group on zero", 0x00, true, true, 0x01},
		{"clear group on zero", 0x00, false, false, 0x00},
		{"set group when already set", 0x01, true, true, 0x01},
		{"clear group when set", 0x01, false, false, 0x00},
		{"set group preserves other bits", 0xfe, true, true, 0xff},
		{"clear group preserves other bits", 0xff, false, false, 0xfe},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr types.ExtAddress
			addr[0] = tt.initial
			addr.SetGroup(tt.set)
			if addr.IsGroup() != tt.wantBit {
				t.Errorf("IsGroup() = %v, want %v", addr.IsGroup(), tt.wantBit)
			}
			if addr[0] != tt.wantB0 {
				t.Errorf("byte[0] = 0x%02x, want 0x%02x", addr[0], tt.wantB0)
			}
		})
	}
}

func TestExtAddressLocalBit(t *testing.T) {
	tests := []struct {
		name    string
		initial byte
		set     bool
		wantBit bool
		wantB0  byte
	}{
		{"set local on zero", 0x00, true, true, 0x02},
		{"clear local on zero", 0x00, false, false, 0x00},
		{"set local when already set", 0x02, true, true, 0x02},
		{"clear local when set", 0x02, false, false, 0x00},
		{"set local preserves other bits", 0xfd, true, true, 0xff},
		{"clear local preserves other bits", 0xff, false, false, 0xfd},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr types.ExtAddress
			addr[0] = tt.initial
			addr.SetLocal(tt.set)
			if addr.IsLocal() != tt.wantBit {
				t.Errorf("IsLocal() = %v, want %v", addr.IsLocal(), tt.wantBit)
			}
			if addr[0] != tt.wantB0 {
				t.Errorf("byte[0] = 0x%02x, want 0x%02x", addr[0], tt.wantB0)
			}
		})
	}
}

func TestExtAddressToggle(t *testing.T) {
	var addr types.ExtAddress

	// Toggle group
	if addr.IsGroup() {
		t.Error("zero value should not have group bit set")
	}
	addr.ToggleGroup()
	if !addr.IsGroup() {
		t.Error("ToggleGroup should set group bit")
	}
	addr.ToggleGroup()
	if addr.IsGroup() {
		t.Error("second ToggleGroup should clear group bit")
	}

	// Toggle local
	if addr.IsLocal() {
		t.Error("zero value should not have local bit set")
	}
	addr.ToggleLocal()
	if !addr.IsLocal() {
		t.Error("ToggleLocal should set local bit")
	}
	addr.ToggleLocal()
	if addr.IsLocal() {
		t.Error("second ToggleLocal should clear local bit")
	}
}

func TestExtAddressCopyToNormal(t *testing.T) {
	// Test vector from OpenThread: {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	addr := types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	dst := make([]byte, types.ExtAddressSize)

	addr.CopyTo(dst, types.NormalByteOrder)
	for i, b := range addr {
		if dst[i] != b {
			t.Fatalf("CopyTo NormalByteOrder: dst[%d]=0x%02x, want 0x%02x", i, dst[i], b)
		}
	}
}

func TestExtAddressCopyToReverse(t *testing.T) {
	addr := types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	dst := make([]byte, types.ExtAddressSize)

	addr.CopyTo(dst, types.ReverseByteOrder)
	for i := range types.ExtAddressSize {
		want := addr[types.ExtAddressSize-1-i]
		if dst[i] != want {
			t.Fatalf("CopyTo ReverseByteOrder: dst[%d]=0x%02x, want 0x%02x", i, dst[i], want)
		}
	}
}

func TestExtAddressSetReverse(t *testing.T) {
	// From OpenThread test: set with reverse byte order, then verify reversed.
	src := []byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	var addr types.ExtAddress
	addr.Set(src, types.ReverseByteOrder)

	for i := range types.ExtAddressSize {
		want := src[types.ExtAddressSize-1-i]
		if addr[i] != want {
			t.Fatalf("Set ReverseByteOrder: addr[%d]=0x%02x, want 0x%02x", i, addr[i], want)
		}
	}
}

func TestExtAddressToString(t *testing.T) {
	tests := []struct {
		name string
		addr types.ExtAddress
		want string
	}{
		{
			"known pattern",
			types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
			"123456789abcdef0",
		},
		{
			"all zeros",
			types.ExtAddress{},
			"0000000000000000",
		},
		{
			"all ff",
			types.ExtAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			"ffffffffffffffff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.ToString()
			if got != tt.want {
				t.Errorf("ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- ShortAddress tests ----------------------------------------------------

func TestShortAddressConstants(t *testing.T) {
	if types.BroadcastAddress != 0xffff {
		t.Errorf("BroadcastAddress = 0x%04x, want 0xffff", types.BroadcastAddress)
	}
	if types.ShortAddressInvalid != 0xfffe {
		t.Errorf("ShortAddressInvalid = 0x%04x, want 0xfffe", types.ShortAddressInvalid)
	}
}

func TestShortAddressToString(t *testing.T) {
	tests := []struct {
		name string
		addr types.ShortAddress
		want string
	}{
		{"broadcast", types.BroadcastAddress, "0xffff"},
		{"invalid", types.ShortAddressInvalid, "0xfffe"},
		{"known", types.ShortAddress(0x1234), "0x1234"},
		{"zero", types.ShortAddress(0), "0x0000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.ToString()
			if got != tt.want {
				t.Errorf("ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- PanId tests -----------------------------------------------------------

func TestPanIDBroadcast(t *testing.T) {
	if types.BroadcastPanID != 0xffff {
		t.Errorf("BroadcastPanID = 0x%04x, want 0xffff", types.BroadcastPanID)
	}
}

// --- Address (tagged union) tests ------------------------------------------

func TestAddressZeroValue(t *testing.T) {
	var addr types.Address
	if !addr.IsNone() {
		t.Error("zero value Address should be None")
	}
	if addr.IsShort() {
		t.Error("zero value Address should not be Short")
	}
	if addr.IsExtended() {
		t.Error("zero value Address should not be Extended")
	}
	if addr.GetType() != types.AddressTypeNone {
		t.Errorf("GetType() = %v, want AddressTypeNone", addr.GetType())
	}
}

func TestAddressSetShort(t *testing.T) {
	var addr types.Address
	addr.SetShort(0x1234)

	if addr.GetType() != types.AddressTypeShort {
		t.Fatalf("GetType() = %v, want AddressTypeShort", addr.GetType())
	}
	if !addr.IsShort() {
		t.Error("should be Short after SetShort")
	}
	if addr.IsExtended() {
		t.Error("should not be Extended after SetShort")
	}
	if addr.GetShort() != 0x1234 {
		t.Errorf("GetShort() = 0x%04x, want 0x1234", addr.GetShort())
	}
}

func TestAddressSetExtended(t *testing.T) {
	ext := types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0}
	var addr types.Address
	addr.SetExtended(ext)

	if addr.GetType() != types.AddressTypeExtended {
		t.Fatalf("GetType() = %v, want AddressTypeExtended", addr.GetType())
	}
	if !addr.IsExtended() {
		t.Error("should be Extended after SetExtended")
	}
	if addr.IsShort() {
		t.Error("should not be Short after SetExtended")
	}
	if addr.GetExtended() != ext {
		t.Errorf("GetExtended() = %v, want %v", addr.GetExtended(), ext)
	}
}

func TestAddressSetNone(t *testing.T) {
	var addr types.Address
	addr.SetShort(0x1234)
	addr.SetNone()

	if addr.GetType() != types.AddressTypeNone {
		t.Fatalf("GetType() = %v, want AddressTypeNone", addr.GetType())
	}
	if !addr.IsNone() {
		t.Error("should be None after SetNone")
	}
	if addr.IsShort() {
		t.Error("should not be Short after SetNone")
	}
	if addr.IsExtended() {
		t.Error("should not be Extended after SetNone")
	}
}

func TestAddressIsBroadcast(t *testing.T) {
	// Directly from OpenThread test vectors.
	tests := []struct {
		name string
		fn   func(a *types.Address)
		want bool
	}{
		{"none", func(a *types.Address) { a.SetNone() }, false},
		{"extended", func(a *types.Address) {
			a.SetExtended(types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0})
		}, false},
		{"short 0x1234", func(a *types.Address) { a.SetShort(0x1234) }, false},
		{"short broadcast", func(a *types.Address) { a.SetShort(types.BroadcastAddress) }, true},
		{"short invalid", func(a *types.Address) { a.SetShort(types.ShortAddressInvalid) }, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr types.Address
			tt.fn(&addr)
			if addr.IsBroadcast() != tt.want {
				t.Errorf("IsBroadcast() = %v, want %v", addr.IsBroadcast(), tt.want)
			}
		})
	}
}

func TestAddressIsShortAddrInvalid(t *testing.T) {
	tests := []struct {
		name string
		fn   func(a *types.Address)
		want bool
	}{
		{"none", func(a *types.Address) { a.SetNone() }, false},
		{"extended", func(a *types.Address) {
			a.SetExtended(types.ExtAddress{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0})
		}, false},
		{"short 0x1234", func(a *types.Address) { a.SetShort(0x1234) }, false},
		{"short broadcast", func(a *types.Address) { a.SetShort(types.BroadcastAddress) }, false},
		{"short invalid", func(a *types.Address) { a.SetShort(types.ShortAddressInvalid) }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr types.Address
			tt.fn(&addr)
			if addr.IsShortAddrInvalid() != tt.want {
				t.Errorf("IsShortAddrInvalid() = %v, want %v", addr.IsShortAddrInvalid(), tt.want)
			}
		})
	}
}

func TestAddressEqual(t *testing.T) {
	tests := []struct {
		name  string
		setup [2]func(a *types.Address)
		want  bool
	}{
		{
			"none==none",
			[2]func(a *types.Address){
				func(_ *types.Address) {},
				func(_ *types.Address) {},
			},
			true,
		},
		{
			"short==short same",
			[2]func(a *types.Address){
				func(a *types.Address) { a.SetShort(0x1234) },
				func(a *types.Address) { a.SetShort(0x1234) },
			},
			true,
		},
		{
			"short!=short different",
			[2]func(a *types.Address){
				func(a *types.Address) { a.SetShort(0x1234) },
				func(a *types.Address) { a.SetShort(0x5678) },
			},
			false,
		},
		{
			"extended==extended same",
			[2]func(a *types.Address){
				func(a *types.Address) {
					a.SetExtended(types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8})
				},
				func(a *types.Address) {
					a.SetExtended(types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8})
				},
			},
			true,
		},
		{
			"extended!=extended different",
			[2]func(a *types.Address){
				func(a *types.Address) {
					a.SetExtended(types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8})
				},
				func(a *types.Address) {
					a.SetExtended(types.ExtAddress{8, 7, 6, 5, 4, 3, 2, 1})
				},
			},
			false,
		},
		{
			"short!=none",
			[2]func(a *types.Address){
				func(a *types.Address) { a.SetShort(0x1234) },
				func(_ *types.Address) {},
			},
			false,
		},
		{
			"short!=extended",
			[2]func(a *types.Address){
				func(a *types.Address) { a.SetShort(0x1234) },
				func(a *types.Address) {
					a.SetExtended(types.ExtAddress{1, 2, 3, 4, 5, 6, 7, 8})
				},
			},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var a, b types.Address
			tt.setup[0](&a)
			tt.setup[1](&b)
			if a.Equal(&b) != tt.want {
				t.Errorf("Equal() = %v, want %v", a.Equal(&b), tt.want)
			}
		})
	}
}

func TestAddressToString(t *testing.T) {
	tests := []struct {
		name  string
		setup func(a *types.Address)
		want  string
	}{
		{"none", func(_ *types.Address) {}, "None"},
		{"short", func(a *types.Address) { a.SetShort(0x1234) }, "0x1234"},
		{"extended", func(a *types.Address) {
			a.SetExtended(types.ExtAddress{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11})
		}, "aabbccddeeff0011"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var addr types.Address
			tt.setup(&addr)
			if got := addr.ToString(); got != tt.want {
				t.Errorf("ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Key tests -------------------------------------------------------------

func TestKeySize(t *testing.T) {
	if types.KeySize != 16 {
		t.Errorf("KeySize = %d, want 16", types.KeySize)
	}
	var k types.Key
	if len(k) != 16 {
		t.Errorf("len(Key{}) = %d, want 16", len(k))
	}
}

func TestKeyZeroValue(t *testing.T) {
	var k types.Key
	for i, b := range k {
		if b != 0 {
			t.Fatalf("zero value Key[%d] = 0x%02x, want 0x00", i, b)
		}
	}
}

// --- KeyMaterial tests -----------------------------------------------------

func TestKeyMaterialGetSet(t *testing.T) {
	var km types.KeyMaterial
	k := types.Key{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	km.SetKey(k)
	got := km.GetKey()
	if got != k {
		t.Errorf("GetKey() = %v, want %v", got, k)
	}
}

func TestKeyMaterialClear(t *testing.T) {
	var km types.KeyMaterial
	km.SetKey(types.Key{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	km.Clear()

	var zero types.Key
	if km.GetKey() != zero {
		t.Errorf("after Clear(), GetKey() = %v, want zero", km.GetKey())
	}
}

// --- ByteOrder tests -------------------------------------------------------

func TestByteOrderConstants(t *testing.T) {
	if types.NormalByteOrder != 0 {
		t.Errorf("NormalByteOrder = %d, want 0", types.NormalByteOrder)
	}
	if types.ReverseByteOrder != 1 {
		t.Errorf("ReverseByteOrder = %d, want 1", types.ReverseByteOrder)
	}
}
