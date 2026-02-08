// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6_test

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Address.FromString / ToString
// ---------------------------------------------------------------------------

func TestAddressFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    [16]byte
		wantErr bool
	}{
		// Valid full IPv6 address.
		{
			name:  "full address lowercase",
			input: "0102:0304:0506:0708:090a:0b0c:0d0e:0f00",
			want:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00},
		},
		// Valid full address using capital letters.
		{
			name:  "full address uppercase",
			input: "0102:0304:0506:0708:090A:0B0C:0D0E:0F00",
			want:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00},
		},
		// Valid full IPv6 address with mixed capital and small letters.
		{
			name:  "mixed case",
			input: "0102:0304:0506:0708:090a:0B0C:0d0E:0F00",
			want:  [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00},
		},
		// Short prefix and full IID.
		{
			name:  "short prefix with double colon",
			input: "fd11::abcd:e0e0:d10e:0001",
			want:  [16]byte{0xfd, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xe0, 0xe0, 0xd1, 0x0e, 0x00, 0x01},
		},
		// Valid IPv6 address with unnecessary :: symbol.
		{
			name:  "unnecessary double colon",
			input: "fd11:1234:5678:abcd::abcd:e0e0:d10e:1000",
			want:  [16]byte{0xfd, 0x11, 0x12, 0x34, 0x56, 0x78, 0xab, 0xcd, 0xab, 0xcd, 0xe0, 0xe0, 0xd1, 0x0e, 0x10, 0x00},
		},
		// Short multicast address.
		{
			name:  "short multicast",
			input: "ff03::0b",
			want:  [16]byte{0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b},
		},
		// Unspecified address.
		{
			name:  "unspecified",
			input: "::",
			want:  [16]byte{},
		},
		// Starts with ::
		{
			name:  "starts with double colon",
			input: "::1:2:3:4",
			want:  [16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04},
		},
		// Ends with ::
		{
			name:  "ends with double colon",
			input: "1001:2002:3003:4004::",
			want:  [16]byte{0x10, 0x01, 0x20, 0x02, 0x30, 0x03, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		// Valid embedded IPv4 address.
		{
			name:  "embedded IPv4 NAT64",
			input: "64:ff9b::100.200.15.4",
			want:  [16]byte{0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0xc8, 0x0f, 0x04},
		},
		// Valid embedded IPv4 address.
		{
			name:  "embedded IPv4 with prefix",
			input: "2001:db8::abc:def1:127.0.0.1",
			want:  [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x0a, 0xbc, 0xde, 0xf1, 0x7f, 0x00, 0x00, 0x01},
		},
		// Valid embedded IPv4 address.
		{
			name:  "embedded IPv4 full prefix",
			input: "1:2:3:4:5:6:127.1.2.3",
			want:  [16]byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x7f, 0x01, 0x02, 0x03},
		},
		// Loopback
		{
			name:  "loopback",
			input: "::1",
			want:  [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
		},
		// Error cases
		{name: "two double colons", input: "2001:db8::a::b", wantErr: true},
		{name: "invalid hex chars", input: "2001:db8::abcd:efgh", wantErr: true},
		{name: "too many groups", input: "1:2:3:4:5:6:7:8:9", wantErr: true},
		{name: "too many hex digits", input: "2001:db8::abc:def12:1:2", wantErr: true},
		{name: "invalid embedded IPv4 byte", input: "64:ff9b::123.231.0.257", wantErr: true},
		{name: "embedded IPv4 too few octets", input: "64:ff9b::1.22.33", wantErr: true},
		{name: "embedded IPv4 too many octets", input: "64:ff9b::1.22.33.44.5", wantErr: true},
		{name: "too many groups with embedded IPv4", input: "1:2:3:4:5:6:7:127.1.2.3", wantErr: true},
		{name: "just a dot", input: ".", wantErr: true},
		{name: "colon dot", input: ":.", wantErr: true},
		{name: "double colon dot", input: "::.", wantErr: true},
		{name: "colon with embedded dots", input: ":f:0:0:c:0:f:f:.", wantErr: true},
		{name: "empty string", input: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := ip6.AddressFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AddressFromString(%q) = nil error, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("AddressFromString(%q) unexpected error: %v", tt.input, err)
			}
			if ip6.Address(tt.want) != addr {
				t.Errorf("AddressFromString(%q)\n got %v\nwant %v", tt.input, addr, tt.want)
			}
		})
	}
}

func TestAddressToString(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want string
	}{
		{
			name: "full address",
			addr: ip6.Address{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00},
			want: "102:304:506:708:90a:b0c:d0e:f00",
		},
		{
			name: "unspecified",
			addr: ip6.Address{},
			want: "0:0:0:0:0:0:0:0",
		},
		{
			name: "loopback no compression",
			addr: ip6.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "0:0:0:0:0:0:0:1",
		},
		{
			name: "link local",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "fe80:0:0:0:0:0:0:1",
		},
		{
			name: "multicast",
			addr: ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: "ff02:0:0:0:0:0:0:1",
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

func TestAddressFromStringRoundTrip(t *testing.T) {
	// Parse then ToString should give the canonical no-compression form.
	inputs := []struct {
		input string
		want  string
	}{
		{"0102:0304:0506:0708:090a:0b0c:0d0e:0f00", "102:304:506:708:90a:b0c:d0e:f00"},
		{"::", "0:0:0:0:0:0:0:0"},
		{"::1", "0:0:0:0:0:0:0:1"},
		{"fe80::1", "fe80:0:0:0:0:0:0:1"},
		{"ff02::1", "ff02:0:0:0:0:0:0:1"},
	}
	for _, tt := range inputs {
		t.Run(tt.input, func(t *testing.T) {
			addr, err := ip6.AddressFromString(tt.input)
			if err != nil {
				t.Fatalf("AddressFromString(%q): %v", tt.input, err)
			}
			got := addr.ToString()
			if got != tt.want {
				t.Errorf("round-trip %q -> %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address classification methods
// ---------------------------------------------------------------------------

func TestAddressIsUnspecified(t *testing.T) {
	var zero ip6.Address
	if !zero.IsUnspecified() {
		t.Error("zero address should be unspecified")
	}
	nonzero := ip6.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if nonzero.IsUnspecified() {
		t.Error("loopback should not be unspecified")
	}
}

func TestAddressIsLoopback(t *testing.T) {
	lb := ip6.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !lb.IsLoopback() {
		t.Error("::1 should be loopback")
	}
	var zero ip6.Address
	if zero.IsLoopback() {
		t.Error(":: should not be loopback")
	}
}

func TestAddressIsMulticast(t *testing.T) {
	mc := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !mc.IsMulticast() {
		t.Error("ff02::1 should be multicast")
	}
	notmc := ip6.Address{0xfe, 0x80}
	if notmc.IsMulticast() {
		t.Error("fe80:: should not be multicast")
	}
}

func TestAddressIsLinkLocal(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want bool
	}{
		{"fe80::1", ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, true},
		{"fe80:: (all zeros IID)", ip6.Address{0xfe, 0x80}, true},
		{"fea0::1", ip6.Address{0xfe, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, true},
		{"febf::1", ip6.Address{0xfe, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, true},
		{"fec0::1 not link-local", ip6.Address{0xfe, 0xc0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false},
		{"ff02::1 multicast", ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, false},
		{":: unspecified", ip6.Address{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.addr.IsLinkLocal(); got != tt.want {
				t.Errorf("IsLinkLocal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressIsLinkLocalMulticast(t *testing.T) {
	llmc := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !llmc.IsLinkLocalMulticast() {
		t.Error("ff02::1 should be link-local multicast")
	}
	notllmc := ip6.Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if notllmc.IsLinkLocalMulticast() {
		t.Error("ff03::1 should not be link-local multicast")
	}
}

func TestAddressIsRealmLocalMulticast(t *testing.T) {
	rlmc := ip6.Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if !rlmc.IsRealmLocalMulticast() {
		t.Error("ff03::1 should be realm-local multicast")
	}
	notrlmc := ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if notrlmc.IsRealmLocalMulticast() {
		t.Error("ff02::1 should not be realm-local multicast")
	}
}

// ---------------------------------------------------------------------------
// Address.GetScope
// ---------------------------------------------------------------------------

func TestAddressGetScope(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want uint8
	}{
		{"loopback -> node-local", ip6.Address{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 0},
		{"link-local unicast", ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 2},
		{"link-local multicast", ip6.Address{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 2},
		{"realm-local multicast", ip6.Address{0xff, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 3},
		{"global multicast", ip6.Address{0xff, 0x0e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 14},
		{"global unicast", ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.GetScope()
			if got != tt.want {
				t.Errorf("GetScope() = %d, want %d", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address.PrefixMatch
// ---------------------------------------------------------------------------

func TestAddressPrefixMatch(t *testing.T) {
	tests := []struct {
		name  string
		a, b  ip6.Address
		match uint8
	}{
		{
			name:  "identical addresses",
			a:     ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			b:     ip6.Address{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			match: 128,
		},
		{
			name:  "first bit differs",
			a:     ip6.Address{0x80},
			b:     ip6.Address{0x00},
			match: 0,
		},
		{
			name:  "64 bits match",
			a:     ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0},
			b:     ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, 0},
			match: 70, // fe80::01xx vs fe80::02xx -> 0000_0001 vs 0000_0010, 70 bits match
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.a.PrefixMatch(tt.b)
			if got != tt.match {
				t.Errorf("PrefixMatch() = %d, want %d", got, tt.match)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Address IID methods
// ---------------------------------------------------------------------------

func TestAddressGetSetIid(t *testing.T) {
	addr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	iid := addr.GetIid()
	want := ip6.InterfaceIdentifier{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	if iid != want {
		t.Errorf("GetIid() = %v, want %v", iid, want)
	}

	newIid := ip6.InterfaceIdentifier{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	addr.SetIid(newIid)
	if addr.GetIid() != newIid {
		t.Errorf("after SetIid, GetIid() = %v, want %v", addr.GetIid(), newIid)
	}
	// Prefix should be unchanged
	if addr[0] != 0xfe || addr[1] != 0x80 {
		t.Error("SetIid should not change prefix bytes")
	}
}

func TestAddressGetSetPrefix(t *testing.T) {
	addr := ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	prefix := addr.GetPrefix()
	want := ip6.NetworkPrefix{0xfe, 0x80, 0, 0, 0, 0, 0, 0}
	if prefix != want {
		t.Errorf("GetPrefix() = %v, want %v", prefix, want)
	}

	newPrefix := ip6.NetworkPrefix{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	addr.SetPrefix(newPrefix)
	if addr.GetPrefix() != newPrefix {
		t.Errorf("after SetPrefix, GetPrefix() = %v, want %v", addr.GetPrefix(), newPrefix)
	}
	// IID should be unchanged
	if addr[8] != 0x01 || addr[9] != 0x02 {
		t.Error("SetPrefix should not change IID bytes")
	}
}

// ---------------------------------------------------------------------------
// Address RLOC/ALOC classification
// ---------------------------------------------------------------------------

func TestAddressIsRoutingLocator(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want bool
	}{
		{
			name: "valid RLOC IID 0000:00ff:fe00:0400",
			// prefix fe80::, IID = 0000:00ff:fe00:0400 -> RLOC16 = 0x0400
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00},
			want: true,
		},
		{
			name: "valid RLOC IID 0000:00ff:fe00:7c00",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x7c, 0x00},
			want: true,
		},
		{
			name: "ALOC not RLOC: 0000:00ff:fe00:fc00",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00},
			want: false,
		},
		{
			name: "not locator pattern",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want: false,
		},
		{
			name: "reserved bit set: 0000:00ff:fe00:0200",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x02, 0x00},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.IsRoutingLocator()
			if got != tt.want {
				t.Errorf("IsRoutingLocator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressIsAnycastRoutingLocator(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want bool
	}{
		{
			name: "valid ALOC: 0000:00ff:fe00:fc00",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00},
			want: true,
		},
		{
			name: "valid ALOC: 0000:00ff:fe00:fcff",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0xff},
			want: true,
		},
		{
			name: "RLOC not ALOC",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00},
			want: false,
		},
		{
			name: "not locator pattern",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.IsAnycastRoutingLocator()
			if got != tt.want {
				t.Errorf("IsAnycastRoutingLocator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAddressIsIidReserved(t *testing.T) {
	tests := []struct {
		name string
		addr ip6.Address
		want bool
	}{
		{
			// Subnet-Router Anycast: IID all zeros
			name: "subnet-router anycast (all zeros IID)",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: true,
		},
		{
			// Reserved Subnet Anycast: fdff:ffff:ffff:ff80
			name: "reserved subnet anycast",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xfd, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x80},
			want: true,
		},
		{
			// ALOC is reserved
			name: "ALOC is reserved",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00},
			want: true,
		},
		{
			name: "normal IID not reserved",
			addr: ip6.Address{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.addr.IsIidReserved()
			if got != tt.want {
				t.Errorf("IsIidReserved() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// InterfaceIdentifier
// ---------------------------------------------------------------------------

func TestInterfaceIdentifierIsRoutingLocator(t *testing.T) {
	tests := []struct {
		name string
		iid  ip6.InterfaceIdentifier
		want bool
	}{
		{
			name: "valid RLOC 0x0400",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00},
			want: true,
		},
		{
			name: "ALOC not RLOC",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00},
			want: false,
		},
		{
			name: "not locator pattern",
			iid:  ip6.InterfaceIdentifier{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			want: false,
		},
		{
			name: "reserved bit set 0x0200",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x02, 0x00},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.iid.IsRoutingLocator()
			if got != tt.want {
				t.Errorf("IsRoutingLocator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInterfaceIdentifierIsAnycastLocator(t *testing.T) {
	tests := []struct {
		name string
		iid  ip6.InterfaceIdentifier
		want bool
	}{
		{
			name: "valid ALOC 0xfc00",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00},
			want: true,
		},
		{
			name: "valid ALOC 0xfcff",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0xff},
			want: true,
		},
		{
			name: "RLOC not ALOC",
			iid:  ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.iid.IsAnycastLocator()
			if got != tt.want {
				t.Errorf("IsAnycastLocator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInterfaceIdentifierGetSetLocator(t *testing.T) {
	iid := ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00}
	if got := iid.GetLocator(); got != 0x0400 {
		t.Errorf("GetLocator() = %#04x, want 0x0400", got)
	}

	iid.SetLocator(0xfc10)
	if got := iid.GetLocator(); got != 0xfc10 {
		t.Errorf("after SetLocator(0xfc10), GetLocator() = %#04x", got)
	}
}

func TestInterfaceIdentifierToString(t *testing.T) {
	iid := ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x04, 0x00}
	got := iid.ToString()
	want := "000000fffe000400"
	if got != want {
		t.Errorf("ToString() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// NetworkPrefix
// ---------------------------------------------------------------------------

func TestNetworkPrefixIsUla(t *testing.T) {
	tests := []struct {
		name   string
		prefix ip6.NetworkPrefix
		want   bool
	}{
		{"fd prefix", ip6.NetworkPrefix{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}, true},
		{"fe80 not ULA", ip6.NetworkPrefix{0xfe, 0x80}, false},
		{"fc not ULA", ip6.NetworkPrefix{0xfc, 0x00}, false},
		{"2001:db8 not ULA", ip6.NetworkPrefix{0x20, 0x01, 0x0d, 0xb8}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.prefix.IsUla()
			if got != tt.want {
				t.Errorf("IsUla() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNetworkPrefixToString(t *testing.T) {
	prefix := ip6.NetworkPrefix{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	got := prefix.ToString()
	want := "fd00123456789abc"
	if got != want {
		t.Errorf("ToString() = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// Prefix
// ---------------------------------------------------------------------------

func TestPrefixFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen uint8
		wantErr bool
	}{
		{name: "full /128", input: "::/128", wantLen: 128},
		{name: "leading zero /0128", input: "::/0128", wantLen: 128},
		{name: "/5", input: "::/5", wantLen: 5},
		{name: "/0", input: "::/0", wantLen: 0},
		{name: "fd00::/16", input: "fd00::/16", wantLen: 16},
		{name: "fe80::/10", input: "fe80::/10", wantLen: 10},
		// Error cases
		{name: "no slash", input: "::", wantErr: true},
		{name: "slash no length", input: "::/", wantErr: true},
		{name: "length too large", input: "::/129", wantErr: true},
		{name: "space before slash", input: ":: /12", wantErr: true},
		{name: "alpha in length", input: "::/a1", wantErr: true},
		{name: "trailing space", input: "::/12 ", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := ip6.PrefixFromString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("PrefixFromString(%q) = nil error, want error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("PrefixFromString(%q) unexpected error: %v", tt.input, err)
			}
			if prefix.GetLength() != tt.wantLen {
				t.Errorf("GetLength() = %d, want %d", prefix.GetLength(), tt.wantLen)
			}
		})
	}
}

func TestPrefixToString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "zero /0", input: "::/0", want: "::/0"},
		{name: "fd00 /16", input: "fd00::/16", want: "fd00::/16"},
		{name: "fe80 /10", input: "fe80::/10", want: "fe80::/10"},
		{name: "full /128", input: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", want: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
		{name: "64-bit prefix", input: "2001:db8:1234:5678::/64", want: "2001:db8:1234:5678::/64"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := ip6.PrefixFromString(tt.input)
			if err != nil {
				t.Fatalf("PrefixFromString(%q): %v", tt.input, err)
			}
			got := prefix.ToString()
			if got != tt.want {
				t.Errorf("ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPrefixClassification(t *testing.T) {
	t.Run("IsLinkLocal", func(t *testing.T) {
		tests := []struct {
			input string
			want  bool
		}{
			{"fe80::/10", true},
			{"fe80::/11", true},
			{"fea0::/16", true},
			{"fe80::/9", false},
			{"ff80::/10", false},
			{"fe00::/10", false},
			{"fec0::/10", false},
		}
		for _, tt := range tests {
			prefix, err := ip6.PrefixFromString(tt.input)
			if err != nil {
				t.Fatalf("PrefixFromString(%q): %v", tt.input, err)
			}
			if got := prefix.IsLinkLocal(); got != tt.want {
				t.Errorf("PrefixFromString(%q).IsLinkLocal() = %v, want %v", tt.input, got, tt.want)
			}
		}
	})

	t.Run("IsMulticast", func(t *testing.T) {
		tests := []struct {
			input string
			want  bool
		}{
			{"ff00::/8", true},
			{"ff80::/9", true},
			{"ffff::/16", true},
			{"ff00::/7", false},
			{"fe00::/8", false},
		}
		for _, tt := range tests {
			prefix, err := ip6.PrefixFromString(tt.input)
			if err != nil {
				t.Fatalf("PrefixFromString(%q): %v", tt.input, err)
			}
			if got := prefix.IsMulticast(); got != tt.want {
				t.Errorf("PrefixFromString(%q).IsMulticast() = %v, want %v", tt.input, got, tt.want)
			}
		}
	})

	t.Run("IsUniqueLocal", func(t *testing.T) {
		tests := []struct {
			input string
			want  bool
		}{
			{"fc00::/7", true},
			{"fd00::/8", true},
			{"fc10::/16", true},
			{"fc00::/6", false},
			{"f800::/7", false},
			{"fe00::/7", false},
		}
		for _, tt := range tests {
			prefix, err := ip6.PrefixFromString(tt.input)
			if err != nil {
				t.Fatalf("PrefixFromString(%q): %v", tt.input, err)
			}
			if got := prefix.IsUniqueLocal(); got != tt.want {
				t.Errorf("PrefixFromString(%q).IsUniqueLocal() = %v, want %v", tt.input, got, tt.want)
			}
		}
	})
}

func TestPrefixContainsPrefix(t *testing.T) {
	outer, _ := ip6.PrefixFromString("fd00::/8")
	inner, _ := ip6.PrefixFromString("fd00:1234::/32")
	if !outer.ContainsPrefix(inner) {
		t.Error("fd00::/8 should contain fd00:1234::/32")
	}
	if inner.ContainsPrefix(outer) {
		t.Error("fd00:1234::/32 should not contain fd00::/8")
	}

	// Self-containment
	if !outer.ContainsPrefix(outer) {
		t.Error("prefix should contain itself")
	}
}

func TestPrefixIsEqual(t *testing.T) {
	a, _ := ip6.PrefixFromString("fd00::/16")
	b, _ := ip6.PrefixFromString("fd00::/16")
	c, _ := ip6.PrefixFromString("fd00::/15")

	if !a.IsEqual(b) {
		t.Error("identical prefixes should be equal")
	}
	if a.IsEqual(c) {
		t.Error("different length prefixes should not be equal")
	}
}

func TestPrefixLessThan(t *testing.T) {
	tests := []struct {
		a, b string
	}{
		{"fd00::/16", "fd01::/16"},
		{"fc00::/16", "fd00::/16"},
		{"fd00::/15", "fd00::/16"},
		{"fd00::/16", "fd00:0::/32"},
		{"2001:0:0:0::/64", "fd00::/8"},
		{"2001:dba::/32", "fd12:3456:1234:abcd::/64"},
		{"910b:1000:0::/48", "910b:2000::/32"},
		{"::/0", "fd00::/8"},
		{"::/0", "::/16"},
		{"fd00:2:2::/33", "fd00:2:2::/35"},
		{"1:2:3:ffff::/62", "1:2:3:ffff::/63"},
	}

	for _, tt := range tests {
		a, _ := ip6.PrefixFromString(tt.a)
		b, _ := ip6.PrefixFromString(tt.b)
		if !a.LessThan(b) {
			t.Errorf("%s should be < %s", tt.a, tt.b)
		}
		if b.LessThan(a) {
			t.Errorf("%s should not be < %s", tt.b, tt.a)
		}
	}
}

func TestPrefixTidy(t *testing.T) {
	// Test a selection of prefix lengths with all-ones prefix bytes.
	tests := []struct {
		length uint8
		want   string
	}{
		{0, "::/0"},
		{1, "8000::/1"},
		{8, "ff00::/8"},
		{16, "ffff::/16"},
		{32, "ffff:ffff::/32"},
		{48, "ffff:ffff:ffff::/48"},
		{64, "ffff:ffff:ffff:ffff::/64"},
		{96, "ffff:ffff:ffff:ffff:ffff:ffff::/96"},
		{128, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			var allOnes [16]byte
			for i := range allOnes {
				allOnes[i] = 0xff
			}
			prefix := ip6.NewPrefix(allOnes, tt.length)
			prefix.Tidy()
			got := prefix.ToString()
			if got != tt.want {
				t.Errorf("Tidy() at length %d = %q, want %q", tt.length, got, tt.want)
			}
		})
	}
}

func TestPrefixIsValidNat64(t *testing.T) {
	valid := []uint8{32, 40, 48, 56, 64, 96}
	invalid := []uint8{0, 8, 16, 24, 72, 80, 88, 104, 112, 120, 128}

	for _, l := range valid {
		p := ip6.NewPrefix([16]byte{}, l)
		if !p.IsValidNat64() {
			t.Errorf("length %d should be valid NAT64", l)
		}
	}
	for _, l := range invalid {
		p := ip6.NewPrefix([16]byte{}, l)
		if p.IsValidNat64() {
			t.Errorf("length %d should not be valid NAT64", l)
		}
	}
}

// ---------------------------------------------------------------------------
// Prefix.FromString with address vectors (from OpenThread test)
// ---------------------------------------------------------------------------

func TestPrefixFromStringWithAddressVectors(t *testing.T) {
	// Each valid address should also parse as addr/128
	validAddresses := []struct {
		input string
		addr  [16]byte
	}{
		{
			"0102:0304:0506:0708:090a:0b0c:0d0e:0f00",
			[16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00},
		},
		{
			"fd11::abcd:e0e0:d10e:0001",
			[16]byte{0xfd, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xe0, 0xe0, 0xd1, 0x0e, 0x00, 0x01},
		},
		{
			"::",
			[16]byte{},
		},
	}

	for _, tt := range validAddresses {
		input := tt.input + "/128"
		t.Run(input, func(t *testing.T) {
			prefix, err := ip6.PrefixFromString(input)
			if err != nil {
				t.Fatalf("PrefixFromString(%q): %v", input, err)
			}
			if prefix.GetLength() != 128 {
				t.Errorf("length = %d, want 128", prefix.GetLength())
			}
			got := prefix.GetBytes()
			for i := 0; i < 16; i++ {
				if got[i] != tt.addr[i] {
					t.Errorf("byte %d: got %#02x, want %#02x", i, got[i], tt.addr[i])
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Error type check
// ---------------------------------------------------------------------------

func TestAddressFromStringReturnsErrParse(t *testing.T) {
	_, err := ip6.AddressFromString("not-an-address")
	if err == nil {
		t.Fatal("expected error")
	}
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}

func TestPrefixFromStringReturnsErrParse(t *testing.T) {
	_, err := ip6.PrefixFromString("::")
	if err == nil {
		t.Fatal("expected error")
	}
	if err != errors.ErrParse {
		t.Errorf("expected ErrParse, got %v", err)
	}
}
