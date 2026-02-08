// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package ip6

import "testing"

func TestSockAddrIsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr SockAddr
		want bool
	}{
		{"zero value", SockAddr{}, true},
		{"port only", SockAddr{Port: 1234}, false},
		{"address only", SockAddr{Address: Address{0: 0xfe, 1: 0x80}}, false},
		{"both set", SockAddr{Address: Address{0: 0xfe, 1: 0x80}, Port: 80}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.addr.IsEmpty(); got != tt.want {
				t.Errorf("SockAddr.IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSockAddrEqual(t *testing.T) {
	t.Parallel()

	a := SockAddr{Address: Address{15: 1}, Port: 1000}
	b := SockAddr{Address: Address{15: 1}, Port: 1000}
	c := SockAddr{Address: Address{15: 2}, Port: 1000}
	d := SockAddr{Address: Address{15: 1}, Port: 2000}

	if !a.Equal(b) {
		t.Error("identical SockAddrs should be equal")
	}
	if a.Equal(c) {
		t.Error("different address should not be equal")
	}
	if a.Equal(d) {
		t.Error("different port should not be equal")
	}
}

func TestSockAddrToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr SockAddr
		want string
	}{
		{
			"zero",
			SockAddr{},
			"[0:0:0:0:0:0:0:0]:0",
		},
		{
			"loopback port 80",
			SockAddr{
				Address: Address{0: 0, 1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0,
					8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: 0, 14: 0, 15: 1},
				Port: 80,
			},
			"[0:0:0:0:0:0:0:1]:80",
		},
		{
			"link-local port 5683",
			SockAddr{
				Address: Address{0: 0xfe, 1: 0x80, 14: 0x00, 15: 0x01},
				Port:    5683,
			},
			"[fe80:0:0:0:0:0:0:1]:5683",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.addr.ToString(); got != tt.want {
				t.Errorf("SockAddr.ToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMessageInfoHasSamePeerAddrAndPort(t *testing.T) {
	t.Parallel()

	mi1 := &MessageInfo{PeerAddr: Address{15: 1}, PeerPort: 5683}
	mi2 := &MessageInfo{PeerAddr: Address{15: 1}, PeerPort: 5683}
	mi3 := &MessageInfo{PeerAddr: Address{15: 2}, PeerPort: 5683}
	mi4 := &MessageInfo{PeerAddr: Address{15: 1}, PeerPort: 9999}

	if !mi1.HasSamePeerAddrAndPort(mi2) {
		t.Error("identical peer addr+port should match")
	}
	if mi1.HasSamePeerAddrAndPort(mi3) {
		t.Error("different peer addr should not match")
	}
	if mi1.HasSamePeerAddrAndPort(mi4) {
		t.Error("different peer port should not match")
	}
}

func TestMessageInfoGetSockSockAddr(t *testing.T) {
	t.Parallel()

	mi := &MessageInfo{
		SockAddr: Address{0: 0xfe, 1: 0x80, 15: 0x01},
		SockPort: 1234,
	}

	sa := mi.GetSockSockAddr()
	if sa.Address != mi.SockAddr {
		t.Error("GetSockSockAddr address mismatch")
	}
	if sa.Port != mi.SockPort {
		t.Error("GetSockSockAddr port mismatch")
	}
}

func TestMessageInfoGetPeerSockAddr(t *testing.T) {
	t.Parallel()

	mi := &MessageInfo{
		PeerAddr: Address{0: 0x20, 1: 0x01, 15: 0x02},
		PeerPort: 5683,
	}

	sa := mi.GetPeerSockAddr()
	if sa.Address != mi.PeerAddr {
		t.Error("GetPeerSockAddr address mismatch")
	}
	if sa.Port != mi.PeerPort {
		t.Error("GetPeerSockAddr port mismatch")
	}
}

func TestMessageInfoDefaults(t *testing.T) {
	t.Parallel()

	var mi MessageInfo
	if mi.HopLimit != 0 {
		t.Error("default HopLimit should be 0")
	}
	if mi.Ecn != EcnNotCapable {
		t.Error("default Ecn should be EcnNotCapable")
	}
	if mi.MulticastLoop {
		t.Error("default MulticastLoop should be false")
	}
	if mi.IsHostInterface {
		t.Error("default IsHostInterface should be false")
	}
	if mi.AllowZeroHopLimit {
		t.Error("default AllowZeroHopLimit should be false")
	}
}
