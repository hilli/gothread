// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netif

import "testing"

func TestNetIf_UpDown(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	if n.IsUp() {
		t.Error("new NetIf should be down")
	}

	n.Up()
	if !n.IsUp() {
		t.Error("NetIf should be up after Up()")
	}

	n.Down()
	if n.IsUp() {
		t.Error("NetIf should be down after Down()")
	}
}

func TestNetIf_MeshLocalPrefix(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	prefix := [8]byte{0xFD, 0x00, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00}
	n.SetMeshLocalPrefix(prefix)

	if got := n.GetMeshLocalPrefix(); got != prefix {
		t.Errorf("GetMeshLocalPrefix() = %v, want %v", got, prefix)
	}
}

func TestNetIf_Rloc16(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	n.SetRloc16(0x0400)
	if got := n.GetRloc16(); got != 0x0400 {
		t.Errorf("GetRloc16() = 0x%04X, want 0x0400", got)
	}
}

func TestNetIf_GetRloc(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	prefix := [8]byte{0xFD, 0x00, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00}
	n.SetMeshLocalPrefix(prefix)
	n.SetRloc16(0x0401)

	rloc := n.GetRloc()

	// First 8 bytes = prefix.
	for i := 0; i < 8; i++ {
		if rloc[i] != prefix[i] {
			t.Errorf("RLOC[%d] = 0x%02X, want 0x%02X", i, rloc[i], prefix[i])
		}
	}

	// Bytes 8-13: 00:00:00:FF:FE:00
	expected := []byte{0x00, 0x00, 0x00, 0xFF, 0xFE, 0x00}
	for i, exp := range expected {
		if rloc[8+i] != exp {
			t.Errorf("RLOC[%d] = 0x%02X, want 0x%02X", 8+i, rloc[8+i], exp)
		}
	}

	// Bytes 14-15: RLOC16 in big-endian.
	if rloc[14] != 0x04 || rloc[15] != 0x01 {
		t.Errorf("RLOC16 bytes = [0x%02X, 0x%02X], want [0x04, 0x01]", rloc[14], rloc[15])
	}
}

func TestNetIf_GetLinkLocalAddress(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	lla := n.GetLinkLocalAddress()
	if lla[0] != 0xFE || lla[1] != 0x80 {
		t.Errorf("link-local prefix = [0x%02X, 0x%02X], want [0xFE, 0x80]", lla[0], lla[1])
	}
}

func TestNetIf_UnicastAddresses(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	addr1 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	addr2 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}

	if !n.AddUnicastAddress(addr1) {
		t.Error("AddUnicastAddress(addr1) should return true")
	}
	if !n.AddUnicastAddress(addr2) {
		t.Error("AddUnicastAddress(addr2) should return true")
	}

	// Duplicate should fail.
	if n.AddUnicastAddress(addr1) {
		t.Error("duplicate AddUnicastAddress should return false")
	}

	if !n.HasUnicastAddress(addr1) {
		t.Error("HasUnicastAddress(addr1) should be true")
	}
	if n.GetUnicastAddressCount() != 2 {
		t.Errorf("GetUnicastAddressCount() = %d, want 2", n.GetUnicastAddressCount())
	}

	if !n.RemoveUnicastAddress(addr1) {
		t.Error("RemoveUnicastAddress(addr1) should return true")
	}
	if n.HasUnicastAddress(addr1) {
		t.Error("HasUnicastAddress(addr1) should be false after removal")
	}
	if n.GetUnicastAddressCount() != 1 {
		t.Errorf("GetUnicastAddressCount() = %d, want 1", n.GetUnicastAddressCount())
	}

	// Remove non-existent.
	if n.RemoveUnicastAddress(addr1) {
		t.Error("RemoveUnicastAddress of non-existent should return false")
	}
}

func TestNetIf_UnicastFull(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	for i := 0; i < MaxUnicastAddresses; i++ {
		addr := [16]byte{byte(i)}
		if !n.AddUnicastAddress(addr) {
			t.Fatalf("AddUnicastAddress(%d) should succeed", i)
		}
	}

	overflow := [16]byte{0xFF}
	if n.AddUnicastAddress(overflow) {
		t.Error("AddUnicastAddress should fail when table is full")
	}
}

func TestNetIf_MulticastAddresses(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	addr := [16]byte{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	if !n.AddMulticastAddress(addr) {
		t.Error("AddMulticastAddress should return true")
	}
	if n.AddMulticastAddress(addr) {
		t.Error("duplicate AddMulticastAddress should return false")
	}
	if n.GetMulticastAddressCount() != 1 {
		t.Errorf("GetMulticastAddressCount() = %d, want 1", n.GetMulticastAddressCount())
	}

	if !n.RemoveMulticastAddress(addr) {
		t.Error("RemoveMulticastAddress should return true")
	}
	if n.GetMulticastAddressCount() != 0 {
		t.Errorf("GetMulticastAddressCount() = %d, want 0 after removal", n.GetMulticastAddressCount())
	}
}

func TestNetIf_MulticastFull(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	for i := 0; i < MaxMulticastAddresses; i++ {
		addr := [16]byte{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i)}
		if !n.AddMulticastAddress(addr) {
			t.Fatalf("AddMulticastAddress(%d) should succeed", i)
		}
	}

	overflow := [16]byte{0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF}
	if n.AddMulticastAddress(overflow) {
		t.Error("AddMulticastAddress should fail when table is full")
	}
}

func TestNetIf_AllRoutersMulticast(t *testing.T) {
	t.Parallel()

	var n NetIf
	n.Init()

	if n.IsSubscribedAllRoutersMulticast() {
		t.Error("should not be subscribed initially")
	}

	n.SubscribeAllRoutersMulticast()
	if !n.IsSubscribedAllRoutersMulticast() {
		t.Error("should be subscribed after SubscribeAllRoutersMulticast")
	}

	n.UnsubscribeAllRoutersMulticast()
	if n.IsSubscribedAllRoutersMulticast() {
		t.Error("should not be subscribed after UnsubscribeAllRoutersMulticast")
	}
}
