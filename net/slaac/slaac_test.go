// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package slaac

import (
	"encoding/hex"
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testSecretKey returns a deterministic 32-byte secret key for tests.
func testSecretKey() [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = byte(i + 1)
	}
	return k
}

// testExtAddr returns a deterministic 8-byte extended address for tests.
func testExtAddr() [8]byte {
	return [8]byte{0x18, 0xb4, 0x30, 0x00, 0x00, 0x00, 0x00, 0x01}
}

// slaacPrefix creates a Prefix with OnMesh+Slaac flags.
func slaacPrefix(addrHex string, length uint8) Prefix {
	b, _ := hex.DecodeString(addrHex)
	var addr [16]byte
	copy(addr[:], b)
	return Prefix{
		Prefix: addr,
		Length: length,
		Flags:  FlagOnMesh | FlagSlaac,
	}
}

// dhcpPrefix creates a Prefix with OnMesh+DHCP flags (no SLAAC).
func dhcpPrefix(addrHex string, length uint8) Prefix {
	b, _ := hex.DecodeString(addrHex)
	var addr [16]byte
	copy(addr[:], b)
	return Prefix{
		Prefix: addr,
		Length: length,
		Flags:  FlagOnMesh | FlagDhcp,
	}
}

// newTestManager creates a manager with the default IID generator and
// default options.
func newTestManager() *Manager {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())
	return NewManager(gen)
}

// ---------------------------------------------------------------------------
// DefaultIIDGenerator tests
// ---------------------------------------------------------------------------

func TestDefaultIIDGenerator_Deterministic(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())

	prefix := slaacPrefix("fd001122334455660000000000000000", 64)
	iid1, err := gen.GenerateIID(prefix.Prefix, prefix.Length, 0)
	if err != nil {
		t.Fatalf("GenerateIID failed: %v", err)
	}
	iid2, err := gen.GenerateIID(prefix.Prefix, prefix.Length, 0)
	if err != nil {
		t.Fatalf("GenerateIID failed: %v", err)
	}
	if iid1 != iid2 {
		t.Errorf("IIDs not deterministic: %x vs %x", iid1, iid2)
	}
}

func TestDefaultIIDGenerator_UniversalLocalBit(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())

	prefix := slaacPrefix("fd001122334455660000000000000000", 64)
	iid, err := gen.GenerateIID(prefix.Prefix, prefix.Length, 0)
	if err != nil {
		t.Fatalf("GenerateIID failed: %v", err)
	}
	// Bit 6 (0x02) should be cleared in the first byte.
	if iid[0]&0x02 != 0 {
		t.Errorf("universal/local bit not cleared: first byte = 0x%02x", iid[0])
	}
}

func TestDefaultIIDGenerator_DADCounterChangesIID(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())

	prefix := slaacPrefix("fd001122334455660000000000000000", 64)
	iid0, _ := gen.GenerateIID(prefix.Prefix, prefix.Length, 0)
	iid1, _ := gen.GenerateIID(prefix.Prefix, prefix.Length, 1)
	iid2, _ := gen.GenerateIID(prefix.Prefix, prefix.Length, 2)

	if iid0 == iid1 || iid0 == iid2 || iid1 == iid2 {
		t.Errorf("different DAD counters should produce different IIDs: %x, %x, %x",
			iid0, iid1, iid2)
	}
}

func TestDefaultIIDGenerator_DifferentPrefixes(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())

	p1 := slaacPrefix("fd001122334455660000000000000000", 64)
	p2 := slaacPrefix("fd00aabbccdd00000000000000000000", 64)

	iid1, _ := gen.GenerateIID(p1.Prefix, p1.Length, 0)
	iid2, _ := gen.GenerateIID(p2.Prefix, p2.Length, 0)

	if iid1 == iid2 {
		t.Errorf("different prefixes should produce different IIDs: %x vs %x", iid1, iid2)
	}
}

func TestDefaultIIDGenerator_DifferentKeys(t *testing.T) {
	key1 := testSecretKey()
	var key2 [32]byte
	for i := range key2 {
		key2[i] = byte(i + 100)
	}

	gen1 := NewDefaultIIDGenerator(key1, testExtAddr())
	gen2 := NewDefaultIIDGenerator(key2, testExtAddr())

	prefix := slaacPrefix("fd001122334455660000000000000000", 64)
	iid1, _ := gen1.GenerateIID(prefix.Prefix, prefix.Length, 0)
	iid2, _ := gen2.GenerateIID(prefix.Prefix, prefix.Length, 0)

	if iid1 == iid2 {
		t.Errorf("different secret keys should produce different IIDs: %x vs %x", iid1, iid2)
	}
}

// ---------------------------------------------------------------------------
// Prefix tests
// ---------------------------------------------------------------------------

func TestPrefix_IsSlaacAllowed(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  bool
	}{
		{"OnMesh+Slaac", FlagOnMesh | FlagSlaac, true},
		{"OnMesh+Slaac+Preferred", FlagOnMesh | FlagSlaac | FlagPreferred, true},
		{"OnMesh only", FlagOnMesh, false},
		{"Slaac only", FlagSlaac, false},
		{"OnMesh+Slaac+Dhcp", FlagOnMesh | FlagSlaac | FlagDhcp, false},
		{"Dhcp only", FlagDhcp, false},
		{"No flags", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Prefix{Flags: tt.flags}
			if got := p.IsSlaacAllowed(); got != tt.want {
				t.Errorf("IsSlaacAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPrefix_HasFlag(t *testing.T) {
	p := Prefix{Flags: FlagOnMesh | FlagPreferred}
	if !p.HasFlag(FlagOnMesh) {
		t.Error("expected OnMesh flag")
	}
	if !p.HasFlag(FlagPreferred) {
		t.Error("expected Preferred flag")
	}
	if p.HasFlag(FlagSlaac) {
		t.Error("unexpected Slaac flag")
	}
}

// ---------------------------------------------------------------------------
// Manager — NewManager and options
// ---------------------------------------------------------------------------

func TestNewManager_Defaults(t *testing.T) {
	m := newTestManager()
	if m.maxAddresses != DefaultMaxAddresses {
		t.Errorf("maxAddresses = %d, want %d", m.maxAddresses, DefaultMaxAddresses)
	}
	if m.IsEnabled() {
		t.Error("manager should start disabled")
	}
	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("new manager should have no valid addresses, got %d", len(addrs))
	}
}

func TestNewManager_WithMaxAddresses(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())
	m := NewManager(gen, WithMaxAddresses(8))
	if m.maxAddresses != 8 {
		t.Errorf("maxAddresses = %d, want 8", m.maxAddresses)
	}
}

func TestNewManager_WithMaxAddresses_Clamp(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())
	m := NewManager(gen, WithMaxAddresses(0))
	if m.maxAddresses != 1 {
		t.Errorf("maxAddresses = %d, want 1 (clamped)", m.maxAddresses)
	}
}

// ---------------------------------------------------------------------------
// Manager — Enable / Disable
// ---------------------------------------------------------------------------

func TestManager_EnableDisable(t *testing.T) {
	m := newTestManager()

	m.Enable()
	if !m.IsEnabled() {
		t.Error("expected enabled after Enable()")
	}

	m.Disable()
	if m.IsEnabled() {
		t.Error("expected disabled after Disable()")
	}
}

func TestManager_DisableRemovesAddresses(t *testing.T) {
	m := newTestManager()
	m.Enable()

	prefixes := []Prefix{slaacPrefix("fd001122334455660000000000000000", 64)}
	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}

	m.Disable()
	addrs = m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses after Disable, got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// Manager — Update: adding addresses
// ---------------------------------------------------------------------------

func TestManager_Update_AddSinglePrefix(t *testing.T) {
	m := newTestManager()
	m.Enable()

	prefix := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{prefix})

	addrs := m.GetAddresses()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address, got %d", len(addrs))
	}

	// Verify the address uses the correct prefix.
	addr := addrs[0]
	ip6Addr := ip6.Address(addr.Address)
	if !ip6Addr.MatchesPrefix(prefix.toIP6Prefix()) {
		t.Errorf("address %s does not match prefix", ip6Addr.ToString())
	}
	if !addr.Valid {
		t.Error("address should be valid")
	}
	if addr.DadCounter != 0 {
		t.Errorf("DadCounter = %d, want 0", addr.DadCounter)
	}
}

func TestManager_Update_MultiplePrefixes(t *testing.T) {
	m := newTestManager()
	m.Enable()

	prefixes := []Prefix{
		slaacPrefix("fd001122334455660000000000000000", 64),
		slaacPrefix("fd00aabbccdd00000000000000000000", 64),
		slaacPrefix("2001db8000010000000000000000000", 64),
	}
	// Fix the last prefix hex — needs to be 32 hex chars
	prefixes[2] = slaacPrefix("2001db80000100000000000000000000", 64)

	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 3 {
		t.Fatalf("expected 3 addresses, got %d", len(addrs))
	}
}

func TestManager_Update_IgnoresNonSlaacPrefix(t *testing.T) {
	m := newTestManager()
	m.Enable()

	prefixes := []Prefix{
		dhcpPrefix("fd001122334455660000000000000000", 64),
	}
	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses for DHCP-only prefix, got %d", len(addrs))
	}
}

func TestManager_Update_MaxAddressesHonored(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())
	m := NewManager(gen, WithMaxAddresses(2))
	m.Enable()

	prefixes := []Prefix{
		slaacPrefix("fd001122334455660000000000000000", 64),
		slaacPrefix("fd00aabbccdd00000000000000000000", 64),
		slaacPrefix("fd00eeff112200000000000000000000", 64),
	}
	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses (max), got %d", len(addrs))
	}
}

func TestManager_Update_DisabledNoOp(t *testing.T) {
	m := newTestManager()
	// Manager is disabled by default.

	prefixes := []Prefix{slaacPrefix("fd001122334455660000000000000000", 64)}
	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("disabled manager should not add addresses, got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// Manager — Update: removing stale addresses
// ---------------------------------------------------------------------------

func TestManager_Update_RemoveStalePrefix(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p1 := slaacPrefix("fd001122334455660000000000000000", 64)
	p2 := slaacPrefix("fd00aabbccdd00000000000000000000", 64)

	m.Update([]Prefix{p1, p2})
	addrs := m.GetAddresses()
	if len(addrs) != 2 {
		t.Fatalf("expected 2 addresses, got %d", len(addrs))
	}

	// Remove p2 from the prefix list.
	m.Update([]Prefix{p1})
	addrs = m.GetAddresses()
	if len(addrs) != 1 {
		t.Fatalf("expected 1 address after removing prefix, got %d", len(addrs))
	}

	// Remaining address should match p1.
	if !ip6.Address(addrs[0].Address).MatchesPrefix(p1.toIP6Prefix()) {
		t.Error("remaining address should match p1")
	}
}

func TestManager_Update_RemoveAll(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p1 := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p1})
	if len(m.GetAddresses()) != 1 {
		t.Fatal("setup: expected 1 address")
	}

	m.Update(nil) // Empty prefix list.
	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses after removing all prefixes, got %d", len(addrs))
	}
}

func TestManager_Update_PrefixFlagsChange(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})
	if len(m.GetAddresses()) != 1 {
		t.Fatal("setup: expected 1 address")
	}

	// Change flags to DHCP — address should be removed.
	pDhcp := dhcpPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{pDhcp})
	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses after flags changed to DHCP, got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// Manager — Update: idempotency
// ---------------------------------------------------------------------------

func TestManager_Update_Idempotent(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})
	addr1 := m.GetAddresses()
	if len(addr1) != 1 {
		t.Fatal("expected 1 address")
	}

	// Update again with the same prefix; address should not change.
	m.Update([]Prefix{p})
	addr2 := m.GetAddresses()
	if len(addr2) != 1 {
		t.Fatal("expected 1 address")
	}

	if addr1[0].Address != addr2[0].Address {
		t.Error("address changed on idempotent update")
	}
}

// ---------------------------------------------------------------------------
// Manager — FindAddress
// ---------------------------------------------------------------------------

func TestManager_FindAddress(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	addr, found := m.FindAddress(p.Prefix, p.Length)
	if !found {
		t.Fatal("expected to find address")
	}
	if !addr.Valid {
		t.Error("found address should be valid")
	}
}

func TestManager_FindAddress_NotFound(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	// Search for a different prefix.
	other := slaacPrefix("fd00aabbccdd00000000000000000000", 64)
	_, found := m.FindAddress(other.Prefix, other.Length)
	if found {
		t.Error("should not find address for non-existent prefix")
	}
}

// ---------------------------------------------------------------------------
// Manager — DAD failure
// ---------------------------------------------------------------------------

func TestManager_SignalDADFailure(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	origAddr := m.GetAddresses()[0].Address

	err := m.SignalDADFailure(p.Prefix, p.Length)
	if err != nil {
		t.Fatalf("SignalDADFailure returned error: %v", err)
	}

	addrs := m.GetAddresses()
	if len(addrs) != 1 {
		t.Fatal("expected 1 address after DAD failure")
	}
	if addrs[0].DadCounter != 1 {
		t.Errorf("DadCounter = %d, want 1", addrs[0].DadCounter)
	}
	if addrs[0].Address == origAddr {
		t.Error("address should change after DAD failure")
	}
	// Verify the new address still matches the prefix.
	if !ip6.Address(addrs[0].Address).MatchesPrefix(p.toIP6Prefix()) {
		t.Error("regenerated address should still match the prefix")
	}
}

func TestManager_SignalDADFailure_NotFound(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	err := m.SignalDADFailure(p.Prefix, p.Length)
	if err == nil {
		t.Error("expected error for non-existent address")
	}
}

func TestManager_SignalDADFailure_MultipleRetries(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	seen := make(map[ip6.Address]bool)
	seen[m.GetAddresses()[0].Address] = true

	for i := 0; i < 5; i++ {
		err := m.SignalDADFailure(p.Prefix, p.Length)
		if err != nil {
			t.Fatalf("SignalDADFailure(%d) returned error: %v", i, err)
		}
		addr := m.GetAddresses()[0].Address
		if seen[addr] {
			t.Errorf("duplicate address generated at DAD retry %d", i+1)
		}
		seen[addr] = true
	}

	// Verify final DadCounter.
	if m.GetAddresses()[0].DadCounter != 5 {
		t.Errorf("DadCounter = %d, want 5", m.GetAddresses()[0].DadCounter)
	}
}

// ---------------------------------------------------------------------------
// Manager — address prefix correctness
// ---------------------------------------------------------------------------

func TestManager_AddressPrefix64(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	addr := m.GetAddresses()[0].Address

	// First 8 bytes must match the prefix.
	for i := 0; i < 8; i++ {
		if addr[i] != p.Prefix[i] {
			t.Errorf("byte %d: addr=0x%02x prefix=0x%02x", i, addr[i], p.Prefix[i])
		}
	}

	// IID (last 8 bytes) should not be all zeros.
	allZero := true
	for i := 8; i < 16; i++ {
		if addr[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("IID should not be all zeros")
	}
}

// ---------------------------------------------------------------------------
// Manager — WithIIDGenerator option
// ---------------------------------------------------------------------------

// staticIIDGenerator always returns the same IID for testing.
type staticIIDGenerator struct {
	iid [8]byte
}

func (g *staticIIDGenerator) GenerateIID(_ [16]byte, _, _ uint8) ([8]byte, error) {
	return g.iid, nil
}

func TestManager_WithIIDGenerator(t *testing.T) {
	wantIID := [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	gen := &staticIIDGenerator{iid: wantIID}
	m := NewManager(gen)
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	addr := m.GetAddresses()[0].Address
	var gotIID [8]byte
	copy(gotIID[:], addr[8:])

	if gotIID != wantIID {
		t.Errorf("IID = %x, want %x", gotIID, wantIID)
	}
}

// ---------------------------------------------------------------------------
// Manager — failingIIDGenerator
// ---------------------------------------------------------------------------

type failingIIDGenerator struct{}

func (g *failingIIDGenerator) GenerateIID(_ [16]byte, _, _ uint8) ([8]byte, error) {
	return [8]byte{}, errors.ErrFailed
}

func TestManager_IIDGeneratorFailure(t *testing.T) {
	gen := &failingIIDGenerator{}
	m := NewManager(gen)
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})

	addrs := m.GetAddresses()
	if len(addrs) != 0 {
		t.Errorf("expected 0 addresses when IID generator fails, got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// Manager — prefix add then re-add after removal
// ---------------------------------------------------------------------------

func TestManager_ReAddPrefix(t *testing.T) {
	m := newTestManager()
	m.Enable()

	p := slaacPrefix("fd001122334455660000000000000000", 64)
	m.Update([]Prefix{p})
	addr1 := m.GetAddresses()[0].Address

	// Remove it.
	m.Update(nil)
	if len(m.GetAddresses()) != 0 {
		t.Fatal("expected 0 addresses after removal")
	}

	// Re-add it: should produce the same address (deterministic IID).
	m.Update([]Prefix{p})
	addr2 := m.GetAddresses()[0].Address
	if addr1 != addr2 {
		t.Errorf("re-added address differs: %x vs %x", addr1, addr2)
	}
}

// ---------------------------------------------------------------------------
// Manager — mixed SLAAC and non-SLAAC prefixes
// ---------------------------------------------------------------------------

func TestManager_MixedPrefixes(t *testing.T) {
	m := newTestManager()
	m.Enable()

	prefixes := []Prefix{
		slaacPrefix("fd001122334455660000000000000000", 64),
		dhcpPrefix("fd00aabbccdd00000000000000000000", 64),
		slaacPrefix("fd00eeff112200000000000000000000", 64),
	}
	m.Update(prefixes)

	addrs := m.GetAddresses()
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses (skipping DHCP), got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// Manager — slot reuse after removal
// ---------------------------------------------------------------------------

func TestManager_SlotReuse(t *testing.T) {
	gen := NewDefaultIIDGenerator(testSecretKey(), testExtAddr())
	m := NewManager(gen, WithMaxAddresses(2))
	m.Enable()

	p1 := slaacPrefix("fd001122334455660000000000000000", 64)
	p2 := slaacPrefix("fd00aabbccdd00000000000000000000", 64)

	m.Update([]Prefix{p1, p2})
	if len(m.GetAddresses()) != 2 {
		t.Fatal("expected 2 addresses")
	}

	// Remove p1.
	m.Update([]Prefix{p2})
	if len(m.GetAddresses()) != 1 {
		t.Fatal("expected 1 address after removal")
	}

	// Add p3 — should reuse the freed slot.
	p3 := slaacPrefix("fd00eeff112200000000000000000000", 64)
	m.Update([]Prefix{p2, p3})
	addrs := m.GetAddresses()
	if len(addrs) != 2 {
		t.Errorf("expected 2 addresses after slot reuse, got %d", len(addrs))
	}
}

// ---------------------------------------------------------------------------
// prefixesMatch
// ---------------------------------------------------------------------------

func TestPrefixesMatch(t *testing.T) {
	p1 := slaacPrefix("fd001122334455660000000000000000", 64)
	p2 := slaacPrefix("fd001122334455660000000000000000", 64)
	p3 := slaacPrefix("fd001122334455670000000000000000", 64) // different byte
	p4 := slaacPrefix("fd001122334455660000000000000000", 48) // different length

	if !prefixesMatch(p1, p2) {
		t.Error("identical prefixes should match")
	}
	if prefixesMatch(p1, p3) {
		t.Error("different prefix bytes should not match")
	}
	if prefixesMatch(p1, p4) {
		t.Error("different prefix lengths should not match")
	}
}
