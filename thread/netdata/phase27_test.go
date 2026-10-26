// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"testing"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Helper: build a test prefix
// ---------------------------------------------------------------------------

func testPrefix(t *testing.T, s string) ip6.Prefix {
	t.Helper()
	p, err := ip6.PrefixFromString(s)
	if err != nil {
		t.Fatalf("PrefixFromString(%q): %v", s, err)
	}
	return p
}

// ---------------------------------------------------------------------------
// service.go tests
// ---------------------------------------------------------------------------

func TestSerialNumberIsGreater(t *testing.T) {
	tests := []struct {
		a, b uint8
		want bool
	}{
		{1, 0, true},
		{0, 1, false},
		{0, 0, false},
		{128, 0, false}, // 128 - 0 = 128 -> int8(128) = -128 < 0 -> false
		{127, 0, true},  // 127 - 0 = 127 -> int8(127) = 127 > 0 -> true
		{0, 128, false}, // 0 - 128 = uint8(128) -> int8(128) = -128 < 0 -> false
		{255, 0, false}, // 255 - 0 = uint8(255) -> int8(255) = -1 < 0 -> false
		{200, 100, true},
		{100, 200, false},
		// Wraparound cases
		{5, 250, true},  // 5 - 250 = 11 -> int8(11) = 11 > 0 -> true
		{250, 5, false}, // 250 - 5 = 245 -> int8(245) = -11 < 0 -> false
	}
	for _, tc := range tests {
		got := SerialNumberIsGreater(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("SerialNumberIsGreater(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestEncodeDnsSrpAnycastServiceData(t *testing.T) {
	data := EncodeDnsSrpAnycastServiceData(42)
	if len(data) != 2 {
		t.Fatalf("expected 2 bytes, got %d", len(data))
	}
	if data[0] != ServiceNumberDnsSrpAnycast {
		t.Errorf("data[0] = %02x, want %02x", data[0], ServiceNumberDnsSrpAnycast)
	}
	if data[1] != 42 {
		t.Errorf("data[1] = %d, want 42", data[1])
	}
}

func TestEncodeDnsSrpUnicastServiceData(t *testing.T) {
	var addr ip6.Address
	addr[15] = 0x01
	port := uint16(53)

	data := EncodeDnsSrpUnicastServiceData(addr, port)
	if len(data) != 19 {
		t.Fatalf("expected 19 bytes, got %d", len(data))
	}
	if data[0] != ServiceNumberDnsSrpUnicast {
		t.Errorf("data[0] = %02x, want %02x", data[0], ServiceNumberDnsSrpUnicast)
	}
	if data[16] != addr[15] {
		t.Errorf("addr byte mismatch")
	}
	// Port in big-endian
	if data[17] != 0x00 || data[18] != 53 {
		t.Errorf("port mismatch: got %02x%02x", data[17], data[18])
	}
}

func TestEncodeBbrServerData(t *testing.T) {
	data := EncodeBbrServerData(10, 300, 3600)
	if len(data) != 7 {
		t.Fatalf("expected 7 bytes, got %d", len(data))
	}
	if data[0] != 10 {
		t.Errorf("seqNum = %d, want 10", data[0])
	}
	// reregDelay = 300 = 0x012C
	if data[1] != 0x01 || data[2] != 0x2C {
		t.Errorf("reregDelay mismatch: %02x%02x", data[1], data[2])
	}
	// mlrTimeout = 3600 = 0x00000E10
	if data[3] != 0x00 || data[4] != 0x00 || data[5] != 0x0E || data[6] != 0x10 {
		t.Errorf("mlrTimeout mismatch")
	}
}

func TestGetServiceAloc(t *testing.T) {
	// Mesh-local prefix: fd00:db8::/64
	var prefixBytes [16]byte
	prefixBytes[0] = 0xfd
	prefixBytes[1] = 0x00
	prefixBytes[2] = 0x0d
	prefixBytes[3] = 0xb8
	mlPrefix := ip6.NewPrefix(prefixBytes, 64)

	addr := GetServiceAloc(mlPrefix, 5)

	// Check prefix portion
	if addr[0] != 0xfd || addr[1] != 0x00 || addr[2] != 0x0d || addr[3] != 0xb8 {
		t.Errorf("prefix mismatch in ALOC address")
	}
	// Check IID pattern
	if addr[8] != 0x00 || addr[9] != 0x00 || addr[10] != 0x00 {
		t.Errorf("IID[0:3] should be zero")
	}
	if addr[11] != 0xff || addr[12] != 0xfe || addr[13] != 0x00 {
		t.Errorf("IID[3:6] should be ff:fe:00")
	}
	if addr[14] != 0xfc {
		t.Errorf("IID[6] = %02x, want 0xfc", addr[14])
	}
	if addr[15] != 0x10+5 {
		t.Errorf("IID[7] = %02x, want %02x", addr[15], 0x10+5)
	}
}

// buildDNSSrpAnycastNetData builds raw network data containing DNS/SRP anycast
// service entries for testing the iterator and preferred-finding functions.
func buildDNSSrpAnycastNetData(entries []struct {
	seqNum  uint8
	version uint8
	rloc16  uint16
}) []byte {
	var buf []byte
	for _, e := range entries {
		// Service data: [0x5c, seqNum]
		serviceData := []byte{ServiceNumberDnsSrpAnycast, e.seqNum}

		// Server sub-TLV: server data = [version]
		serverEntry := ServerEntry{Server16: e.rloc16, ServerData: []byte{e.version}}
		var serverTLV []byte
		serverTLV = AppendServerTLV(serverTLV, true, serverEntry)

		// Service TLV
		svcInfo := ServiceTLVInfo{
			ServiceID:        0,
			EnterpriseNumber: ThreadEnterpriseNumber,
			ServiceData:      serviceData,
			SubTLVsData:      serverTLV,
			Stable:           true,
		}
		valueLen := ServiceValueSize(svcInfo)
		buf = AppendTLVHeader(buf, TLVTypeService, true, uint8(valueLen))
		buf = AppendServiceValue(buf, svcInfo)
	}
	return buf
}

func TestServiceIteratorAnycast(t *testing.T) {
	data := buildDNSSrpAnycastNetData([]struct {
		seqNum  uint8
		version uint8
		rloc16  uint16
	}{
		{seqNum: 10, version: 1, rloc16: 0x0400},
		{seqNum: 20, version: 2, rloc16: 0x0800},
	})

	it := NewServiceIterator(data)

	info1, err := it.GetNextDnsSrpAnycastInfo()
	if err != nil {
		t.Fatalf("first GetNextDnsSrpAnycastInfo: %v", err)
	}
	if info1.SequenceNumber != 10 {
		t.Errorf("info1.SequenceNumber = %d, want 10", info1.SequenceNumber)
	}
	if info1.Version != 1 {
		t.Errorf("info1.Version = %d, want 1", info1.Version)
	}
	if info1.RLOC16 != 0x0400 {
		t.Errorf("info1.RLOC16 = %04x, want 0400", info1.RLOC16)
	}

	info2, err := it.GetNextDnsSrpAnycastInfo()
	if err != nil {
		t.Fatalf("second GetNextDnsSrpAnycastInfo: %v", err)
	}
	if info2.SequenceNumber != 20 {
		t.Errorf("info2.SequenceNumber = %d, want 20", info2.SequenceNumber)
	}
	if info2.RLOC16 != 0x0800 {
		t.Errorf("info2.RLOC16 = %04x, want 0800", info2.RLOC16)
	}

	_, err = it.GetNextDnsSrpAnycastInfo()
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound at end, got %v", err)
	}
}

func TestFindPreferredDnsSrpAnycastInfo(t *testing.T) {
	// Two entries: seq 10 (version 3) and seq 20 (version 1).
	// seq 20 > seq 10, so seq 20 wins. Version = 1.
	data := buildDNSSrpAnycastNetData([]struct {
		seqNum  uint8
		version uint8
		rloc16  uint16
	}{
		{seqNum: 10, version: 3, rloc16: 0x0400},
		{seqNum: 20, version: 1, rloc16: 0x0800},
	})

	info, err := FindPreferredDnsSrpAnycastInfo(data)
	if err != nil {
		t.Fatalf("FindPreferredDnsSrpAnycastInfo: %v", err)
	}
	if info.SequenceNumber != 20 {
		t.Errorf("SequenceNumber = %d, want 20", info.SequenceNumber)
	}
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1", info.Version)
	}
}

func TestFindPreferredDnsSrpAnycastInfoMinVersion(t *testing.T) {
	// Two entries with same seq 20: versions 3 and 1. Min version = 1.
	data := buildDNSSrpAnycastNetData([]struct {
		seqNum  uint8
		version uint8
		rloc16  uint16
	}{
		{seqNum: 20, version: 3, rloc16: 0x0400},
		{seqNum: 20, version: 1, rloc16: 0x0800},
	})

	info, err := FindPreferredDnsSrpAnycastInfo(data)
	if err != nil {
		t.Fatalf("FindPreferredDnsSrpAnycastInfo: %v", err)
	}
	if info.Version != 1 {
		t.Errorf("Version = %d, want 1 (minimum)", info.Version)
	}
	if info.RLOC16 != 0x0800 {
		t.Errorf("RLOC16 = %04x, want 0800", info.RLOC16)
	}
}

func TestFindPreferredDnsSrpAnycastInfoEmpty(t *testing.T) {
	_, err := FindPreferredDnsSrpAnycastInfo(nil)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestFindBackboneRouterPrimary(t *testing.T) {
	// Build BBR service entries
	bbrServiceData := []byte{ServiceNumberBackboneRouter}

	// BBR at RLOC 0x0400 (leader), seq 5
	srv1 := ServerEntry{Server16: 0x0400, ServerData: EncodeBbrServerData(5, 300, 3600)}
	var sub1 []byte
	sub1 = AppendServerTLV(sub1, true, srv1)

	svcInfo1 := ServiceTLVInfo{
		EnterpriseNumber: ThreadEnterpriseNumber,
		ServiceData:      bbrServiceData,
		SubTLVsData:      sub1,
		Stable:           true,
	}
	var data []byte
	vLen1 := ServiceValueSize(svcInfo1)
	data = AppendTLVHeader(data, TLVTypeService, true, uint8(vLen1))
	data = AppendServiceValue(data, svcInfo1)

	// BBR at RLOC 0x0800, seq 10 (higher seq but not leader)
	srv2 := ServerEntry{Server16: 0x0800, ServerData: EncodeBbrServerData(10, 300, 3600)}
	var sub2 []byte
	sub2 = AppendServerTLV(sub2, true, srv2)

	svcInfo2 := ServiceTLVInfo{
		EnterpriseNumber: ThreadEnterpriseNumber,
		ServiceData:      bbrServiceData,
		SubTLVsData:      sub2,
		Stable:           true,
	}
	vLen2 := ServiceValueSize(svcInfo2)
	data = AppendTLVHeader(data, TLVTypeService, true, uint8(vLen2))
	data = AppendServiceValue(data, svcInfo2)

	// Leader RLOC = 0x0400, so it should be preferred despite lower seq.
	config, err := FindBackboneRouterPrimary(data, 0x0400)
	if err != nil {
		t.Fatalf("FindBackboneRouterPrimary: %v", err)
	}
	if config.RLOC16 != 0x0400 {
		t.Errorf("RLOC16 = %04x, want 0400 (leader preferred)", config.RLOC16)
	}
	if config.SequenceNumber != 5 {
		t.Errorf("SequenceNumber = %d, want 5", config.SequenceNumber)
	}

	// With a different leader RLOC, the higher seq should win.
	config2, err := FindBackboneRouterPrimary(data, 0xFFFF)
	if err != nil {
		t.Fatalf("FindBackboneRouterPrimary (non-leader): %v", err)
	}
	if config2.RLOC16 != 0x0800 {
		t.Errorf("RLOC16 = %04x, want 0800 (higher seq)", config2.RLOC16)
	}
}

func TestFindBackboneRouterPrimaryEmpty(t *testing.T) {
	_, err := FindBackboneRouterPrimary(nil, 0x0400)
	if err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// local.go tests
// ---------------------------------------------------------------------------

func TestLocalAddRemoveOnMeshPrefix(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:1::/48")

	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
		SLAAC:      true,
	}

	if err := l.AddOnMeshPrefix(config); err != nil {
		t.Fatalf("AddOnMeshPrefix: %v", err)
	}
	if !l.HasChanged() {
		t.Error("expected HasChanged after add")
	}
	if l.Len() == 0 {
		t.Fatal("expected non-empty data after add")
	}
	if !l.ContainsOnMeshPrefix(prefix) {
		t.Error("ContainsOnMeshPrefix returned false after add")
	}

	// Verify data parses correctly.
	it := NewIterator(l.Data())
	cfg, err := it.NextOnMeshPrefix()
	if err != nil {
		t.Fatalf("NextOnMeshPrefix: %v", err)
	}
	if cfg.RLOC16 != 0x0400 {
		t.Errorf("RLOC16 = %04x, want 0400", cfg.RLOC16)
	}
	if cfg.Preference != RoutePreferenceHigh {
		t.Errorf("Preference = %d, want High", cfg.Preference)
	}
	if !cfg.OnMesh {
		t.Error("expected OnMesh flag")
	}
	if !cfg.SLAAC {
		t.Error("expected SLAAC flag")
	}

	// Remove
	if err := l.RemoveOnMeshPrefix(prefix); err != nil {
		t.Fatalf("RemoveOnMeshPrefix: %v", err)
	}
	if l.ContainsOnMeshPrefix(prefix) {
		t.Error("ContainsOnMeshPrefix returned true after remove")
	}
	if l.Len() != 0 {
		t.Errorf("expected empty data after remove, got len=%d", l.Len())
	}
}

func TestLocalAddRemoveOnMeshPrefixNotFound(t *testing.T) {
	l := NewLocal()
	prefix := testPrefix(t, "2001:db8:2::/48")
	if err := l.RemoveOnMeshPrefix(prefix); err != errors.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestLocalAddHasRoutePrefix(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x1000)

	prefix := testPrefix(t, "2001:db8:3::/48")

	config := ExternalRouteConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceLow,
		Stable:     true,
		NAT64:      true,
	}

	if err := l.AddHasRoutePrefix(config); err != nil {
		t.Fatalf("AddHasRoutePrefix: %v", err)
	}

	it := NewIterator(l.Data())
	cfg, err := it.NextExternalRoute()
	if err != nil {
		t.Fatalf("NextExternalRoute: %v", err)
	}
	if cfg.RLOC16 != 0x1000 {
		t.Errorf("RLOC16 = %04x, want 1000", cfg.RLOC16)
	}
	if cfg.Preference != RoutePreferenceLow {
		t.Errorf("Preference = %d, want Low", cfg.Preference)
	}
	if !cfg.NAT64 {
		t.Error("expected NAT64 flag")
	}

	// Remove
	if err := l.RemoveHasRoutePrefix(prefix); err != nil {
		t.Fatalf("RemoveHasRoutePrefix: %v", err)
	}
	if l.Len() != 0 {
		t.Errorf("expected empty data after remove, got len=%d", l.Len())
	}
}

func TestLocalAddReplace(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:4::/48")

	config1 := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
	}
	if err := l.AddOnMeshPrefix(config1); err != nil {
		t.Fatalf("first AddOnMeshPrefix: %v", err)
	}
	len1 := l.Len()

	// Add again with different config — should replace.
	config2 := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceLow,
		Stable:     true,
		OnMesh:     true,
		DHCP:       true,
	}
	if err := l.AddOnMeshPrefix(config2); err != nil {
		t.Fatalf("second AddOnMeshPrefix: %v", err)
	}

	// Length should be similar (replaced, not doubled).
	if l.Len() != len1 {
		t.Errorf("expected same length after replace, got %d vs %d", l.Len(), len1)
	}

	// Verify updated config.
	it := NewIterator(l.Data())
	cfg, err := it.NextOnMeshPrefix()
	if err != nil {
		t.Fatalf("NextOnMeshPrefix: %v", err)
	}
	if cfg.Preference != RoutePreferenceLow {
		t.Errorf("Preference = %d, want Low (after replace)", cfg.Preference)
	}
	if !cfg.DHCP {
		t.Error("expected DHCP flag after replace")
	}
}

func TestLocalAddService(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x2000)

	serviceData := EncodeDnsSrpAnycastServiceData(42)
	serverData := []byte{0x01} // version 1

	if err := l.AddService(ThreadEnterpriseNumber, serviceData, true, serverData); err != nil {
		t.Fatalf("AddService: %v", err)
	}
	if !l.HasChanged() {
		t.Error("expected HasChanged after add")
	}
	if l.Len() == 0 {
		t.Fatal("expected non-empty data after service add")
	}

	// Remove
	if err := l.RemoveService(ThreadEnterpriseNumber, serviceData); err != nil {
		t.Fatalf("RemoveService: %v", err)
	}
	if l.Len() != 0 {
		t.Errorf("expected empty data after service remove, got len=%d", l.Len())
	}
}

func TestLocalUpdateRloc(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:5::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceMedium,
		Stable:     true,
		OnMesh:     true,
	}
	if err := l.AddOnMeshPrefix(config); err != nil {
		t.Fatalf("AddOnMeshPrefix: %v", err)
	}

	// Change RLOC and update.
	l.SetRloc16(0x0C00)
	l.UpdateRloc()

	it := NewIterator(l.Data())
	cfg, err := it.NextOnMeshPrefix()
	if err != nil {
		t.Fatalf("NextOnMeshPrefix: %v", err)
	}
	if cfg.RLOC16 != 0x0C00 {
		t.Errorf("RLOC16 = %04x, want 0C00 after UpdateRloc", cfg.RLOC16)
	}
}

func TestLocalClear(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:6::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceMedium,
		Stable:     true,
		OnMesh:     true,
	}
	_ = l.AddOnMeshPrefix(config)
	l.ClearChanged()

	l.Clear()
	if l.Len() != 0 {
		t.Errorf("expected empty after Clear, got len=%d", l.Len())
	}
	if !l.HasChanged() {
		t.Error("expected HasChanged after Clear")
	}
}

// ---------------------------------------------------------------------------
// publisher.go tests
// ---------------------------------------------------------------------------

func TestPublisherPublishOnMeshPrefix(t *testing.T) {
	// Use deterministic zero delay for testing.
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))
	pub.SetRloc16(0x0400)
	pub.SetIsRouter(true)

	prefix := testPrefix(t, "2001:db8:1::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
	}

	if err := pub.PublishOnMeshPrefix(config, PublisherRequesterUser); err != nil {
		t.Fatalf("PublishOnMeshPrefix: %v", err)
	}

	// Process with empty leader data — should transition ToAdd -> Adding -> Added.
	actions := pub.Process(nil)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != PublisherActionAdd {
		t.Errorf("action type = %d, want Add", actions[0].Type)
	}
	if !actions[0].IsOnMesh {
		t.Error("expected IsOnMesh=true")
	}
	if !pub.IsPrefixAdded(prefix) {
		t.Error("expected IsPrefixAdded=true after add action")
	}
}

func TestPublisherPublishExternalRoute(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))
	pub.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:2::/48")
	config := ExternalRouteConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceMedium,
		Stable:     true,
	}

	if err := pub.PublishExternalRoute(config, PublisherRequesterUser); err != nil {
		t.Fatalf("PublishExternalRoute: %v", err)
	}

	actions := pub.Process(nil)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if actions[0].Type != PublisherActionAdd {
		t.Errorf("action type = %d, want Add", actions[0].Type)
	}
	if actions[0].IsOnMesh {
		t.Error("expected IsOnMesh=false for external route")
	}
}

func TestPublisherUnpublish(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))

	prefix := testPrefix(t, "2001:db8:3::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
	}

	_ = pub.PublishOnMeshPrefix(config, PublisherRequesterUser)
	// Process to move to Added
	_ = pub.Process(nil)

	if err := pub.UnpublishPrefix(prefix); err != nil {
		t.Fatalf("UnpublishPrefix: %v", err)
	}
	if pub.IsPrefixAdded(prefix) {
		t.Error("expected IsPrefixAdded=false after unpublish")
	}
}

func TestPublisherDnsSrp(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))

	pub.PublishDnsSrpServiceAnycast(42, 1)

	actions := pub.Process(nil)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	if !pub.IsDnsSrpServiceAdded() {
		t.Error("expected IsDnsSrpServiceAdded=true")
	}

	pub.UnpublishDnsSrpService()
	if pub.IsDnsSrpServiceAdded() {
		t.Error("expected IsDnsSrpServiceAdded=false after unpublish")
	}
}

func TestPublisherAlreadyPublished(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))

	prefix := testPrefix(t, "2001:db8:4::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
	}

	_ = pub.PublishOnMeshPrefix(config, PublisherRequesterUser)
	err := pub.PublishOnMeshPrefix(config, PublisherRequesterUser)
	if err != errors.ErrAlready {
		t.Errorf("expected ErrAlready, got %v", err)
	}
}

func TestPublisherCallback(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))

	var events []PublisherEvent
	pub.SetPrefixCallback(func(event PublisherEvent, prefix ip6.Prefix) {
		events = append(events, event)
	})

	prefix := testPrefix(t, "2001:db8:5::/48")
	config := OnMeshPrefixConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceHigh,
		Stable:     true,
		OnMesh:     true,
	}

	_ = pub.PublishOnMeshPrefix(config, PublisherRequesterUser)
	_ = pub.Process(nil) // Should trigger EntryAdded

	if len(events) != 1 || events[0] != PublisherEventEntryAdded {
		t.Errorf("expected [EntryAdded], got %v", events)
	}

	_ = pub.UnpublishPrefix(prefix) // Should trigger EntryRemoved
	if len(events) != 2 || events[1] != PublisherEventEntryRemoved {
		t.Errorf("expected [EntryAdded, EntryRemoved], got %v", events)
	}
}

func TestPublisherMaxEntries(t *testing.T) {
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 { return 0 }))

	// Fill up all slots for user requester
	for i := 0; i < MaxPublisherPrefixEntries; i++ {
		var prefixBytes [16]byte
		prefixBytes[0] = 0x20
		prefixBytes[1] = 0x01
		prefixBytes[2] = byte(i)
		prefix := ip6.NewPrefix(prefixBytes, 48)
		config := OnMeshPrefixConfig{
			Prefix: prefix,
			Stable: true,
			OnMesh: true,
		}
		if err := pub.PublishOnMeshPrefix(config, PublisherRequesterUser); err != nil {
			t.Fatalf("PublishOnMeshPrefix[%d]: %v", i, err)
		}
	}

	// Next one should fail
	var prefixBytes [16]byte
	prefixBytes[0] = 0x20
	prefixBytes[1] = 0x01
	prefixBytes[2] = 0xFF
	overflowPrefix := ip6.NewPrefix(prefixBytes, 48)
	config := OnMeshPrefixConfig{
		Prefix: overflowPrefix,
		Stable: true,
		OnMesh: true,
	}
	if err := pub.PublishOnMeshPrefix(config, PublisherRequesterUser); err != errors.ErrNoBufs {
		t.Errorf("expected ErrNoBufs, got %v", err)
	}

	// But routing manager should still have slots
	if err := pub.PublishOnMeshPrefix(config, PublisherRequesterRoutingManager); err != nil {
		t.Errorf("routing manager slot should be available: %v", err)
	}
}

func TestPublisherAdvanceTime(t *testing.T) {
	callCount := 0
	pub := NewPublisher(WithPublisherRand(func(max uint32) uint32 {
		callCount++
		return 200 // 200ms delay
	}))

	prefix := testPrefix(t, "2001:db8:6::/48")
	config := ExternalRouteConfig{
		Prefix:     prefix,
		Preference: RoutePreferenceMedium,
		Stable:     true,
	}
	_ = pub.PublishExternalRoute(config, PublisherRequesterUser)

	// First process: ToAdd -> Adding (with 200ms delay)
	actions := pub.Process(nil)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions while timer running, got %d", len(actions))
	}
	if !pub.HasPendingTimers() {
		t.Error("expected pending timers")
	}

	// Advance 100ms — not enough
	pub.AdvanceTime(100)
	actions = pub.Process(nil)
	if len(actions) != 0 {
		t.Errorf("expected 0 actions at 100ms, got %d", len(actions))
	}

	// Advance another 150ms — should expire
	pub.AdvanceTime(150)
	actions = pub.Process(nil)
	if len(actions) != 1 {
		t.Fatalf("expected 1 action after timer expires, got %d", len(actions))
	}
	if actions[0].Type != PublisherActionAdd {
		t.Errorf("action type = %d, want Add", actions[0].Type)
	}
}

// ---------------------------------------------------------------------------
// notifier.go tests
// ---------------------------------------------------------------------------

func TestNotifierBasicSync(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:1::/48")
	_ = l.AddOnMeshPrefix(OnMeshPrefixConfig{
		Prefix: prefix,
		Stable: true,
		OnMesh: true,
	})

	n := NewNotifier(l)

	var syncCalled bool
	var syncOldRloc uint16
	n.SetSyncCallback(func(oldRloc16 uint16, data []byte) error {
		syncCalled = true
		syncOldRloc = oldRloc16
		return nil
	})
	n.SetOldRloc16(0x0000)

	// Signal that data updated.
	n.HandleServerDataUpdated()
	if !n.NeedsSync() {
		t.Error("expected NeedsSync=true")
	}

	delay := n.SynchronizeServerData()
	if !syncCalled {
		t.Error("expected sync callback to be called")
	}
	if syncOldRloc != 0x0000 {
		t.Errorf("oldRloc = %04x, want 0000", syncOldRloc)
	}
	if !n.IsWaitingForResponse() {
		t.Error("expected IsWaitingForResponse=true after sync")
	}
	_ = delay

	// Simulate successful response.
	n.HandleSyncResponse(true)
	if n.IsWaitingForResponse() {
		t.Error("expected IsWaitingForResponse=false after response")
	}
	if !n.IsTimerRunning() {
		t.Error("expected timer to be running after successful sync")
	}
	if n.TimerRemaining() != NotifierDelaySynchronize {
		t.Errorf("timer = %d, want %d", n.TimerRemaining(), NotifierDelaySynchronize)
	}
}

func TestNotifierRetryOnFailure(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:2::/48")
	_ = l.AddOnMeshPrefix(OnMeshPrefixConfig{
		Prefix: prefix,
		Stable: true,
		OnMesh: true,
	})

	n := NewNotifier(l)

	callCount := 0
	n.SetSyncCallback(func(oldRloc16 uint16, data []byte) error {
		callCount++
		if callCount == 1 {
			return errors.ErrNoBufs
		}
		return nil
	})

	n.HandleServerDataUpdated()

	// First attempt — should fail with NoBufs and return delay.
	delay := n.SynchronizeServerData()
	if delay != NotifierDelayNoBufs {
		t.Errorf("delay = %d, want %d (NoBufs)", delay, NotifierDelayNoBufs)
	}
	if n.IsWaitingForResponse() {
		t.Error("should not be waiting after NoBufs")
	}

	// Retry — should succeed.
	delay = n.SynchronizeServerData()
	if delay != 0 {
		t.Errorf("retry delay = %d, want 0 after HandleServerDataUpdated", delay)
	}
	if !n.IsWaitingForResponse() {
		t.Error("expected IsWaitingForResponse=true after successful retry")
	}
}

func TestNotifierNoChangeSkipsSync(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	n := NewNotifier(l)

	syncCalled := false
	n.SetSyncCallback(func(oldRloc16 uint16, data []byte) error {
		syncCalled = true
		return nil
	})

	// No changes — sync should be no-op.
	delay := n.SynchronizeServerData()
	if syncCalled {
		t.Error("sync should not be called when no changes")
	}
	if delay != 0 {
		t.Errorf("delay = %d, want 0", delay)
	}
}

func TestNotifierHandleTimerFired(t *testing.T) {
	l := NewLocal()
	n := NewNotifier(l)

	n.HandleTimerFired()
	if !n.NeedsSync() {
		t.Error("expected NeedsSync=true after timer fired")
	}
	if n.IsTimerRunning() {
		t.Error("expected timer not running after fired")
	}
}

func TestNotifierSyncResponseFailure(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)

	prefix := testPrefix(t, "2001:db8:3::/48")
	_ = l.AddOnMeshPrefix(OnMeshPrefixConfig{
		Prefix: prefix,
		Stable: true,
		OnMesh: true,
	})

	n := NewNotifier(l)
	n.SetSyncCallback(func(oldRloc16 uint16, data []byte) error {
		return nil
	})

	n.HandleServerDataUpdated()
	_ = n.SynchronizeServerData()

	// Simulate failed response — should trigger immediate retry.
	n.HandleSyncResponse(false)
	if !n.NeedsSync() {
		t.Error("expected NeedsSync=true after failed response")
	}
	if n.IsWaitingForResponse() {
		t.Error("expected not waiting after failed response")
	}
}

func TestNotifierConsistencyCheck(t *testing.T) {
	l := NewLocal()
	l.SetRloc16(0x0400)
	n := NewNotifier(l)

	// Initially consistent (no data, no changes).
	// Actually, NewLocal starts with changed=false.
	if !n.IsLocalDataConsistent() {
		t.Error("expected consistent when no data and no changes")
	}

	// Add data — becomes inconsistent.
	prefix := testPrefix(t, "2001:db8:4::/48")
	_ = l.AddOnMeshPrefix(OnMeshPrefixConfig{
		Prefix: prefix,
		Stable: true,
		OnMesh: true,
	})

	if n.IsLocalDataConsistent() {
		t.Error("expected inconsistent after adding data")
	}

	// Clear changed flag.
	l.ClearChanged()
	if !n.IsLocalDataConsistent() {
		t.Error("expected consistent after ClearChanged")
	}
}
