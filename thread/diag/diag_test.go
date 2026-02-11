// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package diag

import (
	"bytes"
	"testing"

	mactypes "github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/tlv"
)

// --- Connectivity round-trip ---

func TestConnectivityRoundTrip(t *testing.T) {
	orig := Connectivity{
		ParentPriority:   -1,
		LinkQuality3:     3,
		LinkQuality2:     2,
		LinkQuality1:     1,
		LeaderCost:       5,
		IDSequence:       42,
		ActiveRouters:    10,
		SEDBufferSize:    512,
		SEDDatagramCount: 4,
	}

	encoded := MarshalConnectivity(&orig)
	if encoded.Type != TypeConnectivity {
		t.Fatalf("expected type %d, got %d", TypeConnectivity, encoded.Type)
	}
	if len(encoded.Value) != ConnectivitySize {
		t.Fatalf("expected %d bytes, got %d", ConnectivitySize, len(encoded.Value))
	}

	decoded, err := UnmarshalConnectivity(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

// --- MacCounters round-trip ---

func TestMacCountersRoundTrip(t *testing.T) {
	orig := MacCounters{
		IfInUnknownProtos:  100,
		IfInErrors:         200,
		IfOutErrors:        300,
		IfInUcastPkts:      1000,
		IfInBroadcastPkts:  2000,
		IfInDiscards:       50,
		IfOutUcastPkts:     3000,
		IfOutBroadcastPkts: 4000,
		IfOutDiscards:      75,
	}

	encoded := MarshalMacCounters(&orig)
	if encoded.Type != TypeMacCounters {
		t.Fatalf("expected type %d, got %d", TypeMacCounters, encoded.Type)
	}
	if len(encoded.Value) != MacCountersSize {
		t.Fatalf("expected %d bytes, got %d", MacCountersSize, len(encoded.Value))
	}

	decoded, err := UnmarshalMacCounters(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

// --- MleCounters round-trip ---

func TestMleCountersRoundTrip(t *testing.T) {
	orig := MleCounters{
		DisabledRole:                  1,
		DetachedRole:                  2,
		ChildRole:                     3,
		RouterRole:                    4,
		LeaderRole:                    5,
		AttachAttempts:                6,
		PartitionIDChanges:            7,
		BetterPartitionAttachAttempts: 8,
		ParentChanges:                 9,
		TrackedTime:                   1000000,
		DisabledTime:                  200000,
		DetachedTime:                  300000,
		ChildTime:                     400000,
		RouterTime:                    500000,
		LeaderTime:                    600000,
	}

	encoded := MarshalMleCounters(&orig)
	if encoded.Type != TypeMleCounters {
		t.Fatalf("expected type %d, got %d", TypeMleCounters, encoded.Type)
	}
	if len(encoded.Value) != MleCountersSize {
		t.Fatalf("expected %d bytes, got %d", MleCountersSize, len(encoded.Value))
	}

	decoded, err := UnmarshalMleCounters(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

// --- ChildTableEntry round-trip ---

func TestChildTableEntryRoundTrip(t *testing.T) {
	orig := ChildTableEntry{
		Timeout:       10,
		ChildID:       255,
		LinkQualityIn: 3,
		Mode:          0x0F,
	}

	buf := MarshalChildTableEntry(&orig)
	if len(buf) != ChildTableEntrySize {
		t.Fatalf("expected %d bytes, got %d", ChildTableEntrySize, len(buf))
	}

	decoded, err := UnmarshalChildTableEntry(buf)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

func TestChildTableRoundTrip(t *testing.T) {
	entries := []ChildTableEntry{
		{Timeout: 5, ChildID: 1, LinkQualityIn: 2, Mode: 0x0E},
		{Timeout: 10, ChildID: 200, LinkQualityIn: 1, Mode: 0x0F},
		{Timeout: 31, ChildID: 511, LinkQualityIn: 3, Mode: 0x04},
	}

	encoded := MarshalChildTable(entries)
	if encoded.Type != TypeChildTable {
		t.Fatalf("expected type %d, got %d", TypeChildTable, encoded.Type)
	}

	decoded, err := UnmarshalChildTable(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if len(decoded) != len(entries) {
		t.Fatalf("expected %d entries, got %d", len(entries), len(decoded))
	}

	for i, e := range entries {
		if decoded[i] != e {
			t.Fatalf("entry %d mismatch:\n  got  %+v\n  want %+v", i, decoded[i], e)
		}
	}
}

// --- ChildTlv round-trip ---

func TestChildTlvRoundTrip(t *testing.T) {
	orig := ChildTlv{
		Flags:               ChildTlvFlagRxOnWhenIdle | ChildTlvFlagFTD,
		RLOC16:              0x1801,
		ExtAddress:          mactypes.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		Version:             4,
		Timeout:             120,
		Age:                 60,
		ConnectionTime:      3600,
		SupervisionInterval: 10,
	}

	encoded := MarshalChildTlv(&orig)
	if encoded.Type != TypeChild {
		t.Fatalf("expected type %d, got %d", TypeChild, encoded.Type)
	}

	decoded, err := UnmarshalChildTlv(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

// --- RouterNeighborTlv round-trip ---

func TestRouterNeighborTlvRoundTrip(t *testing.T) {
	orig := RouterNeighborTlv{
		Flags:            RouterNeighborFlagTrackEui64,
		RLOC16:           0x2000,
		ExtAddress:       mactypes.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22},
		Version:          4,
		ConnectionTime:   7200,
		LinkMargin:       20,
		AverageRSSI:      -60,
		LastRSSI:         -55,
		FrameErrorRate:   100,
		MessageErrorRate: 50,
	}

	encoded := MarshalRouterNeighborTlv(&orig)
	if encoded.Type != TypeRouterNeighbor {
		t.Fatalf("expected type %d, got %d", TypeRouterNeighbor, encoded.Type)
	}

	decoded, err := UnmarshalRouterNeighborTlv(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded != orig {
		t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
	}
}

// --- AnswerTlv round-trip ---

func TestAnswerTlvRoundTrip(t *testing.T) {
	tests := []AnswerTlv{
		{IsLast: false, Index: 0},
		{IsLast: false, Index: 42},
		{IsLast: true, Index: 0},
		{IsLast: true, Index: 32767},
	}

	for _, orig := range tests {
		encoded := MarshalAnswerTlv(&orig)
		if encoded.Type != TypeAnswer {
			t.Fatalf("expected type %d, got %d", TypeAnswer, encoded.Type)
		}

		decoded, err := UnmarshalAnswerTlv(encoded.Value)
		if err != nil {
			t.Fatal(err)
		}

		if decoded != orig {
			t.Fatalf("round-trip mismatch:\n  got  %+v\n  want %+v", decoded, orig)
		}
	}
}

// --- Route64 round-trip ---

func TestRoute64RoundTrip(t *testing.T) {
	orig := Route64{
		IDSequence:  5,
		RouterIDSet: [8]byte{0x80, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // router IDs 0 and 9
		RouteData: []Route64Entry{
			{RouterID: 0, LinkQualityOut: 3, LinkQualityIn: 2, RouteCost: 5},
			{RouterID: 9, LinkQualityOut: 1, LinkQualityIn: 1, RouteCost: 8},
		},
	}

	encoded := MarshalRoute64(&orig)
	if encoded.Type != TypeRoute64 {
		t.Fatalf("expected type %d, got %d", TypeRoute64, encoded.Type)
	}

	decoded, err := UnmarshalRoute64(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.IDSequence != orig.IDSequence {
		t.Fatalf("IDSequence mismatch: got %d, want %d", decoded.IDSequence, orig.IDSequence)
	}
	if decoded.RouterIDSet != orig.RouterIDSet {
		t.Fatalf("RouterIDSet mismatch")
	}
	if len(decoded.RouteData) != len(orig.RouteData) {
		t.Fatalf("RouteData length mismatch: got %d, want %d", len(decoded.RouteData), len(orig.RouteData))
	}
	for i, e := range orig.RouteData {
		if decoded.RouteData[i] != e {
			t.Fatalf("RouteData[%d] mismatch:\n  got  %+v\n  want %+v", i, decoded.RouteData[i], e)
		}
	}
}

// --- Scalar TLV helpers ---

func TestUint16TLVRoundTrip(t *testing.T) {
	encoded := MarshalUint16TLV(TypeAddress16, 0x1800)
	decoded, err := UnmarshalUint16TLV(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != 0x1800 {
		t.Fatalf("expected 0x1800, got 0x%04x", decoded)
	}
}

func TestUint32TLVRoundTrip(t *testing.T) {
	encoded := MarshalUint32TLV(TypeTimeout, 120)
	decoded, err := UnmarshalUint32TLV(encoded.Value)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != 120 {
		t.Fatalf("expected 120, got %d", decoded)
	}
}

// --- Full TLV wire format ---

func TestMarshalThenParseConnectivity(t *testing.T) {
	c := Connectivity{
		ParentPriority:   1,
		LinkQuality3:     0,
		LinkQuality2:     1,
		LinkQuality1:     2,
		LeaderCost:       3,
		IDSequence:       7,
		ActiveRouters:    5,
		SEDBufferSize:    256,
		SEDDatagramCount: 2,
	}

	wire := MarshalConnectivity(&c).Marshal()
	parsed, _, err := tlv.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Type != TypeConnectivity {
		t.Fatalf("type mismatch: got %d, want %d", parsed.Type, TypeConnectivity)
	}

	decoded, err := UnmarshalConnectivity(parsed.Value)
	if err != nil {
		t.Fatal(err)
	}
	if decoded != c {
		t.Fatalf("decode mismatch:\n  got  %+v\n  want %+v", decoded, c)
	}
}

// --- Error cases ---

func TestUnmarshalTruncated(t *testing.T) {
	_, err := UnmarshalConnectivity([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for truncated connectivity data")
	}

	_, err = UnmarshalMacCounters(make([]byte, MacCountersSize-1))
	if err == nil {
		t.Fatal("expected error for truncated mac counters data")
	}

	_, err = UnmarshalMleCounters(make([]byte, MleCountersSize-1))
	if err == nil {
		t.Fatal("expected error for truncated mle counters data")
	}

	_, err = UnmarshalChildTableEntry([]byte{1})
	if err == nil {
		t.Fatal("expected error for truncated child table entry")
	}

	_, err = UnmarshalChildTlv(make([]byte, ChildTlvSize-1))
	if err == nil {
		t.Fatal("expected error for truncated child tlv")
	}

	_, err = UnmarshalRouterNeighborTlv(make([]byte, RouterNeighborTlvSize-1))
	if err == nil {
		t.Fatal("expected error for truncated router neighbor tlv")
	}

	_, err = UnmarshalAnswerTlv([]byte{1})
	if err == nil {
		t.Fatal("expected error for truncated answer tlv")
	}

	_, err = UnmarshalRoute64([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for truncated route64 data")
	}
}

func TestChildTableBadLength(t *testing.T) {
	// 4 bytes is not a multiple of ChildTableEntrySize (3).
	_, err := UnmarshalChildTable(make([]byte, 4))
	if err == nil {
		t.Fatal("expected error for invalid child table length")
	}
}

// --- mockProvider for Server tests ---

type mockProvider struct {
	extMac       mactypes.ExtAddress
	rloc16       uint16
	mode         uint8
	timeout      uint32
	connectivity *Connectivity
	route64      *Route64
	macCounters  *MacCounters
	mleCounters  *MleCounters
	version      uint16
	vendorName   string
	childTable   []ChildTableEntry
	batteryLevel uint8
	hasBattery   bool
}

func (m *mockProvider) GetExtMacAddress() ([]byte, bool) { return m.extMac[:], true }
func (m *mockProvider) GetAddress16() (uint16, bool)     { return m.rloc16, true }
func (m *mockProvider) GetMode() (uint8, bool)           { return m.mode, true }
func (m *mockProvider) GetTimeout() (uint32, bool)       { return m.timeout, true }
func (m *mockProvider) GetConnectivity() (*Connectivity, bool) {
	if m.connectivity == nil {
		return nil, false
	}
	return m.connectivity, true
}
func (m *mockProvider) GetRoute64() (*Route64, bool) {
	if m.route64 == nil {
		return nil, false
	}
	return m.route64, true
}
func (m *mockProvider) GetLeaderData() ([]byte, bool)      { return nil, false }
func (m *mockProvider) GetNetworkData() ([]byte, bool)     { return nil, false }
func (m *mockProvider) GetIPv6AddressList() ([]byte, bool) { return nil, false }
func (m *mockProvider) GetMacCounters() (*MacCounters, bool) {
	if m.macCounters == nil {
		return nil, false
	}
	return m.macCounters, true
}
func (m *mockProvider) GetBatteryLevel() (uint8, bool) {
	if !m.hasBattery {
		return 0, false
	}
	return m.batteryLevel, true
}
func (m *mockProvider) GetSupplyVoltage() (uint16, bool) { return 0, false }
func (m *mockProvider) GetChildTable() ([]ChildTableEntry, bool) {
	if m.childTable == nil {
		return nil, false
	}
	return m.childTable, true
}
func (m *mockProvider) GetChannelPages() ([]byte, bool)       { return nil, false }
func (m *mockProvider) GetMaxChildTimeout() (uint32, bool)    { return 0, false }
func (m *mockProvider) GetVersion() (uint16, bool)            { return m.version, true }
func (m *mockProvider) GetVendorName() (string, bool)         { return m.vendorName, true }
func (m *mockProvider) GetVendorModel() (string, bool)        { return "", false }
func (m *mockProvider) GetVendorSWVersion() (string, bool)    { return "", false }
func (m *mockProvider) GetThreadStackVersion() (string, bool) { return "", false }
func (m *mockProvider) GetMleCounters() (*MleCounters, bool) {
	if m.mleCounters == nil {
		return nil, false
	}
	return m.mleCounters, true
}

// --- Server tests ---

func TestServerHandleGetRequest(t *testing.T) {
	provider := &mockProvider{
		extMac:  mactypes.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		rloc16:  0x1800,
		mode:    0x0F,
		version: 4,
	}

	server := NewServer(provider)

	// Build a request asking for ExtMacAddress, Address16, Mode, Version.
	requestedTypes := []uint8{TypeExtMacAddress, TypeAddress16, TypeMode, TypeVersion}
	typeListTLV := MarshalBytesTLV(TypeTypeList, requestedTypes)
	queryIDTLV := MarshalUint16TLV(TypeQueryID, 42)
	requestPayload := append(typeListTLV.Marshal(), queryIDTLV.Marshal()...)

	response, err := server.HandleGetRequest(requestPayload)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the response.
	tlvs, err := tlv.ParseAll(response)
	if err != nil {
		t.Fatal(err)
	}

	// We should have 5 TLVs: ExtMacAddress, Address16, Mode, Version, QueryID.
	if len(tlvs) != 5 {
		t.Fatalf("expected 5 TLVs, got %d", len(tlvs))
	}

	// Check ExtMacAddress.
	extMacTlv := tlv.FindByType(tlvs, TypeExtMacAddress)
	if extMacTlv == nil {
		t.Fatal("missing ExtMacAddress TLV")
	}
	if !bytes.Equal(extMacTlv.Value, provider.extMac[:]) {
		t.Fatalf("ExtMacAddress mismatch")
	}

	// Check Address16.
	addr16Tlv := tlv.FindByType(tlvs, TypeAddress16)
	if addr16Tlv == nil {
		t.Fatal("missing Address16 TLV")
	}
	addr16, err := UnmarshalUint16TLV(addr16Tlv.Value)
	if err != nil {
		t.Fatal(err)
	}
	if addr16 != 0x1800 {
		t.Fatalf("Address16 mismatch: got 0x%04x, want 0x1800", addr16)
	}

	// Check QueryID is echoed back.
	qidTlv := tlv.FindByType(tlvs, TypeQueryID)
	if qidTlv == nil {
		t.Fatal("missing QueryID TLV")
	}
	qid, err := UnmarshalUint16TLV(qidTlv.Value)
	if err != nil {
		t.Fatal(err)
	}
	if qid != 42 {
		t.Fatalf("QueryID mismatch: got %d, want 42", qid)
	}
}

func TestServerSkipsUnavailableTLVs(t *testing.T) {
	provider := &mockProvider{
		rloc16:  0x1800,
		version: 4,
	}

	server := NewServer(provider)

	// Request BatteryLevel (not available) and Version (available).
	requestedTypes := []uint8{TypeBatteryLevel, TypeVersion}
	typeListTLV := MarshalBytesTLV(TypeTypeList, requestedTypes)
	requestPayload := typeListTLV.Marshal()

	response, err := server.HandleGetRequest(requestPayload)
	if err != nil {
		t.Fatal(err)
	}

	tlvs, err := tlv.ParseAll(response)
	if err != nil {
		t.Fatal(err)
	}

	// Only Version should be present.
	if len(tlvs) != 1 {
		t.Fatalf("expected 1 TLV, got %d", len(tlvs))
	}
	if tlvs[0].Type != TypeVersion {
		t.Fatalf("expected Version TLV, got type %d", tlvs[0].Type)
	}
}

// --- Client tests ---

func TestClientBuildDiagnosticGetRequest(t *testing.T) {
	client := NewClient()

	payload, queryID := client.BuildDiagnosticGetRequest([]uint8{TypeMode, TypeVersion})
	if queryID != 0 {
		t.Fatalf("first query ID should be 0, got %d", queryID)
	}

	// Parse the payload.
	tlvs, err := tlv.ParseAll(payload)
	if err != nil {
		t.Fatal(err)
	}

	typeListTlv := tlv.FindByType(tlvs, TypeTypeList)
	if typeListTlv == nil {
		t.Fatal("missing TypeList TLV")
	}
	if !bytes.Equal(typeListTlv.Value, []uint8{TypeMode, TypeVersion}) {
		t.Fatalf("TypeList mismatch")
	}

	qidTlv := tlv.FindByType(tlvs, TypeQueryID)
	if qidTlv == nil {
		t.Fatal("missing QueryID TLV")
	}

	// Second request should increment.
	_, queryID2 := client.BuildDiagnosticGetRequest([]uint8{TypeMode})
	if queryID2 != 1 {
		t.Fatalf("second query ID should be 1, got %d", queryID2)
	}
}

func TestClientHandleResponse(t *testing.T) {
	client := NewClient()

	_, queryID := client.BuildDiagnosticGetRequest([]uint8{TypeMode})

	var received bool
	client.RegisterQuery(queryID, ip6.Address{}, func(source ip6.Address, tlvs []tlv.TLV) {
		received = true
	})

	if client.PendingCount() != 1 {
		t.Fatalf("expected 1 pending, got %d", client.PendingCount())
	}

	// Build a response with mode TLV + queryID TLV + answer(isLast=true).
	modeTLV := MarshalByteTLV(TypeMode, 0x0F)
	qidTLV := MarshalUint16TLV(TypeQueryID, queryID)
	answerTLV := MarshalAnswerTlv(&AnswerTlv{IsLast: true, Index: 0})

	responsePayload := modeTLV.Marshal()
	responsePayload = append(responsePayload, qidTLV.Marshal()...)
	responsePayload = append(responsePayload, answerTLV.Marshal()...)

	err := client.HandleResponse(ip6.Address{}, responsePayload)
	if err != nil {
		t.Fatal(err)
	}

	if !received {
		t.Fatal("handler was not called")
	}

	if client.PendingCount() != 0 {
		t.Fatalf("expected 0 pending after last response, got %d", client.PendingCount())
	}
}

func TestClientMultiPartResponse(t *testing.T) {
	client := NewClient()

	_, queryID := client.BuildDiagnosticGetRequest([]uint8{TypeMode})

	callCount := 0
	client.RegisterQuery(queryID, ip6.Address{}, func(source ip6.Address, tlvs []tlv.TLV) {
		callCount++
	})

	// First fragment: not last.
	modeTLV := MarshalByteTLV(TypeMode, 0x0F)
	qidTLV := MarshalUint16TLV(TypeQueryID, queryID)
	answer1 := MarshalAnswerTlv(&AnswerTlv{IsLast: false, Index: 0})

	frag1 := modeTLV.Marshal()
	frag1 = append(frag1, qidTLV.Marshal()...)
	frag1 = append(frag1, answer1.Marshal()...)

	err := client.HandleResponse(ip6.Address{}, frag1)
	if err != nil {
		t.Fatal(err)
	}

	if callCount != 1 {
		t.Fatalf("expected 1 call, got %d", callCount)
	}
	if client.PendingCount() != 1 {
		t.Fatalf("query should still be pending, got %d", client.PendingCount())
	}

	// Second fragment: last.
	answer2 := MarshalAnswerTlv(&AnswerTlv{IsLast: true, Index: 1})
	frag2 := modeTLV.Marshal()
	frag2 = append(frag2, qidTLV.Marshal()...)
	frag2 = append(frag2, answer2.Marshal()...)

	err = client.HandleResponse(ip6.Address{}, frag2)
	if err != nil {
		t.Fatal(err)
	}

	if callCount != 2 {
		t.Fatalf("expected 2 calls, got %d", callCount)
	}
	if client.PendingCount() != 0 {
		t.Fatalf("query should be completed, got %d pending", client.PendingCount())
	}
}

func TestClientCancelQuery(t *testing.T) {
	client := NewClient()
	_, queryID := client.BuildDiagnosticGetRequest([]uint8{TypeMode})
	client.RegisterQuery(queryID, ip6.Address{}, nil)

	err := client.CancelQuery(queryID)
	if err != nil {
		t.Fatal(err)
	}
	if client.PendingCount() != 0 {
		t.Fatalf("expected 0 pending after cancel, got %d", client.PendingCount())
	}

	// Cancel nonexistent.
	err = client.CancelQuery(999)
	if err == nil {
		t.Fatal("expected error canceling nonexistent query")
	}
}

func TestClientHandleResponseNoMatch(t *testing.T) {
	client := NewClient()

	qidTLV := MarshalUint16TLV(TypeQueryID, 999)
	err := client.HandleResponse(ip6.Address{}, qidTLV.Marshal())
	if err == nil {
		t.Fatal("expected ErrNotFound for unmatched query")
	}
}

// --- Diagnostic Reset ---

func TestBuildDiagnosticResetRequest(t *testing.T) {
	payload := BuildDiagnosticResetRequest([]uint8{TypeMacCounters, TypeMleCounters})

	tlvs, err := tlv.ParseAll(payload)
	if err != nil {
		t.Fatal(err)
	}

	typeListTlv := tlv.FindByType(tlvs, TypeTypeList)
	if typeListTlv == nil {
		t.Fatal("missing TypeList TLV")
	}
	if !bytes.Equal(typeListTlv.Value, []uint8{TypeMacCounters, TypeMleCounters}) {
		t.Fatal("TypeList mismatch")
	}
}

// --- ParseTypeList and ParseQueryID ---

func TestParseTypeList(t *testing.T) {
	typeListTLV := MarshalBytesTLV(TypeTypeList, []uint8{TypeMode, TypeVersion, TypeMacCounters})
	payload := typeListTLV.Marshal()

	types, err := ParseTypeList(payload)
	if err != nil {
		t.Fatal(err)
	}
	expected := []uint8{TypeMode, TypeVersion, TypeMacCounters}
	if !bytes.Equal(types, expected) {
		t.Fatalf("got %v, want %v", types, expected)
	}
}

func TestParseQueryID(t *testing.T) {
	qidTLV := MarshalUint16TLV(TypeQueryID, 1234)
	payload := qidTLV.Marshal()

	qid, ok := ParseQueryID(payload)
	if !ok {
		t.Fatal("expected to find query ID")
	}
	if qid != 1234 {
		t.Fatalf("got %d, want 1234", qid)
	}

	// No query ID.
	typeListTLV := MarshalBytesTLV(TypeTypeList, []uint8{TypeMode})
	_, ok = ParseQueryID(typeListTLV.Marshal())
	if ok {
		t.Fatal("expected no query ID found")
	}
}

// --- String/Bytes TLV ---

func TestStringTLV(t *testing.T) {
	vendorTLV := MarshalStringTLV(TypeVendorName, "GoThread")
	if vendorTLV.Type != TypeVendorName {
		t.Fatalf("type mismatch")
	}
	if string(vendorTLV.Value) != "GoThread" {
		t.Fatalf("value mismatch: got %q", string(vendorTLV.Value))
	}
}
