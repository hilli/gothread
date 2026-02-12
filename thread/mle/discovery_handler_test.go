// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/discover"
	"github.com/hilli/gothread/thread/key"
)

// --- mock NetworkInfoProvider ---

type mockNetworkInfo struct {
	networkName          string
	extendedPanID        [8]byte
	steeringData         []byte
	isNativeCommissioner bool
}

func (m *mockNetworkInfo) GetNetworkName() string     { return m.networkName }
func (m *mockNetworkInfo) GetExtendedPanID() [8]byte  { return m.extendedPanID }
func (m *mockNetworkInfo) GetSteeringData() []byte    { return m.steeringData }
func (m *mockNetworkInfo) IsNativeCommissioner() bool { return m.isNativeCommissioner }

// --- test setup ---

func newDiscoveryHandlerTestSetup(role DeviceRole, routerID uint8) (
	*DiscoveryHandler, *Mle, *Dispatcher, *mockTransport, *mockNetworkInfo,
) {
	m := NewMle()
	_ = m.Enable()

	m.mu.Lock()
	m.role = role
	m.rloc16 = RLOC16FromRouterID(routerID)
	m.ftd.routerID = routerID
	m.routerEligible = true
	m.mu.Unlock()

	transport := &mockTransport{
		extAddr: types.ExtAddress{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x44},
		linkLocal: ip6.Address{
			0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			0xA8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x44,
		},
	}

	keyMgr := &mockKeyProvider{
		currentSeq:      5,
		currentKey:      key.MleKey{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10},
		macFrameCounter: 1000,
		mleFrameCounter: 2000,
	}

	networkInfo := &mockNetworkInfo{
		networkName:          "TestThread",
		extendedPanID:        [8]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE},
		steeringData:         nil,
		isNativeCommissioner: false,
	}

	d := NewDispatcher(m, keyMgr, transport)
	h := NewDiscoveryHandler(m, d, networkInfo)

	return h, m, d, transport, networkInfo
}

// buildDiscoveryRequestSubTLVs builds raw MeshCoP sub-TLV bytes for a
// DiscoveryRequest with the given version and joiner flag.
func buildDiscoveryRequestSubTLVs(version uint16, isJoiner bool) []byte {
	data := encodeDiscoveryRequest(DiscoveryRequestData{
		Version:  version,
		IsJoiner: isJoiner,
	})
	var buf []byte
	buf = appendMeshCoPSubTLV(buf, meshcop.TLVDiscoveryRequest, data[:])
	return buf
}

// buildDiscoveryRequestRxInfo creates an RxInfo simulating a received
// Discovery Request with configurable parameters.
func buildDiscoveryRequestRxInfo(discoveryTLVValue []byte) *RxInfo {
	var tlvs []TLV
	if discoveryTLVValue != nil {
		tlvs = append(tlvs, TLV{Type: TLVDiscovery, Value: discoveryTLVValue})
	}

	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xBB}
	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))

	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         LinkLocalAllNodesMulticast,
		LinkMarginRaw: 20,
		Command:       CommandDiscoveryRequest,
		TLVs:          tlvs,
		IsSecured:     false,
	}
}

// --- NewDiscoveryHandler tests ---

func TestNewDiscoveryHandler_RegistersOnDispatcher(t *testing.T) {
	t.Parallel()

	h, _, d, _, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)

	if h == nil {
		t.Fatal("NewDiscoveryHandler returned nil")
	}

	if _, ok := d.handlers[CommandDiscoveryRequest]; !ok {
		t.Error("DiscoveryHandler should register for CommandDiscoveryRequest")
	}
}

// --- HandleDiscoveryRequest tests ---

func TestHandleDiscoveryRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		role    DeviceRole
		setup   func(*mockNetworkInfo)
		buildRx func() *RxInfo
		wantErr bool
		verify  func(*testing.T, *mockTransport)
	}{
		{
			name: "rejects missing Discovery TLV",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				return buildDiscoveryRequestRxInfo(nil)
			},
			wantErr: true,
		},
		{
			name: "rejects empty Discovery TLV value",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				return buildDiscoveryRequestRxInfo([]byte{})
			},
			wantErr: true, // empty sub-TLVs → missing DiscoveryRequest sub-TLV
		},
		{
			name: "rejects missing DiscoveryRequest sub-TLV",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				// Discovery TLV with unrelated sub-TLV data.
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte("test"))
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: true,
		},
		{
			name: "ignores when role is Child",
			role: RoleChild,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "ignores when role is Detached",
			role: RoleDetached,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "ignores when role is Disabled",
			role: RoleDisabled,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "ignores incompatible version (requester too old)",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				// Version 2 is below our ThreadVersion of 4.
				subTLVs := buildDiscoveryRequestSubTLVs(2, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 0 {
					t.Errorf("expected no messages sent for old version, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "responds as Router with compatible version",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]
				// Response should be unsecured (first byte = SecuritySuiteNone).
				if msg.data[0] != SecuritySuiteNone {
					t.Errorf("response security suite = 0x%02X, want 0x%02X", msg.data[0], SecuritySuiteNone)
				}
				// Command byte should be DiscoveryResponse.
				if Command(msg.data[1]) != CommandDiscoveryResponse {
					t.Errorf("response command = %d, want %d", msg.data[1], CommandDiscoveryResponse)
				}
			},
		},
		{
			name: "responds as Leader",
			role: RoleLeader,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "responds to higher version requester",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				// Version 5 is above ThreadVersion 4 — should still respond.
				subTLVs := buildDiscoveryRequestSubTLVs(5, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "responds to Joiner request",
			role: RoleRouter,
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, true)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
			},
		},
		{
			name: "includes steering data when available",
			role: RoleRouter,
			setup: func(ni *mockNetworkInfo) {
				ni.steeringData = []byte{0xFF, 0x00, 0xAA}
			},
			buildRx: func() *RxInfo {
				subTLVs := buildDiscoveryRequestSubTLVs(ThreadVersion, false)
				return buildDiscoveryRequestRxInfo(subTLVs)
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				// Parse the sent message to verify steering data is present.
				msg := transport.sentMessages[0]
				pm, err := ParseMessage(msg.data)
				if err != nil {
					t.Fatalf("failed to parse sent message: %v", err)
				}
				// Unsecured: payload starts with command byte.
				payload := pm.Payload
				if len(payload) < 1 {
					t.Fatal("empty payload")
				}
				tlvs, err := ParseTLVs(payload[1:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}
				discoveryVal, ok := FindTLV(tlvs, TLVDiscovery)
				if !ok {
					t.Fatal("missing Discovery TLV in response")
				}
				subTLVs, err := parseMeshCoPSubTLVs(discoveryVal)
				if err != nil {
					t.Fatalf("failed to parse sub-TLVs: %v", err)
				}
				steeringVal, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData)
				if !ok {
					t.Fatal("expected SteeringData sub-TLV in response")
				}
				if len(steeringVal) != 3 || steeringVal[0] != 0xFF || steeringVal[1] != 0x00 || steeringVal[2] != 0xAA {
					t.Errorf("SteeringData = %x, want ff00aa", steeringVal)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, _, _, transport, networkInfo := newDiscoveryHandlerTestSetup(tt.role, 3)

			if tt.setup != nil {
				tt.setup(networkInfo)
			}

			rxInfo := tt.buildRx()
			err := h.HandleDiscoveryRequest(rxInfo)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.verify != nil {
				tt.verify(t, transport)
			}
		})
	}
}

// --- SendDiscoveryResponse tests ---

func TestSendDiscoveryResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(*mockNetworkInfo)
		dst     ip6.Address
		wantErr bool
		verify  func(*testing.T, *mockTransport, *mockNetworkInfo)
	}{
		{
			name: "sends response with correct contents",
			dst: ip6.Address{
				0xfe, 0x80, 0, 0, 0, 0, 0, 0,
				0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xBB,
			},
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport, ni *mockNetworkInfo) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]

				// Should be unsecured.
				if msg.data[0] != SecuritySuiteNone {
					t.Errorf("security suite = 0x%02X, want 0x%02X", msg.data[0], SecuritySuiteNone)
				}

				// Command should be DiscoveryResponse.
				if Command(msg.data[1]) != CommandDiscoveryResponse {
					t.Errorf("command = %d, want %d", msg.data[1], CommandDiscoveryResponse)
				}

				// Parse the response to check sub-TLVs.
				tlvs, err := ParseTLVs(msg.data[2:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}

				parsed, err := ParseDiscoveryResponse(tlvs)
				if err != nil {
					t.Fatalf("failed to parse discovery response: %v", err)
				}

				if parsed.Version != ThreadVersion {
					t.Errorf("version = %d, want %d", parsed.Version, ThreadVersion)
				}
				if parsed.IsNativeCommissioner != ni.isNativeCommissioner {
					t.Errorf("isNativeCommissioner = %v, want %v", parsed.IsNativeCommissioner, ni.isNativeCommissioner)
				}
				if parsed.ExtendedPanID != ni.extendedPanID {
					t.Errorf("extendedPanID = %x, want %x", parsed.ExtendedPanID, ni.extendedPanID)
				}
				if parsed.NetworkName != ni.networkName {
					t.Errorf("networkName = %q, want %q", parsed.NetworkName, ni.networkName)
				}
			},
		},
		{
			name: "includes native commissioner flag",
			setup: func(ni *mockNetworkInfo) {
				ni.isNativeCommissioner = true
			},
			dst:     LinkLocalAllNodesMulticast,
			wantErr: false,
			verify: func(t *testing.T, transport *mockTransport, _ *mockNetworkInfo) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]
				tlvs, err := ParseTLVs(msg.data[2:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}
				parsed, err := ParseDiscoveryResponse(tlvs)
				if err != nil {
					t.Fatalf("failed to parse discovery response: %v", err)
				}
				if !parsed.IsNativeCommissioner {
					t.Error("expected IsNativeCommissioner to be true")
				}
			},
		},
		{
			name: "omits steering data when nil",
			dst:  LinkLocalAllNodesMulticast,
			verify: func(t *testing.T, transport *mockTransport, _ *mockNetworkInfo) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]
				tlvs, err := ParseTLVs(msg.data[2:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}
				discoveryVal, ok := FindTLV(tlvs, TLVDiscovery)
				if !ok {
					t.Fatal("missing Discovery TLV")
				}
				subTLVs, err := parseMeshCoPSubTLVs(discoveryVal)
				if err != nil {
					t.Fatalf("failed to parse sub-TLVs: %v", err)
				}
				if _, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData); ok {
					t.Error("expected no SteeringData sub-TLV when steering data is nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, _, _, transport, networkInfo := newDiscoveryHandlerTestSetup(RoleRouter, 3)

			if tt.setup != nil {
				tt.setup(networkInfo)
			}

			err := h.SendDiscoveryResponse(tt.dst)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.verify != nil {
				tt.verify(t, transport, networkInfo)
			}
		})
	}
}

// --- SendDiscoveryRequest tests ---

func TestSendDiscoveryRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		isJoiner bool
		wantErr  bool
		verify   func(*testing.T, *mockTransport)
	}{
		{
			name:     "sends non-joiner discovery request",
			isJoiner: false,
			wantErr:  false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]

				// Should be unsecured.
				if msg.data[0] != SecuritySuiteNone {
					t.Errorf("security suite = 0x%02X, want 0x%02X", msg.data[0], SecuritySuiteNone)
				}

				// Command should be DiscoveryRequest.
				if Command(msg.data[1]) != CommandDiscoveryRequest {
					t.Errorf("command = %d, want %d", msg.data[1], CommandDiscoveryRequest)
				}

				// Destination should be all-nodes multicast.
				if msg.dst != LinkLocalAllNodesMulticast {
					t.Errorf("dst = %v, want %v", msg.dst, LinkLocalAllNodesMulticast)
				}

				// Parse and verify the Discovery Request sub-TLV.
				tlvs, err := ParseTLVs(msg.data[2:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}
				discoveryVal, ok := FindTLV(tlvs, TLVDiscovery)
				if !ok {
					t.Fatal("missing Discovery TLV")
				}
				subTLVs, err := parseMeshCoPSubTLVs(discoveryVal)
				if err != nil {
					t.Fatalf("failed to parse sub-TLVs: %v", err)
				}
				reqValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryRequest)
				if !ok {
					t.Fatal("missing DiscoveryRequest sub-TLV")
				}
				reqData, err := decodeDiscoveryRequest(reqValue)
				if err != nil {
					t.Fatalf("failed to decode DiscoveryRequest: %v", err)
				}
				if reqData.Version != ThreadVersion {
					t.Errorf("version = %d, want %d", reqData.Version, ThreadVersion)
				}
				if reqData.IsJoiner {
					t.Error("expected IsJoiner to be false")
				}
			},
		},
		{
			name:     "sends joiner discovery request",
			isJoiner: true,
			wantErr:  false,
			verify: func(t *testing.T, transport *mockTransport) {
				t.Helper()
				if len(transport.sentMessages) != 1 {
					t.Fatalf("expected 1 sent message, got %d", len(transport.sentMessages))
				}
				msg := transport.sentMessages[0]

				// Parse and verify joiner flag.
				tlvs, err := ParseTLVs(msg.data[2:])
				if err != nil {
					t.Fatalf("failed to parse TLVs: %v", err)
				}
				discoveryVal, ok := FindTLV(tlvs, TLVDiscovery)
				if !ok {
					t.Fatal("missing Discovery TLV")
				}
				subTLVs, err := parseMeshCoPSubTLVs(discoveryVal)
				if err != nil {
					t.Fatalf("failed to parse sub-TLVs: %v", err)
				}
				reqValue, ok := findMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryRequest)
				if !ok {
					t.Fatal("missing DiscoveryRequest sub-TLV")
				}
				reqData, err := decodeDiscoveryRequest(reqValue)
				if err != nil {
					t.Fatalf("failed to decode DiscoveryRequest: %v", err)
				}
				if !reqData.IsJoiner {
					t.Error("expected IsJoiner to be true")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h, _, _, transport, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)

			err := h.SendDiscoveryRequest(tt.isJoiner)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.verify != nil {
				tt.verify(t, transport)
			}
		})
	}
}

// --- ParseDiscoveryResponse tests ---

func TestParseDiscoveryResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tlvs    []TLV
		wantErr bool
		verify  func(*testing.T, *ParsedDiscoveryResponse)
	}{
		{
			name:    "rejects missing Discovery TLV",
			tlvs:    []TLV{},
			wantErr: true,
		},
		{
			name: "rejects missing DiscoveryResponse sub-TLV",
			tlvs: func() []TLV {
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, make([]byte, 8))
				return []TLV{{Type: TLVDiscovery, Value: subTLVs}}
			}(),
			wantErr: true,
		},
		{
			name: "rejects missing ExtendedPanID sub-TLV",
			tlvs: func() []TLV {
				resp := encodeDiscoveryResponse(DiscoveryResponseData{Version: 4})
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, resp[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte("test"))
				return []TLV{{Type: TLVDiscovery, Value: subTLVs}}
			}(),
			wantErr: true,
		},
		{
			name: "rejects missing NetworkName sub-TLV",
			tlvs: func() []TLV {
				resp := encodeDiscoveryResponse(DiscoveryResponseData{Version: 4})
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, resp[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, make([]byte, 8))
				return []TLV{{Type: TLVDiscovery, Value: subTLVs}}
			}(),
			wantErr: true,
		},
		{
			name: "parses complete response without steering data",
			tlvs: func() []TLV {
				resp := encodeDiscoveryResponse(DiscoveryResponseData{
					Version:              4,
					IsNativeCommissioner: true,
				})
				extPanID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, resp[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, extPanID[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte("MyNetwork"))
				return []TLV{{Type: TLVDiscovery, Value: subTLVs}}
			}(),
			wantErr: false,
			verify: func(t *testing.T, parsed *ParsedDiscoveryResponse) {
				t.Helper()
				if parsed.Version != 4 {
					t.Errorf("version = %d, want 4", parsed.Version)
				}
				if !parsed.IsNativeCommissioner {
					t.Error("expected IsNativeCommissioner to be true")
				}
				expectedExtPanID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
				if parsed.ExtendedPanID != expectedExtPanID {
					t.Errorf("ExtendedPanID = %x, want %x", parsed.ExtendedPanID, expectedExtPanID)
				}
				if parsed.NetworkName != "MyNetwork" {
					t.Errorf("NetworkName = %q, want %q", parsed.NetworkName, "MyNetwork")
				}
				if parsed.SteeringData != nil {
					t.Errorf("expected nil SteeringData, got %x", parsed.SteeringData)
				}
			},
		},
		{
			name: "parses complete response with steering data",
			tlvs: func() []TLV {
				resp := encodeDiscoveryResponse(DiscoveryResponseData{Version: 4})
				extPanID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
				steering := []byte{0xFF, 0x00, 0x55}
				var subTLVs []byte
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, resp[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, extPanID[:])
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte("SteerNet"))
				subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData, steering)
				return []TLV{{Type: TLVDiscovery, Value: subTLVs}}
			}(),
			wantErr: false,
			verify: func(t *testing.T, parsed *ParsedDiscoveryResponse) {
				t.Helper()
				if parsed.NetworkName != "SteerNet" {
					t.Errorf("NetworkName = %q, want %q", parsed.NetworkName, "SteerNet")
				}
				if len(parsed.SteeringData) != 3 {
					t.Fatalf("SteeringData length = %d, want 3", len(parsed.SteeringData))
				}
				if parsed.SteeringData[0] != 0xFF || parsed.SteeringData[1] != 0x00 || parsed.SteeringData[2] != 0x55 {
					t.Errorf("SteeringData = %x, want ff0055", parsed.SteeringData)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ParseDiscoveryResponse(tt.tlvs)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.verify != nil {
				tt.verify(t, result)
			}
		})
	}
}

// --- Encode/Decode round-trip tests ---

func TestDiscoveryRequestEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version uint16
		joiner  bool
	}{
		{name: "version 4 non-joiner", version: 4, joiner: false},
		{name: "version 4 joiner", version: 4, joiner: true},
		{name: "version 0", version: 0, joiner: false},
		{name: "version 15 max", version: 15, joiner: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := DiscoveryRequestData{Version: tt.version, IsJoiner: tt.joiner}
			encoded := encodeDiscoveryRequest(input)
			decoded, err := decodeDiscoveryRequest(encoded[:])
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			// Version is masked to 4 bits.
			wantVersion := tt.version & 0x0F
			if decoded.Version != wantVersion {
				t.Errorf("Version = %d, want %d", decoded.Version, wantVersion)
			}
			if decoded.IsJoiner != tt.joiner {
				t.Errorf("IsJoiner = %v, want %v", decoded.IsJoiner, tt.joiner)
			}
		})
	}
}

func TestDiscoveryResponseEncodeDecodeRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		version uint16
		native  bool
	}{
		{name: "version 4 no native", version: 4, native: false},
		{name: "version 4 native", version: 4, native: true},
		{name: "version 0", version: 0, native: false},
		{name: "version 15 max", version: 15, native: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			input := DiscoveryResponseData{Version: tt.version, IsNativeCommissioner: tt.native}
			encoded := encodeDiscoveryResponse(input)
			decoded, err := decodeDiscoveryResponse(encoded[:])
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}
			wantVersion := tt.version & 0x0F
			if decoded.Version != wantVersion {
				t.Errorf("Version = %d, want %d", decoded.Version, wantVersion)
			}
			if decoded.IsNativeCommissioner != tt.native {
				t.Errorf("IsNativeCommissioner = %v, want %v", decoded.IsNativeCommissioner, tt.native)
			}
		})
	}
}

// --- HandleDiscoveryResponse tests ---

// mockDiscoverySender implements discover.DiscoverySender for test scanners.
type mockDiscoverySender struct{}

func (m *mockDiscoverySender) SendDiscoveryRequest(channel, panID uint16, enableFiltering bool) error {
	return nil
}

// mockDiscoverTimer implements discover.Timer for test scanners.
type mockDiscoverTimer struct {
	running  bool
	callback func()
}

func (t *mockDiscoverTimer) Start(delayMs uint32) {
	t.running = true
}

func (t *mockDiscoverTimer) Stop() {
	t.running = false
}

func (t *mockDiscoverTimer) IsRunning() bool {
	return t.running
}

// buildDiscoveryResponseRxInfo creates an RxInfo simulating a received
// Discovery Response with the given parameters.
func buildDiscoveryResponseRxInfo(
	version uint16,
	isNative bool,
	extPanID [8]byte,
	networkName string,
	steeringData []byte,
	srcAddr types.ExtAddress,
) *RxInfo {
	resp := encodeDiscoveryResponse(DiscoveryResponseData{
		Version:              version,
		IsNativeCommissioner: isNative,
	})
	var subTLVs []byte
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVDiscoveryResponse, resp[:])
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVExtendedPanID, extPanID[:])
	subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVNetworkName, []byte(networkName))
	if steeringData != nil {
		subTLVs = appendMeshCoPSubTLV(subTLVs, meshcop.TLVSteeringData, steeringData)
	}

	tlvs := []TLV{{Type: TLVDiscovery, Value: subTLVs}}
	srcIP := ip6.Address(linkLocalIPFromExtAddress(srcAddr))

	return &RxInfo{
		SrcAddr:       srcAddr,
		SrcIP:         srcIP,
		DstIP:         LinkLocalAllNodesMulticast,
		LinkMarginRaw: 20,
		Command:       CommandDiscoveryResponse,
		TLVs:          tlvs,
	}
}

func TestHandleDiscoveryResponse_NilScanner(t *testing.T) {
	t.Parallel()

	h, _, _, _, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)
	// scanner is nil by default

	extPanID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildDiscoveryResponseRxInfo(4, true, extPanID, "TestNet", nil, srcAddr)

	err := h.HandleDiscoveryResponse(rxInfo)
	if err != nil {
		t.Fatalf("expected nil error with nil scanner, got: %v", err)
	}
}

func TestHandleDiscoveryResponse_NotScanning(t *testing.T) {
	t.Parallel()

	h, _, _, _, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)

	// Create a scanner but don't start scanning.
	scanner := discover.NewScanner(&mockDiscoverySender{}, &mockDiscoverTimer{})
	h.SetScanner(scanner)

	extPanID := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	rxInfo := buildDiscoveryResponseRxInfo(4, false, extPanID, "IdleNet", nil, srcAddr)

	err := h.HandleDiscoveryResponse(rxInfo)
	if err != nil {
		t.Fatalf("expected nil error when not scanning, got: %v", err)
	}
}

func TestHandleDiscoveryResponse_ParsesAndForwards(t *testing.T) {
	t.Parallel()

	h, _, _, _, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)

	// Create a scanner and start scanning.
	timer := &mockDiscoverTimer{}
	scanner := discover.NewScanner(&mockDiscoverySender{}, timer)

	var receivedResults []*discover.ScanResult
	err := scanner.Discover(1<<11, discover.PanIDBroadcast, false, func(result *discover.ScanResult) {
		if result != nil {
			receivedResults = append(receivedResults, result)
		}
	})
	if err != nil {
		t.Fatalf("Discover error: %v", err)
	}

	h.SetScanner(scanner)

	// Build and handle a Discovery Response.
	extPanID := [8]byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11}
	steering := []byte{0xFF, 0x00, 0x55}
	srcAddr := types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x99}
	rxInfo := buildDiscoveryResponseRxInfo(4, true, extPanID, "DiscNet", steering, srcAddr)

	err = h.HandleDiscoveryResponse(rxInfo)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Allow scanner to process (it's synchronous within HandleDiscoveryResponse).
	// The scanner should have received the result via its handler.
	if len(receivedResults) != 1 {
		t.Fatalf("expected 1 scan result, got %d", len(receivedResults))
	}

	got := receivedResults[0]
	if got.ExtPanID != extPanID {
		t.Errorf("ExtPanID = %x, want %x", got.ExtPanID, extPanID)
	}
	if got.NetworkName != "DiscNet" {
		t.Errorf("NetworkName = %q, want %q", got.NetworkName, "DiscNet")
	}
	if got.Version != 4 {
		t.Errorf("Version = %d, want 4", got.Version)
	}
	if !got.IsNative {
		t.Error("expected IsNative to be true")
	}
	if got.ExtAddress != srcAddr {
		t.Errorf("ExtAddress = %x, want %x", got.ExtAddress, srcAddr)
	}
	if len(got.SteeringData) != 3 {
		t.Fatalf("SteeringData length = %d, want 3", len(got.SteeringData))
	}
	if got.SteeringData[0] != 0xFF || got.SteeringData[1] != 0x00 || got.SteeringData[2] != 0x55 {
		t.Errorf("SteeringData = %x, want ff0055", got.SteeringData)
	}
}

func TestHandleDiscoveryResponse_MissingDiscoveryTLV(t *testing.T) {
	t.Parallel()

	h, _, _, _, _ := newDiscoveryHandlerTestSetup(RoleRouter, 3)

	// Create a scanner and start scanning.
	timer := &mockDiscoverTimer{}
	scanner := discover.NewScanner(&mockDiscoverySender{}, timer)
	err := scanner.Discover(1<<11, discover.PanIDBroadcast, false, func(result *discover.ScanResult) {})
	if err != nil {
		t.Fatalf("Discover error: %v", err)
	}

	h.SetScanner(scanner)

	// Build an RxInfo with no Discovery TLV.
	rxInfo := &RxInfo{
		SrcAddr:       types.ExtAddress{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xAA},
		Command:       CommandDiscoveryResponse,
		TLVs:          []TLV{}, // no Discovery TLV
		LinkMarginRaw: 20,
	}

	err = h.HandleDiscoveryResponse(rxInfo)
	if err == nil {
		t.Fatal("expected error for missing Discovery TLV, got nil")
	}
}
