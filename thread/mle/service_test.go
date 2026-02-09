// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"testing"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// --- mock types for Service testing ---

// serviceTestRouterLookup implements RouterLookup for Service tests.
type serviceTestRouterLookup struct {
	routers map[uint16]*Router
}

func (m *serviceTestRouterLookup) FindRouterByRLOC16(rloc16 uint16) *Router {
	if m.routers == nil {
		return nil
	}
	return m.routers[rloc16]
}

func (m *serviceTestRouterLookup) FindRouterByExtAddress(_ types.ExtAddress) *Router {
	return nil
}

// serviceTestRouterOps implements AdvertisementRouterOps for Service tests.
type serviceTestRouterOps struct {
	serviceTestRouterLookup
}

func (m *serviceTestRouterOps) GetActiveRouterCount() int                   { return 1 }
func (m *serviceTestRouterOps) GetNeighborCount(_ uint8) int                { return 0 }
func (m *serviceTestRouterOps) IsAllocated(_ uint8) bool                    { return false }
func (m *serviceTestRouterOps) GetRouterIDSequence() uint8                  { return 0 }
func (m *serviceTestRouterOps) IsRouteTlvIDSequenceMoreRecent(_ uint8) bool { return false }
func (m *serviceTestRouterOps) UpdateRouterIDSet(_ uint8, _ RouterIDSet, _ uint32) bool {
	return false
}
func (m *serviceTestRouterOps) UpdateRoutes(_ uint8, _ RouterIDSet, _ []Route64Entry, _ uint8, _ uint8) bool {
	return false
}
func (m *serviceTestRouterOps) UpdateRouterOnFtdChild(_ uint8, _ RouterIDSet, _ []Route64Entry, _ uint8) {
}
func (m *serviceTestRouterOps) FindRouterByID(_ uint8) *Router { return nil }
func (m *serviceTestRouterOps) RemoveRouterLink(_ *Router)     {}

// serviceTestRouteData implements RouteDataProvider for Service tests.
type serviceTestRouteData struct{}

func (m *serviceTestRouteData) GetRouteData(_, _ uint8) (uint8, RouterIDSet, []Route64Entry) {
	return 0, RouterIDSet{}, nil
}

// serviceTestConnectivity implements ConnectivityProvider for Service tests.
type serviceTestConnectivity struct{}

func (m *serviceTestConnectivity) GetConnectivityTLV() ConnectivityTLV {
	return ConnectivityTLV{}
}

// serviceTestNetworkInfo implements NetworkInfoProvider for Service tests.
type serviceTestNetworkInfo struct{}

func (m *serviceTestNetworkInfo) GetNetworkName() string     { return "TestNet" }
func (m *serviceTestNetworkInfo) GetExtendedPanID() [8]byte  { return [8]byte{} }
func (m *serviceTestNetworkInfo) GetSteeringData() []byte    { return nil }
func (m *serviceTestNetworkInfo) IsNativeCommissioner() bool { return false }

// newTestServiceConfig returns a ServiceConfig with mock dependencies.
func newTestServiceConfig() ServiceConfig {
	return ServiceConfig{
		Transport: &mockTransport{
			extAddr: types.ExtAddress{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			linkLocal: ip6.Address{
				0xfe, 0x80, 0, 0, 0, 0, 0, 0,
				0x03, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			},
		},
		KeyProvider:  &mockKeyProvider{currentSeq: 1},
		RouterLookup: &serviceTestRouterLookup{},
		RouteData:    &serviceTestRouteData{},
		RouterOps:    &serviceTestRouterOps{},
		Connectivity: &serviceTestConnectivity{},
		NetworkInfo:  &serviceTestNetworkInfo{},
	}
}

// --- Service tests ---

func TestNewService(t *testing.T) {
	t.Parallel()

	s := NewService(newTestServiceConfig())
	if s == nil {
		t.Fatal("NewService returned nil")
	}
}

func TestService_CoreAccessors(t *testing.T) {
	t.Parallel()

	s := NewService(newTestServiceConfig())

	if s.Mle() == nil {
		t.Error("Mle() returned nil")
	}
	if s.Dispatcher() == nil {
		t.Error("Dispatcher() returned nil")
	}
	if s.ChildTable() == nil {
		t.Error("ChildTable() returned nil")
	}
}

func TestService_InitialRole(t *testing.T) {
	t.Parallel()

	s := NewService(newTestServiceConfig())

	if s.Mle().Role() != RoleDisabled {
		t.Errorf("expected initial role Disabled, got %s", s.Mle().Role())
	}
}

func TestService_HandlersNotNil(t *testing.T) {
	t.Parallel()

	s := NewService(newTestServiceConfig())

	handlers := []struct {
		name string
		val  interface{}
	}{
		{"Attacher", s.Attacher},
		{"ChildHandlers", s.ChildHandlers},
		{"LinkHandlers", s.LinkHandlers},
		{"LinkRejectHandler", s.LinkRejectHandler},
		{"AdvertisementHandler", s.AdvertisementHandler},
		{"AnnounceHandler", s.AnnounceHandler},
		{"DataRequestHandler", s.DataRequestHandler},
		{"ParentRequestHandler", s.ParentRequestHandler},
		{"ChildIDHandler", s.ChildIDHandler},
		{"ChildUpdateRouter", s.ChildUpdateRouter},
		{"DiscoveryHandler", s.DiscoveryHandler},
	}

	for _, h := range handlers {
		if h.val == nil {
			t.Errorf("%s is nil", h.name)
		}
	}
}

func TestService_CommandsRegistered(t *testing.T) {
	t.Parallel()

	s := NewService(newTestServiceConfig())

	// These commands should be registered on the dispatcher.
	expectedCommands := []Command{
		CommandLinkRequest,
		CommandLinkAccept,
		CommandLinkAcceptAndRequest,
		CommandLinkReject,
		CommandAdvertisement,
		CommandDataRequest,
		CommandParentRequest,
		CommandChildIDRequest,
		CommandAnnounce,
		CommandDiscoveryRequest,
		CommandParentResponse,      // Registered by Attacher
		CommandChildIDResponse,     // Registered by Attacher
		CommandDataResponse,        // Registered by ChildHandlers
		CommandChildUpdateRequest,  // Registered by ChildHandlers
		CommandChildUpdateResponse, // Registered by ChildHandlers
	}

	for _, cmd := range expectedCommands {
		if _, ok := s.Dispatcher().handlers[cmd]; !ok {
			t.Errorf("expected command %d to be registered on dispatcher", cmd)
		}
	}
}

func TestService_NeighborLookupWired(t *testing.T) {
	t.Parallel()

	neighbor := &Neighbor{
		State:   StateValid,
		MacAddr: types.ExtAddress{0xAA},
	}

	cfg := newTestServiceConfig()
	cfg.NeighborLookup = func(_ types.ExtAddress) *Neighbor {
		return neighbor
	}

	s := NewService(cfg)

	if s.Dispatcher().lookupNeighbor == nil {
		t.Fatal("NeighborLookup not wired to dispatcher")
	}

	got := s.Dispatcher().lookupNeighbor(types.ExtAddress{0xAA})
	if got != neighbor {
		t.Error("NeighborLookup returned wrong neighbor")
	}
}

func TestService_NeighborLookupNilOK(t *testing.T) {
	t.Parallel()

	cfg := newTestServiceConfig()
	cfg.NeighborLookup = nil

	s := NewService(cfg)

	if s.Dispatcher().lookupNeighbor != nil {
		t.Error("expected lookupNeighbor to be nil when not provided")
	}
}
