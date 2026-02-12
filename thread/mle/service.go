// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file implements the MLE Service, which is the integration layer that
// wires all MLE handlers, the dispatcher, and the state machine together
// into a cohesive service.
//
// The Service owns the Mle state machine, Dispatcher, ChildTable, and all
// command handlers. External packages interact with the MLE protocol through
// the Service rather than directly with individual handlers.
//
// This is analogous to how OpenThread's Mle class acts as both the state
// machine and the entry point for all MLE operations.

package mle

import (
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ServiceConfig holds the external dependencies needed by the MLE Service.
// These are provided by the caller since they come from other packages
// (routing, key management, platform) that the MLE package does not import.
type ServiceConfig struct {
	// Transport is the UDP send/receive abstraction for MLE messages.
	Transport Transport

	// KeyProvider supplies the key material for MLE security.
	KeyProvider KeyProvider

	// RouterLookup resolves RLOC16 and extended addresses to router entries.
	RouterLookup RouterLookup

	// RouteData provides route TLV data for advertisements and link accepts.
	RouteData RouteDataProvider

	// RouterOps provides router table operations for the advertisement handler.
	RouterOps AdvertisementRouterOps

	// Connectivity provides connectivity TLV data for parent responses.
	Connectivity ConnectivityProvider

	// NetworkInfo provides network identity data for discovery responses.
	NetworkInfo NetworkInfoProvider

	// Datasets provides operational dataset timestamps and raw TLV data
	// for MLE handlers that need to include Active/Pending Dataset info.
	Datasets DatasetProvider

	// NetworkData provides access to the Thread Network Data TLVs for
	// inclusion in Data Response and Child ID Response messages.
	NetworkData NetworkDataProvider

	// MacInfo provides PAN ID and channel information from the MAC layer.
	MacInfo MacInfoProvider

	// NeighborLookup resolves source extended addresses to neighbor entries.
	// This is typically provided by the router/child table.
	NeighborLookup func(addr types.ExtAddress) *Neighbor
}

// Service is the top-level integration layer for the MLE protocol.
//
// It owns the Mle state machine, Dispatcher, ChildTable, and all command
// handlers. It provides the entry points for receiving MLE messages from
// the network and for initiating MLE operations (attach, send advertisement,
// etc.).
type Service struct {
	// Core state.
	mle        *Mle
	dispatcher *Dispatcher
	childTable *ChildTable

	// Handlers — stored so callers can access handler-specific methods
	// (e.g., SendAdvertisement, SendLinkRequest, etc.).

	// Attacher handles the attach process (ParentResponse, ChildIDResponse).
	Attacher *Attacher

	// ChildHandlers handles child-side MLE messages (DataResponse,
	// ChildUpdateRequest, ChildUpdateResponse).
	ChildHandlers *ChildHandlers

	// LinkHandlers handles Link Request, Link Accept, and Link Accept and
	// Request messages for FTD devices.
	LinkHandlers *FtdLinkHandlers

	// LinkRejectHandler handles Link Reject messages.
	LinkRejectHandler *LinkRejectHandler

	// AdvertisementHandler handles received Advertisement messages.
	AdvertisementHandler *FtdAdvertisementHandler

	// AnnounceHandler handles received Announce messages.
	AnnounceHandler *AnnounceHandler

	// DataRequestHandler handles Data Request messages from children.
	DataRequestHandler *DataRequestHandler

	// ParentRequestHandler handles Parent Request messages from attaching
	// devices.
	ParentRequestHandler *ParentRequestHandler

	// ChildIDHandler handles Child ID Request messages from attaching
	// children.
	ChildIDHandler *ChildIDHandler

	// ChildUpdateRouter handles Child Update Request messages received by
	// a router/leader from its children. Unlike other handlers, it is NOT
	// registered on the dispatcher because ChildHandlers already registers
	// for those commands. The caller must route messages here when the
	// device is operating as a router or leader.
	ChildUpdateRouter *ChildUpdateRouter

	// DiscoveryHandler handles Discovery Request messages.
	DiscoveryHandler *DiscoveryHandler
}

// NewService creates a new MLE Service, wiring together the state machine,
// dispatcher, and all command handlers.
//
// The caller provides external dependencies via ServiceConfig. All handler
// registrations on the dispatcher happen during construction, so the
// service is ready to receive messages immediately after creation.
func NewService(cfg ServiceConfig) *Service {
	mle := NewMle()
	childTable := NewChildTable()
	dispatcher := NewDispatcher(mle, cfg.KeyProvider, cfg.Transport)

	if cfg.NeighborLookup != nil {
		dispatcher.SetNeighborLookup(cfg.NeighborLookup)
	}

	s := &Service{
		mle:        mle,
		dispatcher: dispatcher,
		childTable: childTable,
	}

	// Wire up all handlers. Most constructors register their commands
	// on the dispatcher automatically.
	s.Attacher = NewAttacher(mle, dispatcher)
	// The Attacher does not self-register; register its handlers here.
	dispatcher.RegisterHandler(CommandParentResponse, s.Attacher.HandleParentResponse)
	dispatcher.RegisterHandler(CommandChildIDResponse, s.Attacher.HandleChildIDResponse)

	s.ChildHandlers = NewChildHandlers(mle, dispatcher, cfg.Datasets, cfg.NetworkData)
	s.LinkHandlers = NewFtdLinkHandlers(mle, dispatcher, cfg.KeyProvider, cfg.RouterLookup, cfg.RouteData)
	s.LinkRejectHandler = NewLinkRejectHandler(mle, dispatcher)
	s.AdvertisementHandler = NewFtdAdvertisementHandler(mle, dispatcher, cfg.RouterOps)
	s.AnnounceHandler = NewAnnounceHandler(mle, dispatcher, cfg.KeyProvider, cfg.Datasets, cfg.MacInfo)
	s.DataRequestHandler = NewDataRequestHandler(mle, dispatcher, cfg.KeyProvider, childTable, cfg.Datasets, cfg.NetworkData)
	s.ParentRequestHandler = NewParentRequestHandler(mle, dispatcher, cfg.KeyProvider, childTable, cfg.Connectivity)
	s.ChildIDHandler = NewChildIDHandler(mle, dispatcher, cfg.KeyProvider, childTable, cfg.Datasets, cfg.NetworkData, cfg.RouteData)
	s.DiscoveryHandler = NewDiscoveryHandler(mle, dispatcher, cfg.NetworkInfo)

	// ChildUpdateRouter is NOT registered on the dispatcher (see its doc comment).
	s.ChildUpdateRouter = NewChildUpdateRouter(mle, dispatcher, cfg.KeyProvider, childTable)

	return s
}

// Mle returns the MLE state machine. This provides access to role
// queries, state transitions, leader data, parent information, and
// device mode.
func (s *Service) Mle() *Mle {
	return s.mle
}

// Dispatcher returns the MLE message dispatcher.
func (s *Service) Dispatcher() *Dispatcher {
	return s.dispatcher
}

// ChildTable returns the child table managed by this service.
func (s *Service) ChildTable() *ChildTable {
	return s.childTable
}

// HandleReceive processes a received MLE message from the UDP layer.
// This is the main entry point for incoming MLE traffic.
//
// It delegates to the Dispatcher which handles parsing, security
// validation, decryption, and dispatching to the appropriate handler.
func (s *Service) HandleReceive(data []byte, srcAddr types.ExtAddress, srcIP, dstIP ip6.Address, linkMargin uint8) error {
	return s.dispatcher.HandleReceive(data, srcAddr, srcIP, dstIP, linkMargin)
}
