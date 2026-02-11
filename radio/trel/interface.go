// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package trel

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// --------------------------------------------------------------------------
// Platform — platform abstraction for TREL transport
// --------------------------------------------------------------------------

// Platform defines the platform-specific operations required for TREL
// transport. A concrete implementation must provide UDP socket management,
// DNS-SD service registration, and peer discovery.
type Platform interface {
	// Enable enables the TREL transport and returns the allocated UDP port.
	Enable() (port uint16, err error)
	// Disable disables the TREL transport.
	Disable() error
	// Send transmits a TREL packet to the given destination socket address.
	Send(packet []byte, dest ip6.SockAddr) error
	// RegisterService registers the TREL DNS-SD service with the given port
	// and TXT record data for peer discovery.
	RegisterService(port uint16, txtData []byte) error
}

// --------------------------------------------------------------------------
// Requester — identifies who requested an interface state change
// --------------------------------------------------------------------------

// Requester identifies the entity requesting an interface enable/disable.
type Requester uint8

const (
	// RequesterUser indicates the request comes from the user (public API).
	RequesterUser Requester = iota
	// RequesterStack indicates the request comes from the Thread stack.
	RequesterStack
)

// --------------------------------------------------------------------------
// Interface — TREL network interface
// --------------------------------------------------------------------------

// InterfaceState represents the state of the TREL interface.
type InterfaceState uint8

const (
	// InterfaceStateUninitialized is the initial state before Init.
	InterfaceStateUninitialized InterfaceState = iota
	// InterfaceStateDisabled indicates the interface is disabled.
	InterfaceStateDisabled
	// InterfaceStateEnabled indicates the interface is enabled.
	InterfaceStateEnabled
)

// Interface manages the TREL platform transport and acts as the bridge
// between the Link layer and the underlying platform implementation.
type Interface struct {
	platform     Platform
	state        InterfaceState
	userEnabled  bool
	stackEnabled bool
	filtered     bool
	udpPort      uint16
	rxCallback   func(packet Packet, senderAddr ip6.SockAddr)
}

// NewInterface creates a new Interface with the given platform implementation.
func NewInterface(platform Platform) *Interface {
	return &Interface{
		platform:    platform,
		state:       InterfaceStateUninitialized,
		userEnabled: true, // user-enabled by default, matching OpenThread
	}
}

// Init initializes the interface. Must be called once before use.
func (iface *Interface) Init() {
	if iface.state != InterfaceStateUninitialized {
		return
	}
	iface.state = InterfaceStateDisabled
	iface.updateState()
}

// SetEnabled enables or disables the TREL interface for the given requester.
// The interface is only enabled when both user and stack have enabled it.
func (iface *Interface) SetEnabled(enable bool, requester Requester) {
	switch requester {
	case RequesterUser:
		if iface.userEnabled == enable {
			return
		}
		iface.userEnabled = enable
	case RequesterStack:
		if iface.stackEnabled == enable {
			return
		}
		iface.stackEnabled = enable
	}
	iface.updateState()
}

// IsEnabled reports whether the interface is currently enabled.
func (iface *Interface) IsEnabled() bool {
	return iface.state == InterfaceStateEnabled
}

// SetFilterEnabled enables or disables the traffic filter. When filtering
// is enabled, all rx and tx traffic through the TREL interface is silently
// dropped. The interface remains enabled; this is primarily for testing.
func (iface *Interface) SetFilterEnabled(enable bool) {
	iface.filtered = enable
}

// IsFilterEnabled reports whether the traffic filter is active.
func (iface *Interface) IsFilterEnabled() bool {
	return iface.filtered
}

// GetUDPPort returns the UDP port assigned to this TREL interface.
func (iface *Interface) GetUDPPort() uint16 {
	return iface.udpPort
}

// SetRxCallback sets the callback invoked when a packet is received.
func (iface *Interface) SetRxCallback(cb func(packet Packet, senderAddr ip6.SockAddr)) {
	iface.rxCallback = cb
}

// Send transmits a packet. For broadcast packets it sends to each known
// peer; for unicast/ack packets it sends to the specific destination.
// The peerTable parameter is used for broadcast fan-out.
func (iface *Interface) Send(pkt Packet, peerTable *PeerTable) error {
	if !iface.IsEnabled() {
		return errors.ErrAbort
	}
	if iface.filtered {
		return nil // silently drop
	}

	h := pkt.GetHeader()
	switch h.GetType() {
	case TypeBroadcast:
		it := peerTable.GetIterator()
		for {
			peer := it.Next()
			if peer == nil {
				break
			}
			if !peer.HasValidSockAddr() {
				continue
			}
			// Best-effort: send to each peer, ignoring individual errors.
			_ = iface.platform.Send(pkt.GetBuffer(), peer.SockAddr)
		}
	case TypeUnicast, TypeAck:
		destAddr := h.GetDestination()
		peer := peerTable.FindByExtAddress(destAddr)
		if peer == nil || !peer.HasValidSockAddr() {
			return errors.ErrAbort
		}
		peer.UpdateLastActivity()
		if err := iface.platform.Send(pkt.GetBuffer(), peer.SockAddr); err != nil {
			return errors.ErrFailed
		}
	}
	return nil
}

// HandleReceived is called by the platform when a packet is received.
func (iface *Interface) HandleReceived(data []byte, senderAddr ip6.SockAddr) {
	if !iface.IsEnabled() || iface.filtered {
		return
	}
	pkt := NewPacket(data)
	if iface.rxCallback != nil {
		iface.rxCallback(pkt, senderAddr)
	}
}

// updateState transitions the interface between enabled and disabled states
// based on both user and stack enable flags.
func (iface *Interface) updateState() {
	if iface.state == InterfaceStateUninitialized {
		return
	}

	if iface.userEnabled && iface.stackEnabled {
		if iface.state == InterfaceStateDisabled {
			iface.state = InterfaceStateEnabled
			port, err := iface.platform.Enable()
			if err == nil {
				iface.udpPort = port
			}
		}
	} else {
		if iface.state == InterfaceStateEnabled {
			iface.state = InterfaceStateDisabled
			_ = iface.platform.Disable()
		}
	}
}
