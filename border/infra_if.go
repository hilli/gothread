// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package border

import (
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Platform interfaces
// ---------------------------------------------------------------------------

// InfraIfPlatform abstracts the platform-specific operations needed by InfraIf.
// Implementations are provided by the platform layer.
type InfraIfPlatform interface {
	// SendIcmp6Nd sends an ICMPv6 Neighbor Discovery message through the
	// infrastructure interface identified by ifIndex.
	SendIcmp6Nd(ifIndex uint32, dest ip6.Address, buf []byte) error

	// HasAddress returns true if the infrastructure interface has the given
	// unicast address assigned.
	HasAddress(ifIndex uint32, addr ip6.Address) bool

	// DiscoverNat64Prefix initiates NAT64 prefix discovery on the
	// infrastructure interface.
	DiscoverNat64Prefix(ifIndex uint32) error

	// GetLinkLayerAddress returns the link-layer (MAC) address of the
	// infrastructure interface, or nil if unavailable.
	GetLinkLayerAddress(ifIndex uint32) []byte
}

// InfraIfCallbacks receives events from the infrastructure interface.
type InfraIfCallbacks interface {
	// HandleInfraIfStateChanged is called when the link state changes.
	HandleInfraIfStateChanged()

	// HandleReceiveIcmp6Nd is called when an ICMPv6 ND message is received
	// from the infrastructure interface. icmpType is the ICMPv6 type field,
	// src is the source address, and buf is the message payload (after the
	// ICMPv6 header).
	HandleReceiveIcmp6Nd(ifIndex uint32, src ip6.Address, icmpType uint8, buf []byte)
}

// ---------------------------------------------------------------------------
// InfraIf — infrastructure interface abstraction
// ---------------------------------------------------------------------------

// linkLocalAllRouters is the link-local all-routers multicast address (ff02::2).
var linkLocalAllRouters = ip6.Address{
	0xff, 0x02, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0x02,
}

// InfraIf manages the infrastructure network interface used by the border
// router for sending and receiving ICMPv6 Neighbor Discovery messages.
type InfraIf struct {
	ifIndex     uint32
	isRunning   bool
	initialized bool
	platform    InfraIfPlatform
	callbacks   InfraIfCallbacks
}

// NewInfraIf creates a new InfraIf with the given platform and callback
// implementations. The interface starts in the uninitialized, not-running state.
func NewInfraIf(platform InfraIfPlatform, callbacks InfraIfCallbacks) *InfraIf {
	return &InfraIf{
		platform:  platform,
		callbacks: callbacks,
	}
}

// Init initializes the infrastructure interface with the given interface index.
// Must be called before any other operations. Returns an error if already
// initialized with a different index.
func (i *InfraIf) Init(ifIndex uint32) error {
	if i.initialized && i.ifIndex != ifIndex {
		return errAlreadyInitialized
	}
	i.ifIndex = ifIndex
	i.initialized = true
	return nil
}

// Deinit resets the infrastructure interface to the uninitialized state.
func (i *InfraIf) Deinit() {
	i.ifIndex = 0
	i.isRunning = false
	i.initialized = false
}

// IsInitialized returns true if Init has been called successfully.
func (i *InfraIf) IsInitialized() bool {
	return i.initialized
}

// IsRunning returns true if the infrastructure link is up.
func (i *InfraIf) IsRunning() bool {
	return i.isRunning
}

// GetIfIndex returns the platform interface index.
func (i *InfraIf) GetIfIndex() uint32 {
	return i.ifIndex
}

// SetRunning updates the link state. If the state changes, the callback
// HandleInfraIfStateChanged is invoked. Returns true if the state actually
// changed.
func (i *InfraIf) SetRunning(running bool) bool {
	if !i.initialized {
		return false
	}
	if i.isRunning == running {
		return false
	}
	i.isRunning = running
	if i.callbacks != nil {
		i.callbacks.HandleInfraIfStateChanged()
	}
	return true
}

// SendIcmp6Nd sends an ICMPv6 ND message through the infrastructure interface.
// Returns an error if the interface is not initialized or not running.
func (i *InfraIf) SendIcmp6Nd(dest ip6.Address, buf []byte) error {
	if !i.initialized {
		return errNotInitialized
	}
	if !i.isRunning {
		return errNotRunning
	}
	return i.platform.SendIcmp6Nd(i.ifIndex, dest, buf)
}

// HasAddress returns true if the infrastructure interface has the given
// unicast address assigned. Returns false if not initialized.
func (i *InfraIf) HasAddress(addr ip6.Address) bool {
	if !i.initialized {
		return false
	}
	return i.platform.HasAddress(i.ifIndex, addr)
}

// DiscoverNat64Prefix initiates NAT64 prefix discovery.
// Returns an error if the interface is not initialized or not running.
func (i *InfraIf) DiscoverNat64Prefix() error {
	if !i.initialized {
		return errNotInitialized
	}
	if !i.isRunning {
		return errNotRunning
	}
	return i.platform.DiscoverNat64Prefix(i.ifIndex)
}

// GetLinkLayerAddress returns the link-layer address, or nil if unavailable
// or not initialized.
func (i *InfraIf) GetLinkLayerAddress() []byte {
	if !i.initialized {
		return nil
	}
	return i.platform.GetLinkLayerAddress(i.ifIndex)
}

// HandleReceiveIcmp6Nd processes an incoming ICMPv6 ND message received on
// the infrastructure interface. It delegates to the callbacks. Returns an error
// if the interface is not initialized.
func (i *InfraIf) HandleReceiveIcmp6Nd(src ip6.Address, icmpType uint8, buf []byte) error {
	if !i.initialized {
		return errNotInitialized
	}
	if i.callbacks != nil {
		i.callbacks.HandleReceiveIcmp6Nd(i.ifIndex, src, icmpType, buf)
	}
	return nil
}

// GetLinkLocalAllRoutersAddress returns ff02::2.
func GetLinkLocalAllRoutersAddress() ip6.Address {
	return linkLocalAllRouters
}

// ---------------------------------------------------------------------------
// Sentinel errors
// ---------------------------------------------------------------------------

type infraError string

func (e infraError) Error() string { return string(e) }

const (
	errNotInitialized     infraError = "infra_if: not initialized"
	errNotRunning         infraError = "infra_if: not running"
	errAlreadyInitialized infraError = "infra_if: already initialized with different index"
)
