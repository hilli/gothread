// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package mle implements MLE (Mesh Link Establishment) types and constants
// for Thread networking.
//
// This is a Go port of the MLE types defined in OpenThread's
// src/core/thread/mle_types.hpp.
package mle

import "math/bits"

// UDPPort is the MLE UDP port used for MLE message exchange.
const UDPPort uint16 = 19788

// Child and Router ID limits.
const (
	MinChildID      uint16 = 1
	MaxChildID      uint16 = 511
	MaxRouterID     uint8  = 62 // OT_NETWORK_MAX_ROUTER_ID
	InvalidRouterID uint8  = 63 // MaxRouterID + 1
	RouterIDOffset  uint8  = 10
	InvalidRLOC16   uint16 = 0xFFFE
)

// MaxRouteCost is the maximum route cost for Thread routing.
const MaxRouteCost uint8 = 16

// MeshLocalPrefixContextID is the context ID for the mesh-local prefix.
const MeshLocalPrefixContextID uint8 = 0

// DeviceRole represents the role of a Thread device.
type DeviceRole uint8

const (
	// RoleDisabled indicates the Thread interface is disabled.
	RoleDisabled DeviceRole = 0
	// RoleDetached indicates the device is not participating in a Thread network.
	RoleDetached DeviceRole = 1
	// RoleChild indicates the device is a child in the Thread network.
	RoleChild DeviceRole = 2
	// RoleRouter indicates the device is a router in the Thread network.
	RoleRouter DeviceRole = 3
	// RoleLeader indicates the device is the leader of the Thread network.
	RoleLeader DeviceRole = 4
)

// String returns a human-readable representation of the device role.
func (r DeviceRole) String() string {
	switch r {
	case RoleDisabled:
		return "Disabled"
	case RoleDetached:
		return "Detached"
	case RoleChild:
		return "Child"
	case RoleRouter:
		return "Router"
	case RoleLeader:
		return "Leader"
	default:
		return "Unknown"
	}
}

// Command represents an MLE command type.
type Command uint8

const (
	// CommandLinkRequest is the MLE Link Request command.
	CommandLinkRequest Command = 0
	// CommandLinkAccept is the MLE Link Accept command.
	CommandLinkAccept Command = 1
	// CommandLinkAcceptAndRequest is the MLE Link Accept and Request command.
	CommandLinkAcceptAndRequest Command = 2
	// CommandLinkReject is the MLE Link Reject command.
	CommandLinkReject Command = 3
	// CommandAdvertisement is the MLE Advertisement command.
	CommandAdvertisement Command = 4
	// CommandUpdate is the MLE Update command.
	CommandUpdate Command = 5
	// CommandUpdateRequest is the MLE Update Request command.
	CommandUpdateRequest Command = 6
	// CommandDataRequest is the MLE Data Request command.
	CommandDataRequest Command = 7
	// CommandDataResponse is the MLE Data Response command.
	CommandDataResponse Command = 8
	// CommandParentRequest is the MLE Parent Request command.
	CommandParentRequest Command = 9
	// CommandParentResponse is the MLE Parent Response command.
	CommandParentResponse Command = 10
	// CommandChildIDRequest is the MLE Child ID Request command.
	CommandChildIDRequest Command = 11
	// CommandChildIDResponse is the MLE Child ID Response command.
	CommandChildIDResponse Command = 12
	// CommandChildUpdateRequest is the MLE Child Update Request command.
	CommandChildUpdateRequest Command = 13
	// CommandChildUpdateResponse is the MLE Child Update Response command.
	CommandChildUpdateResponse Command = 14
	// CommandAnnounce is the MLE Announce command.
	CommandAnnounce Command = 15
	// CommandDiscoveryRequest is the MLE Discovery Request command.
	CommandDiscoveryRequest Command = 16
	// CommandDiscoveryResponse is the MLE Discovery Response command.
	CommandDiscoveryResponse Command = 17
	// CommandLinkMetricsManagementRequest is the MLE Link Metrics Management Request command.
	CommandLinkMetricsManagementRequest Command = 18
	// CommandLinkMetricsManagementResponse is the MLE Link Metrics Management Response command.
	CommandLinkMetricsManagementResponse Command = 19
	// CommandLinkProbe is the MLE Link Probe command.
	CommandLinkProbe Command = 20
	// CommandTimeSync is the MLE Time Sync command.
	CommandTimeSync Command = 99
	// CommandP2PLinkRequest is the MLE P2P Link Request command.
	CommandP2PLinkRequest Command = 100
	// CommandP2PLinkAccept is the MLE P2P Link Accept command.
	CommandP2PLinkAccept Command = 101
	// CommandP2PLinkAcceptAndRequest is the MLE P2P Link Accept and Request command.
	CommandP2PLinkAcceptAndRequest Command = 102
	// CommandP2PLinkTearDown is the MLE P2P Link TearDown command.
	CommandP2PLinkTearDown Command = 103
)

// DeviceMode flags for the MLE Mode TLV.
const (
	ModeRxOnWhenIdle     uint8 = 1 << 3 // 0x08
	ModeReserved         uint8 = 1 << 2 // 0x04 - always set on wire
	ModeFullThreadDevice uint8 = 1 << 1 // 0x02
	ModeFullNetworkData  uint8 = 1 << 0 // 0x01
)

// DeviceMode represents the mode flags of a Thread device.
type DeviceMode struct {
	mode uint8
}

// NewDeviceMode creates a DeviceMode with the given flags.
// The Reserved bit is always set.
func NewDeviceMode(mode uint8) DeviceMode {
	return DeviceMode{mode: mode | ModeReserved}
}

// Get returns the raw mode byte.
func (m DeviceMode) Get() uint8 {
	return m.mode
}

// Set sets the mode byte. The Reserved bit is always set.
func (m *DeviceMode) Set(mode uint8) {
	m.mode = mode | ModeReserved
}

// IsRxOnWhenIdle returns true if the device keeps its receiver on when idle.
func (m DeviceMode) IsRxOnWhenIdle() bool {
	return m.mode&ModeRxOnWhenIdle != 0
}

// IsFullThreadDevice returns true if the device is a Full Thread Device.
func (m DeviceMode) IsFullThreadDevice() bool {
	return m.mode&ModeFullThreadDevice != 0
}

// IsFullNetworkData returns true if the device requests full network data.
func (m DeviceMode) IsFullNetworkData() bool {
	return m.mode&ModeFullNetworkData != 0
}

// IsMinimalEndDevice returns true if the device is a Minimal End Device
// (not a Full Thread Device, but with RxOnWhenIdle set).
func (m DeviceMode) IsMinimalEndDevice() bool {
	return !m.IsFullThreadDevice() && m.IsRxOnWhenIdle()
}

// IsValid returns true if the mode flags are a valid combination.
// A Full Thread Device must have RxOnWhenIdle set.
func (m DeviceMode) IsValid() bool {
	return !m.IsFullThreadDevice() || m.IsRxOnWhenIdle()
}

// RLOC16 helper functions.

// ChildIDFromRLOC16 extracts the child ID from an RLOC16.
func ChildIDFromRLOC16(rloc16 uint16) uint16 {
	return rloc16 & uint16(MaxChildID)
}

// RouterIDFromRLOC16 extracts the router ID from an RLOC16.
func RouterIDFromRLOC16(rloc16 uint16) uint8 {
	return uint8(rloc16 >> RouterIDOffset)
}

// RLOC16FromRouterID constructs an RLOC16 from a router ID.
func RLOC16FromRouterID(routerID uint8) uint16 {
	return uint16(routerID) << RouterIDOffset
}

// IsRouterRLOC16 returns true if the RLOC16 belongs to a router (child ID == 0).
func IsRouterRLOC16(rloc16 uint16) bool {
	return ChildIDFromRLOC16(rloc16) == 0
}

// IsChildRLOC16 returns true if the RLOC16 belongs to a child (child ID != 0).
func IsChildRLOC16(rloc16 uint16) bool {
	return ChildIDFromRLOC16(rloc16) != 0
}

// IsRouterIDValid returns true if the router ID is within the valid range.
func IsRouterIDValid(routerID uint8) bool {
	return routerID <= MaxRouterID
}

// RouterIDMatch returns true if two RLOC16 values share the same router ID.
func RouterIDMatch(a, b uint16) bool {
	return RouterIDFromRLOC16(a) == RouterIDFromRLOC16(b)
}

// ParentRLOC16ForRLOC16 returns the parent (router) RLOC16 for a given RLOC16.
func ParentRLOC16ForRLOC16(rloc16 uint16) uint16 {
	return RLOC16FromRouterID(RouterIDFromRLOC16(rloc16))
}

// LeaderData contains the data advertised by the Thread Leader.
type LeaderData struct {
	PartitionID       uint32
	Weighting         uint8
	DataVersion       uint8
	StableDataVersion uint8
	LeaderRouterID    uint8
}

// RouterIDSet is a bit set for 64 router IDs stored in 8 bytes with MSB-first
// bit ordering.
type RouterIDSet [8]byte

// maskFor returns the bitmask for the given router ID within its byte.
// Uses MSB-first ordering: router ID 0 is bit 7 (0x80) of byte 0.
func maskFor(routerID uint8) byte {
	return 0x80 >> (routerID % 8)
}

// Contains returns true if the set contains the given router ID.
func (s *RouterIDSet) Contains(routerID uint8) bool {
	return s[routerID/8]&maskFor(routerID) != 0
}

// Add adds the given router ID to the set.
func (s *RouterIDSet) Add(routerID uint8) {
	s[routerID/8] |= maskFor(routerID)
}

// Remove removes the given router ID from the set.
func (s *RouterIDSet) Remove(routerID uint8) {
	s[routerID/8] &^= maskFor(routerID)
}

// GetAllocatedCount returns the number of router IDs in the set.
func (s *RouterIDSet) GetAllocatedCount() uint8 {
	var count uint8
	for _, b := range s {
		count += uint8(bits.OnesCount8(b))
	}
	return count
}

// Clear removes all router IDs from the set.
func (s *RouterIDSet) Clear() {
	*s = RouterIDSet{}
}

// ComparePartitions performs a three-way comparison of two Thread partitions.
// Returns -1 if partition A is worse, 0 if equal, +1 if A is better.
//
// Comparison order:
//  1. Higher weighting wins.
//  2. Non-singleton wins over singleton.
//  3. Higher partition ID wins.
func ComparePartitions(singletonA bool, leaderDataA LeaderData, singletonB bool, leaderDataB LeaderData) int {
	// 1. Compare weighting.
	switch {
	case leaderDataA.Weighting > leaderDataB.Weighting:
		return 1
	case leaderDataA.Weighting < leaderDataB.Weighting:
		return -1
	}

	// 2. Singleton loses.
	switch {
	case singletonA && !singletonB:
		return -1
	case !singletonA && singletonB:
		return 1
	}

	// 3. Higher partition ID wins.
	switch {
	case leaderDataA.PartitionID > leaderDataB.PartitionID:
		return 1
	case leaderDataA.PartitionID < leaderDataB.PartitionID:
		return -1
	}

	return 0
}

// IsSingleton returns true if the router ID set has exactly one allocated
// router, indicating a singleton partition.
func IsSingleton(idSet RouterIDSet) bool {
	return idSet.GetAllocatedCount() == 1
}

// SerialNumberIsGreater returns true if a is strictly ahead of b using
// 8-bit serial number arithmetic (RFC 1982 style comparison).
func SerialNumberIsGreater(a, b uint8) bool {
	return a != b && int8(a-b) > 0
}
