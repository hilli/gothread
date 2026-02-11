// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package diag implements Thread Network Diagnostics TLV types and
// marshaling/unmarshaling.
//
// This is a Go port of the types and logic in OpenThread's
// src/core/thread/network_diagnostic_tlvs.hpp.
package diag

import (
	mactypes "github.com/hilli/gothread/mac/types"
)

// Diagnostic TLV type constants.
// Reference: Thread 1.3.0 spec, Section 10 & OpenThread network_diagnostic_tlvs.hpp.
const (
	TypeExtMacAddress        uint8 = 0  // Extended MAC Address
	TypeAddress16            uint8 = 1  // RLOC16
	TypeMode                 uint8 = 2  // Device Mode
	TypeTimeout              uint8 = 3  // Timeout (SED polling timeout)
	TypeConnectivity         uint8 = 4  // Connectivity
	TypeRoute64              uint8 = 5  // Route64
	TypeLeaderData           uint8 = 6  // Leader Data
	TypeNetworkData          uint8 = 7  // Network Data
	TypeIPv6AddressList      uint8 = 8  // IPv6 Address List
	TypeMacCounters          uint8 = 9  // MAC Counters
	TypeBatteryLevel         uint8 = 14 // Battery Level
	TypeSupplyVoltage        uint8 = 15 // Supply Voltage
	TypeChildTable           uint8 = 16 // Child Table
	TypeChannelPages         uint8 = 17 // Channel Pages
	TypeTypeList             uint8 = 18 // Type List (list of TLV types requested)
	TypeMaxChildTimeout      uint8 = 19 // Max Child Timeout
	TypeEUI64                uint8 = 20 // EUI-64
	TypeVersion              uint8 = 24 // Thread Version
	TypeVendorName           uint8 = 25 // Vendor Name
	TypeVendorModel          uint8 = 26 // Vendor Model
	TypeVendorSWVersion      uint8 = 27 // Vendor SW Version
	TypeThreadStackVersion   uint8 = 28 // Thread Stack Version
	TypeChild                uint8 = 29 // Child (extended child info)
	TypeChildIPv6AddressList uint8 = 30 // Child IPv6 Address List
	TypeRouterNeighbor       uint8 = 31 // Router Neighbor
	TypeAnswer               uint8 = 32 // Answer
	TypeQueryID              uint8 = 33 // Query ID
	TypeMleCounters          uint8 = 34 // MLE Counters
)

// Connectivity contains the connectivity metrics of a Thread device.
// Wire format: 1 byte parentPriority + 1 byte linkQuality3 + 1 byte
// linkQuality2 + 1 byte linkQuality1 + 1 byte leaderCost + 1 byte idSequence
// + 1 byte activeRouters + 2 bytes sedBufferSize + 1 byte sedDatagramCount
// = 10 bytes.
type Connectivity struct {
	ParentPriority   int8
	LinkQuality3     uint8
	LinkQuality2     uint8
	LinkQuality1     uint8
	LeaderCost       uint8
	IDSequence       uint8
	ActiveRouters    uint8
	SEDBufferSize    uint16
	SEDDatagramCount uint8
}

// ConnectivitySize is the wire size in bytes of a Connectivity TLV value.
const ConnectivitySize = 10

// Route64Entry contains routing information for a single router in the Route64 TLV.
// Each entry is a nibble pair packed into bytes on the wire, but we store the
// logical values here.
type Route64Entry struct {
	RouterID       uint8
	LinkQualityOut uint8 // 2 bits
	LinkQualityIn  uint8 // 2 bits
	RouteCost      uint8 // 4 bits
}

// Route64 contains the full routing table advertised in a Route64 TLV.
// Wire format: 1 byte idSequence + 8 bytes routerIDMask + variable route data
// (one nibble-pair per allocated router).
type Route64 struct {
	IDSequence  uint8
	RouterIDSet [8]byte // bit set of allocated router IDs (MSB-first)
	RouteData   []Route64Entry
}

// MacCounters contains IEEE 802.15.4 MAC-layer counters.
// Wire format: 9 x uint32 = 36 bytes (big-endian).
type MacCounters struct {
	IfInUnknownProtos  uint32
	IfInErrors         uint32
	IfOutErrors        uint32
	IfInUcastPkts      uint32
	IfInBroadcastPkts  uint32
	IfInDiscards       uint32
	IfOutUcastPkts     uint32
	IfOutBroadcastPkts uint32
	IfOutDiscards      uint32
}

// MacCountersSize is the wire size in bytes of a MacCounters TLV value.
const MacCountersSize = 36

// MleCounters contains MLE-layer counters.
// Wire format: 9 x uint16 + 6 x uint64 = 18 + 48 = 66 bytes (big-endian).
type MleCounters struct {
	DisabledRole                  uint16
	DetachedRole                  uint16
	ChildRole                     uint16
	RouterRole                    uint16
	LeaderRole                    uint16
	AttachAttempts                uint16
	PartitionIDChanges            uint16
	BetterPartitionAttachAttempts uint16
	ParentChanges                 uint16
	TrackedTime                   uint64
	DisabledTime                  uint64
	DetachedTime                  uint64
	ChildTime                     uint64
	RouterTime                    uint64
	LeaderTime                    uint64
}

// MleCountersSize is the wire size in bytes of an MleCounters TLV value.
const MleCountersSize = 66

// ChildTableEntry contains a single entry in the Child Table TLV.
// Wire format: 2-byte packed field + 1-byte mode = 3 bytes.
//
// The 2-byte packed field is big-endian:
//
//	bits 15..11: Timeout (5 bits, represents log2 of seconds)
//	bits 10..9:  Link Quality In (2 bits, 0-3)
//	bits 8..0:   Child ID (9 bits)
type ChildTableEntry struct {
	Timeout       uint8  // 5 bits: timeout exponent
	ChildID       uint16 // 9 bits
	LinkQualityIn uint8  // 2 bits (0-3)
	Mode          uint8  // device mode byte
}

// ChildTableEntrySize is the wire size in bytes of a single ChildTableEntry.
const ChildTableEntrySize = 3

// ChildTlv contains extended child information as defined in the Child TLV (type 29).
// Wire format varies; includes flags, RLOC16, ExtAddress, version, timeout, age,
// connection time, supervision interval, etc.
type ChildTlv struct {
	Flags               uint8
	RLOC16              uint16
	ExtAddress          mactypes.ExtAddress
	Version             uint16
	Timeout             uint32
	Age                 uint32
	ConnectionTime      uint32
	SupervisionInterval uint16
}

// ChildTlvFlags bit definitions.
const (
	ChildTlvFlagRxOnWhenIdle uint8 = 1 << 7
	ChildTlvFlagFTD          uint8 = 1 << 6
	ChildTlvFlagFullNetData  uint8 = 1 << 5
	ChildTlvFlagCSLSync      uint8 = 1 << 4
	ChildTlvFlagTrackEui64   uint8 = 1 << 3
)

// ChildTlvSize is the wire size of the ChildTlv value (without the TLV header).
// flags(1) + rloc16(2) + extAddr(8) + version(2) + timeout(4) + age(4) +
// connectionTime(4) + supervisionInterval(2) = 27 bytes.
const ChildTlvSize = 27

// RouterNeighborTlv contains information about a router neighbor.
type RouterNeighborTlv struct {
	Flags            uint8
	RLOC16           uint16
	ExtAddress       mactypes.ExtAddress
	Version          uint16
	ConnectionTime   uint32
	LinkMargin       uint8
	AverageRSSI      int8
	LastRSSI         int8
	FrameErrorRate   uint16
	MessageErrorRate uint16
}

// RouterNeighborTlvFlags bit definitions.
const (
	RouterNeighborFlagTrackEui64 uint8 = 1 << 7
)

// RouterNeighborTlvSize is the wire size of the RouterNeighborTlv value.
// flags(1) + rloc16(2) + extAddr(8) + version(2) + connectionTime(4) +
// linkMargin(1) + avgRSSI(1) + lastRSSI(1) + frameErrorRate(2) +
// messageErrorRate(2) = 24 bytes.
const RouterNeighborTlvSize = 24

// AnswerTlv represents the Answer TLV used in multi-part diagnostic responses.
// Wire format: 2 bytes (big-endian uint16).
//
//	bit 15:    IsLast flag (1 = last answer fragment)
//	bits 14-0: Index (sequence number of this fragment)
type AnswerTlv struct {
	IsLast bool
	Index  uint16 // 15 bits max
}

// AnswerTlvSize is the wire size of the AnswerTlv value.
const AnswerTlvSize = 2

// QueryIDSize is the wire size of a QueryID TLV value (uint16).
const QueryIDSize = 2
