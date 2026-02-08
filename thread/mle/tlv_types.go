// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

// TLV type constants for MLE messages.
//
// Reference: openthread/src/core/thread/mle_tlvs.hpp
const (
	// TLVSourceAddress identifies the Source Address TLV (RLOC16).
	TLVSourceAddress uint8 = 0

	// TLVMode identifies the Mode TLV (device mode flags).
	TLVMode uint8 = 1

	// TLVTimeout identifies the Timeout TLV (child timeout in seconds).
	TLVTimeout uint8 = 2

	// TLVChallenge identifies the Challenge TLV (random bytes for handshake).
	TLVChallenge uint8 = 3

	// TLVResponse identifies the Response TLV (echo of a received Challenge).
	TLVResponse uint8 = 4

	// TLVLinkFrameCounter identifies the Link Frame Counter TLV.
	TLVLinkFrameCounter uint8 = 5

	// TLVRoute64 identifies the Route64 TLV (router cost/quality table).
	TLVRoute64 uint8 = 9

	// TLVAddress16 identifies the Address16 TLV (short address / RLOC16).
	TLVAddress16 uint8 = 10

	// TLVLeaderData identifies the Leader Data TLV.
	TLVLeaderData uint8 = 11

	// TLVNetworkData identifies the Network Data TLV.
	TLVNetworkData uint8 = 12

	// TLVTLVRequest identifies the TLV Request TLV (list of requested TLV types).
	TLVTLVRequest uint8 = 13

	// TLVScanMask identifies the Scan Mask TLV.
	TLVScanMask uint8 = 14

	// TLVConnectivity identifies the Connectivity TLV.
	TLVConnectivity uint8 = 15

	// TLVLinkMargin identifies the Link Margin TLV.
	TLVLinkMargin uint8 = 16

	// TLVStatus identifies the Status TLV.
	TLVStatus uint8 = 17

	// TLVVersion identifies the Version TLV (Thread protocol version).
	TLVVersion uint8 = 18

	// TLVAddressRegistration identifies the Address Registration TLV.
	TLVAddressRegistration uint8 = 19

	// TLVChannel identifies the Channel TLV.
	TLVChannel uint8 = 20

	// TLVPanID identifies the PAN ID TLV.
	TLVPanID uint8 = 21

	// TLVActiveTimestamp identifies the Active Timestamp TLV.
	TLVActiveTimestamp uint8 = 22

	// TLVPendingTimestamp identifies the Pending Timestamp TLV.
	TLVPendingTimestamp uint8 = 23

	// TLVActiveDataset identifies the Active Operational Dataset TLV.
	TLVActiveDataset uint8 = 24

	// TLVPendingDataset identifies the Pending Operational Dataset TLV.
	TLVPendingDataset uint8 = 25

	// TLVDiscovery identifies the Discovery TLV.
	TLVDiscovery uint8 = 26

	// TLVSupervisionInterval identifies the Supervision Interval TLV.
	TLVSupervisionInterval uint8 = 27

	// TLVMleFrameCounter identifies the MLE Frame Counter TLV.
	TLVMleFrameCounter uint8 = 8

	// TLVCSLTimeout identifies the CSL Timeout TLV.
	TLVCSLTimeout uint8 = 28

	// TLVTimeRequest identifies the Time Request TLV.
	TLVTimeRequest uint8 = 252

	// TLVTimeParameter identifies the Time Parameter TLV.
	TLVTimeParameter uint8 = 253

	// TLVLinkMetricsQuery identifies the Link Metrics Query TLV.
	TLVLinkMetricsQuery uint8 = 87

	// TLVLinkMetricsManagement identifies the Link Metrics Management TLV.
	TLVLinkMetricsManagement uint8 = 88

	// TLVLinkMetricsReport identifies the Link Metrics Report TLV.
	TLVLinkMetricsReport uint8 = 89

	// TLVLinkProbe identifies the Link Probe TLV.
	TLVLinkProbe uint8 = 90
)

// Status codes for the MLE Status TLV.
const (
	// StatusError indicates a generic error.
	StatusError uint8 = 1

	// StatusDuplicate indicates a duplicate Address16 was detected.
	StatusDuplicate uint8 = 2
)

// Scan mask bits for the ScanMask TLV.
const (
	// ScanMaskRouterFlag requests responses from routers.
	ScanMaskRouterFlag uint8 = 1 << 7

	// ScanMaskEndDeviceFlag requests responses from end devices.
	ScanMaskEndDeviceFlag uint8 = 1 << 6
)

// ConnectivityFlags for the Connectivity TLV.
const (
	// ConnectivityFlagParentPriority is the mask for parent priority bits (bits 7:6).
	ConnectivityFlagParentPriority uint8 = 0xC0
)

// Connectivity TLV sizes.
const (
	// ConnectivityTLVMinSize is the minimum size of a Connectivity TLV value (without SED fields).
	ConnectivityTLVMinSize = 7

	// ConnectivityTLVMaxSize is the maximum size of a Connectivity TLV value (with SED fields).
	ConnectivityTLVMaxSize = 10
)

// LeaderDataTLVSize is the size of a LeaderData TLV value in bytes.
const LeaderDataTLVSize = 8

// Route64 entry encoding constants.
const (
	// Route64EntryLinkQualityOutShift is the bit shift for the outgoing link quality.
	Route64EntryLinkQualityOutShift = 6

	// Route64EntryLinkQualityInShift is the bit shift for the incoming link quality.
	Route64EntryLinkQualityInShift = 4

	// Route64EntryCostMask is the mask for the route cost nibble.
	Route64EntryCostMask = 0x0F
)

// Address registration entry constants.
const (
	// AddressRegistrationCompressed indicates a compressed address entry (context ID + IID).
	AddressRegistrationCompressed uint8 = 0x80

	// AddressRegistrationFull indicates a full 16-byte IPv6 address entry.
	AddressRegistrationFull uint8 = 0x00
)
