// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This file defines the MLE TLV type constants as specified in OpenThread's
// src/core/thread/mle_tlvs.hpp.

package mle

// TLVType represents the type field of an MLE TLV.
type TLVType uint8

const (
	// TLVSourceAddress is the Source Address TLV type.
	TLVSourceAddress TLVType = 0
	// TLVMode is the Mode TLV type.
	TLVMode TLVType = 1
	// TLVTimeout is the Timeout TLV type.
	TLVTimeout TLVType = 2
	// TLVChallenge is the Challenge TLV type.
	TLVChallenge TLVType = 3
	// TLVResponse is the Response TLV type.
	TLVResponse TLVType = 4
	// TLVLinkFrameCounter is the Link Frame Counter TLV type.
	TLVLinkFrameCounter TLVType = 5
	// TLVLinkQuality is the Link Quality TLV type.
	TLVLinkQuality TLVType = 6
	// TLVNetworkParameter is the Network Parameter TLV type.
	TLVNetworkParameter TLVType = 7
	// TLVMleFrameCounter is the MLE Frame Counter TLV type.
	TLVMleFrameCounter TLVType = 8
	// TLVRoute is the Route TLV type.
	TLVRoute TLVType = 9
	// TLVAddress16 is the Address16 TLV type.
	TLVAddress16 TLVType = 10
	// TLVLeaderData is the Leader Data TLV type.
	TLVLeaderData TLVType = 11
	// TLVNetworkData is the Network Data TLV type.
	TLVNetworkData TLVType = 12
	// TLVTlvRequest is the TLV Request TLV type.
	TLVTlvRequest TLVType = 13
	// TLVScanMask is the Scan Mask TLV type.
	TLVScanMask TLVType = 14
	// TLVConnectivity is the Connectivity TLV type.
	TLVConnectivity TLVType = 15
	// TLVLinkMargin is the Link Margin TLV type.
	TLVLinkMargin TLVType = 16
	// TLVStatus is the Status TLV type.
	TLVStatus TLVType = 17
	// TLVVersion is the Version TLV type.
	TLVVersion TLVType = 18
	// TLVAddressRegistration is the Address Registration TLV type.
	TLVAddressRegistration TLVType = 19
	// TLVChannel is the Channel TLV type.
	TLVChannel TLVType = 20
	// TLVPanID is the PAN ID TLV type.
	TLVPanID TLVType = 21
	// TLVActiveTimestamp is the Active Timestamp TLV type.
	TLVActiveTimestamp TLVType = 22
	// TLVPendingTimestamp is the Pending Timestamp TLV type.
	TLVPendingTimestamp TLVType = 23
	// TLVActiveDataset is the Active Dataset TLV type.
	TLVActiveDataset TLVType = 24
	// TLVPendingDataset is the Pending Dataset TLV type.
	TLVPendingDataset TLVType = 25
	// TLVDiscovery is the Discovery TLV type.
	TLVDiscovery TLVType = 26
	// TLVSupervisionInterval is the Supervision Interval TLV type.
	TLVSupervisionInterval TLVType = 27
	// TLVWakeupChannel is the Wakeup Channel TLV type.
	TLVWakeupChannel TLVType = 74
	// TLVCSLChannel is the CSL Channel TLV type.
	TLVCSLChannel TLVType = 80
	// TLVCSLTimeout is the CSL Timeout TLV type.
	TLVCSLTimeout TLVType = 85
	// TLVCSLClockAccuracy is the CSL Clock Accuracy TLV type.
	TLVCSLClockAccuracy TLVType = 86
	// TLVLinkMetricsQuery is the Link Metrics Query TLV type.
	TLVLinkMetricsQuery TLVType = 87
	// TLVLinkMetricsManagement is the Link Metrics Management TLV type.
	TLVLinkMetricsManagement TLVType = 88
	// TLVLinkMetricsReport is the Link Metrics Report TLV type.
	TLVLinkMetricsReport TLVType = 89
	// TLVLinkProbe is the Link Probe TLV type.
	TLVLinkProbe TLVType = 90
	// TLVTimeRequest is the Time Request TLV type.
	TLVTimeRequest TLVType = 252
	// TLVTimeParameter is the Time Parameter TLV type.
	TLVTimeParameter TLVType = 253
	// TLVXtalAccuracy is the Crystal Accuracy TLV type.
	TLVXtalAccuracy TLVType = 254
)
