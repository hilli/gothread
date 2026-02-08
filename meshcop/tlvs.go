// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package meshcop implements Thread Mesh Commissioning Protocol (MeshCoP) types.
//
// Based on OpenThread: https://github.com/openthread/openthread
package meshcop

import "fmt"

// TLVType represents the type field of a MeshCoP TLV.
type TLVType uint8

const (
	// TLVChannel is the Channel TLV type.
	TLVChannel TLVType = 0
	// TLVPanID is the PAN ID TLV type.
	TLVPanID TLVType = 1
	// TLVExtendedPanID is the Extended PAN ID TLV type.
	TLVExtendedPanID TLVType = 2
	// TLVNetworkName is the Network Name TLV type.
	TLVNetworkName TLVType = 3
	// TLVPSKc is the PSKc TLV type.
	TLVPSKc TLVType = 4
	// TLVNetworkKey is the Network Key TLV type.
	TLVNetworkKey TLVType = 5
	// TLVNetworkKeySequence is the Network Key Sequence TLV type.
	TLVNetworkKeySequence TLVType = 6
	// TLVMeshLocalPrefix is the Mesh Local Prefix TLV type.
	TLVMeshLocalPrefix TLVType = 7
	// TLVSteeringData is the Steering Data TLV type.
	TLVSteeringData TLVType = 8
	// TLVBorderAgentLocator is the Border Agent Locator TLV type.
	TLVBorderAgentLocator TLVType = 9
	// TLVCommissionerID is the Commissioner ID TLV type.
	TLVCommissionerID TLVType = 10
	// TLVCommissionerSessionID is the Commissioner Session ID TLV type.
	TLVCommissionerSessionID TLVType = 11
	// TLVSecurityPolicy is the Security Policy TLV type.
	TLVSecurityPolicy TLVType = 12
	// TLVGet is the Get TLV type.
	TLVGet TLVType = 13
	// TLVActiveTimestamp is the Active Timestamp TLV type.
	TLVActiveTimestamp TLVType = 14
	// TLVCommissionerUDPPort is the Commissioner UDP Port TLV type.
	TLVCommissionerUDPPort TLVType = 15
	// TLVState is the State TLV type.
	TLVState TLVType = 16
	// TLVJoinerDTLSEncapsulation is the Joiner DTLS Encapsulation TLV type.
	TLVJoinerDTLSEncapsulation TLVType = 17
	// TLVJoinerUDPPort is the Joiner UDP Port TLV type.
	TLVJoinerUDPPort TLVType = 18
	// TLVJoinerIID is the Joiner IID TLV type.
	TLVJoinerIID TLVType = 19
	// TLVJoinerRouterLocator is the Joiner Router Locator TLV type.
	TLVJoinerRouterLocator TLVType = 20
	// TLVJoinerRouterKEK is the Joiner Router KEK TLV type.
	TLVJoinerRouterKEK TLVType = 21
	// TLVDuration is the Duration TLV type.
	TLVDuration TLVType = 23
	// TLVProvisioningURL is the Provisioning URL TLV type.
	TLVProvisioningURL TLVType = 32
	// TLVVendorName is the Vendor Name TLV type.
	TLVVendorName TLVType = 33
	// TLVVendorModel is the Vendor Model TLV type.
	TLVVendorModel TLVType = 34
	// TLVVendorSWVersion is the Vendor SW Version TLV type.
	TLVVendorSWVersion TLVType = 35
	// TLVVendorData is the Vendor Data TLV type.
	TLVVendorData TLVType = 36
	// TLVVendorStackVersion is the Vendor Stack Version TLV type.
	TLVVendorStackVersion TLVType = 37
	// TLVUDPEncapsulation is the UDP Encapsulation TLV type.
	TLVUDPEncapsulation TLVType = 48
	// TLVIP6Address is the IPv6 Address TLV type.
	TLVIP6Address TLVType = 49
	// TLVPendingTimestamp is the Pending Timestamp TLV type.
	TLVPendingTimestamp TLVType = 51
	// TLVDelayTimer is the Delay Timer TLV type.
	TLVDelayTimer TLVType = 52
	// TLVChannelMask is the Channel Mask TLV type.
	TLVChannelMask TLVType = 53
	// TLVCount is the Count TLV type.
	TLVCount TLVType = 54
	// TLVPeriod is the Period TLV type.
	TLVPeriod TLVType = 55
	// TLVScanDuration is the Scan Duration TLV type.
	TLVScanDuration TLVType = 56
	// TLVEnergyList is the Energy List TLV type.
	TLVEnergyList TLVType = 57
	// TLVThreadDomainName is the Thread Domain Name TLV type.
	TLVThreadDomainName TLVType = 59
	// TLVWakeupChannel is the Wakeup Channel TLV type.
	TLVWakeupChannel TLVType = 74
	// TLVDiscoveryRequest is the Discovery Request TLV type.
	TLVDiscoveryRequest TLVType = 128
	// TLVDiscoveryResponse is the Discovery Response TLV type.
	TLVDiscoveryResponse TLVType = 129
	// TLVJoinerAdvertisement is the Joiner Advertisement TLV type.
	TLVJoinerAdvertisement TLVType = 241
)

// String returns the name of the TLV type.
func (t TLVType) String() string {
	switch t {
	case TLVChannel:
		return "Channel"
	case TLVPanID:
		return "PanID"
	case TLVExtendedPanID:
		return "ExtendedPanID"
	case TLVNetworkName:
		return "NetworkName"
	case TLVPSKc:
		return "PSKc"
	case TLVNetworkKey:
		return "NetworkKey"
	case TLVNetworkKeySequence:
		return "NetworkKeySequence"
	case TLVMeshLocalPrefix:
		return "MeshLocalPrefix"
	case TLVSteeringData:
		return "SteeringData"
	case TLVBorderAgentLocator:
		return "BorderAgentLocator"
	case TLVCommissionerID:
		return "CommissionerID"
	case TLVCommissionerSessionID:
		return "CommissionerSessionID"
	case TLVSecurityPolicy:
		return "SecurityPolicy"
	case TLVGet:
		return "Get"
	case TLVActiveTimestamp:
		return "ActiveTimestamp"
	case TLVCommissionerUDPPort:
		return "CommissionerUDPPort"
	case TLVState:
		return "State"
	case TLVJoinerDTLSEncapsulation:
		return "JoinerDTLSEncapsulation"
	case TLVJoinerUDPPort:
		return "JoinerUDPPort"
	case TLVJoinerIID:
		return "JoinerIID"
	case TLVJoinerRouterLocator:
		return "JoinerRouterLocator"
	case TLVJoinerRouterKEK:
		return "JoinerRouterKEK"
	case TLVDuration:
		return "Duration"
	case TLVProvisioningURL:
		return "ProvisioningURL"
	case TLVVendorName:
		return "VendorName"
	case TLVVendorModel:
		return "VendorModel"
	case TLVVendorSWVersion:
		return "VendorSWVersion"
	case TLVVendorData:
		return "VendorData"
	case TLVVendorStackVersion:
		return "VendorStackVersion"
	case TLVUDPEncapsulation:
		return "UDPEncapsulation"
	case TLVIP6Address:
		return "IP6Address"
	case TLVPendingTimestamp:
		return "PendingTimestamp"
	case TLVDelayTimer:
		return "DelayTimer"
	case TLVChannelMask:
		return "ChannelMask"
	case TLVCount:
		return "Count"
	case TLVPeriod:
		return "Period"
	case TLVScanDuration:
		return "ScanDuration"
	case TLVEnergyList:
		return "EnergyList"
	case TLVThreadDomainName:
		return "ThreadDomainName"
	case TLVWakeupChannel:
		return "WakeupChannel"
	case TLVDiscoveryRequest:
		return "DiscoveryRequest"
	case TLVDiscoveryResponse:
		return "DiscoveryResponse"
	case TLVJoinerAdvertisement:
		return "JoinerAdvertisement"
	default:
		return fmt.Sprintf("TLVType(%d)", t)
	}
}

// Max length constants for MeshCoP TLV values.
const (
	// MaxProvisioningURLLength is the maximum length of a Provisioning URL.
	MaxProvisioningURLLength = 64
	// MaxCommissionerIDLength is the maximum length of a Commissioner ID.
	MaxCommissionerIDLength = 64
	// MaxVendorNameLength is the maximum length of a Vendor Name.
	MaxVendorNameLength = 32
	// MaxVendorModelLength is the maximum length of a Vendor Model.
	MaxVendorModelLength = 32
	// MaxVendorSWVersionLength is the maximum length of a Vendor SW Version.
	MaxVendorSWVersionLength = 16
	// MaxVendorDataLength is the maximum length of Vendor Data.
	MaxVendorDataLength = 64
	// MaxThreadDomainNameLength is the maximum length of a Thread Domain Name.
	MaxThreadDomainNameLength = 16
)

// State TLV values.
const (
	// StateReject indicates a rejected state.
	StateReject uint8 = 0xFF
	// StatePending indicates a pending state.
	StatePending uint8 = 0
	// StateAccept indicates an accepted state.
	StateAccept uint8 = 1
)

// Delay timer constants.
const (
	// DelayTimerMin is the minimum delay in milliseconds.
	DelayTimerMin uint32 = 30000
	// DelayTimerMax is the maximum delay (72 hours) in milliseconds.
	DelayTimerMax uint32 = 259200000
	// DelayTimerDefault is the default delay in milliseconds.
	DelayTimerDefault uint32 = 300000
)
