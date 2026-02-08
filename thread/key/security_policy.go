// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package key

// SecurityPolicy constants.
const (
	DefaultKeyRotationTime = 672 // Default key rotation time in hours.
	MinKeyRotationTime     = 2   // Minimum key rotation time in hours.

	// VersionThresholdOffsetVersion is the offset between the Thread Version
	// and the version threshold valid for routing.
	VersionThresholdOffsetVersion = 3
)

// Security policy flag masks for byte 0 (flags[0]).
const (
	obtainNetworkKeyMask      = 1 << 7
	nativeCommissioningMask   = 1 << 6
	routersMask               = 1 << 5
	externalCommissioningMask = 1 << 4
	beaconsMask               = 1 << 3
	commercialCommMask        = 1 << 2
	autonomousEnrollmentMask  = 1 << 1
	networkKeyProvisionMask   = 1 << 0
)

// Security policy flag masks for byte 1 (flags[1]).
const (
	tobleLinkMask              = 1 << 7
	nonCcmRoutersMask          = 1 << 6
	reservedMask               = 0x38
	versionThresholdRoutingMsk = 0x07
)

// SecurityPolicy represents Thread Security Policy rotation time and flags.
//
// The flags encode administrator preferences for which security-related
// operations are allowed or disallowed on the network.
type SecurityPolicy struct {
	RotationTime uint16 // Key rotation time in hours.

	// Byte 0 flags (set=1 means enabled, except where noted).
	ObtainNetworkKeyEnabled      bool
	NativeCommissioningEnabled   bool
	RoutersEnabled               bool
	ExternalCommissioningEnabled bool
	BeaconsEnabled               bool

	// Byte 0 flags (inverted polarity: bit=0 means enabled).
	CommercialCommissioningEnabled bool
	AutonomousEnrollmentEnabled    bool
	NetworkKeyProvisioningEnabled  bool

	// Byte 1 flags.
	TobleLinkEnabled           bool
	NonCcmRoutersEnabled       bool // Inverted polarity: bit=0 means enabled.
	VersionThresholdForRouting uint8
}

// SetToDefault initializes the SecurityPolicy to default values matching
// OpenThread's SecurityPolicy::SetToDefault.
func (sp *SecurityPolicy) SetToDefault() {
	*sp = SecurityPolicy{}
	sp.RotationTime = DefaultKeyRotationTime
	sp.setDefaultFlags()
}

func (sp *SecurityPolicy) setDefaultFlags() {
	sp.ObtainNetworkKeyEnabled = true
	sp.NativeCommissioningEnabled = true
	sp.RoutersEnabled = true
	sp.ExternalCommissioningEnabled = true
	sp.BeaconsEnabled = false
	sp.CommercialCommissioningEnabled = false
	sp.AutonomousEnrollmentEnabled = false
	sp.NetworkKeyProvisioningEnabled = false
	sp.TobleLinkEnabled = true
	sp.NonCcmRoutersEnabled = false
	sp.VersionThresholdForRouting = 0
}

// SetFlags decodes the security policy flags from the given byte slice.
// The length should be 1 for Thread 1.1, or 2 for Thread 1.2+.
func (sp *SecurityPolicy) SetFlags(flags []byte) {
	if len(flags) == 0 {
		return
	}

	sp.setDefaultFlags()

	sp.ObtainNetworkKeyEnabled = flags[0]&obtainNetworkKeyMask != 0
	sp.NativeCommissioningEnabled = flags[0]&nativeCommissioningMask != 0
	sp.RoutersEnabled = flags[0]&routersMask != 0
	sp.ExternalCommissioningEnabled = flags[0]&externalCommissioningMask != 0
	sp.BeaconsEnabled = flags[0]&beaconsMask != 0

	// Inverted polarity: bit=0 means the feature is enabled.
	sp.CommercialCommissioningEnabled = flags[0]&commercialCommMask == 0
	sp.AutonomousEnrollmentEnabled = flags[0]&autonomousEnrollmentMask == 0
	sp.NetworkKeyProvisioningEnabled = flags[0]&networkKeyProvisionMask == 0

	if len(flags) < 2 {
		return
	}

	sp.TobleLinkEnabled = flags[1]&tobleLinkMask != 0
	sp.NonCcmRoutersEnabled = flags[1]&nonCcmRoutersMask == 0 // Inverted.
	sp.VersionThresholdForRouting = flags[1] & versionThresholdRoutingMsk
}

// GetFlags encodes the security policy flags into the given byte slice.
// The length should be 1 for Thread 1.1, or 2 for Thread 1.2+.
func (sp *SecurityPolicy) GetFlags(flags []byte) {
	if len(flags) == 0 {
		return
	}

	for i := range flags {
		flags[i] = 0
	}

	if sp.ObtainNetworkKeyEnabled {
		flags[0] |= obtainNetworkKeyMask
	}
	if sp.NativeCommissioningEnabled {
		flags[0] |= nativeCommissioningMask
	}
	if sp.RoutersEnabled {
		flags[0] |= routersMask
	}
	if sp.ExternalCommissioningEnabled {
		flags[0] |= externalCommissioningMask
	}
	if sp.BeaconsEnabled {
		flags[0] |= beaconsMask
	}

	// Inverted polarity: set bit if feature is DISABLED.
	if !sp.CommercialCommissioningEnabled {
		flags[0] |= commercialCommMask
	}
	if !sp.AutonomousEnrollmentEnabled {
		flags[0] |= autonomousEnrollmentMask
	}
	if !sp.NetworkKeyProvisioningEnabled {
		flags[0] |= networkKeyProvisionMask
	}

	if len(flags) < 2 {
		return
	}

	if sp.TobleLinkEnabled {
		flags[1] |= tobleLinkMask
	}
	if !sp.NonCcmRoutersEnabled {
		flags[1] |= nonCcmRoutersMask
	}
	flags[1] |= reservedMask
	flags[1] |= sp.VersionThresholdForRouting & versionThresholdRoutingMsk
}
