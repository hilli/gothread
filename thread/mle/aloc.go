// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

// ALOC16 address range constants.
const (
	alocLeader                = 0xfc00
	alocDHCPAgentStart        = 0xfc01
	alocDHCPAgentEnd          = 0xfc0f
	alocServiceStart          = 0xfc10
	alocServiceEnd            = 0xfc1f
	alocCommissionerStart     = 0xfc30
	alocCommissionerEnd       = 0xfc37
	alocPrimaryBackboneRouter = 0xfc38
	alocNDAgentStart          = 0xfc40
	alocNDAgentEnd            = 0xfc4e
	alocCommissionerMask      = 0x0007
)

// IsALOCForLeader returns true if the ALOC16 is the Leader ALOC.
func IsALOCForLeader(aloc16 uint16) bool {
	return aloc16 == alocLeader
}

// ALOCForLeader returns the Leader ALOC16 address.
func ALOCForLeader() uint16 {
	return alocLeader
}

// IsALOCForDHCP6Agent returns true if the ALOC16 is within the DHCPv6 Agent range.
func IsALOCForDHCP6Agent(aloc16 uint16) bool {
	return aloc16 >= alocDHCPAgentStart && aloc16 <= alocDHCPAgentEnd
}

// ALOCDDHCP6AgentContextID returns the context ID from a DHCPv6 Agent ALOC16.
func ALOCDDHCP6AgentContextID(aloc16 uint16) uint8 {
	return uint8(aloc16-alocDHCPAgentStart) + 1
}

// ALOCFromDHCP6AgentContextID returns the DHCPv6 Agent ALOC16 for a context ID.
func ALOCFromDHCP6AgentContextID(contextID uint8) uint16 {
	return alocDHCPAgentStart + uint16(contextID) - 1
}

// IsALOCForService returns true if the ALOC16 is within the Service range.
func IsALOCForService(aloc16 uint16) bool {
	return aloc16 >= alocServiceStart && aloc16 <= alocServiceEnd
}

// ALOCToServiceID returns the service ID from a Service ALOC16.
func ALOCToServiceID(aloc16 uint16) uint8 {
	return uint8(aloc16 - alocServiceStart)
}

// ALOCFromServiceID returns the Service ALOC16 for a service ID.
func ALOCFromServiceID(serviceID uint8) uint16 {
	return alocServiceStart + uint16(serviceID)
}

// IsALOCForCommissioner returns true if the ALOC16 is within the Commissioner range.
func IsALOCForCommissioner(aloc16 uint16) bool {
	return aloc16 >= alocCommissionerStart && aloc16 <= alocCommissionerEnd
}

// ALOCFromCommissionerSessionID returns the Commissioner ALOC16 for a session ID.
func ALOCFromCommissionerSessionID(sessionID uint16) uint16 {
	return alocCommissionerStart + (sessionID & alocCommissionerMask)
}

// IsALOCForPrimaryBackboneRouter returns true if the ALOC16 is the Primary
// Backbone Router ALOC.
func IsALOCForPrimaryBackboneRouter(aloc16 uint16) bool {
	return aloc16 == alocPrimaryBackboneRouter
}

// ALOCForPrimaryBackboneRouter returns the Primary Backbone Router ALOC16.
func ALOCForPrimaryBackboneRouter() uint16 {
	return alocPrimaryBackboneRouter
}

// IsALOCForNDAgent returns true if the ALOC16 is within the ND Agent range.
func IsALOCForNDAgent(aloc16 uint16) bool {
	return aloc16 >= alocNDAgentStart && aloc16 <= alocNDAgentEnd
}

// ALOCToNDAgentContextID returns the context ID from an ND Agent ALOC16.
func ALOCToNDAgentContextID(aloc16 uint16) uint8 {
	return uint8(aloc16 - alocNDAgentStart)
}

// ALOCFromNDAgentContextID returns the ND Agent ALOC16 for a context ID.
func ALOCFromNDAgentContextID(contextID uint8) uint16 {
	return alocNDAgentStart + uint16(contextID)
}
