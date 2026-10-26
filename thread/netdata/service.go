// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Service number constants for Thread enterprise services
// ---------------------------------------------------------------------------

const (
	// ServiceNumberBackboneRouter is the service number for the Backbone Router service.
	ServiceNumberBackboneRouter uint8 = 0x01
	// ServiceNumberDnsSrpAnycast is the service number for DNS/SRP anycast.
	ServiceNumberDnsSrpAnycast uint8 = 0x5c //nolint:revive // Preserve the exported API spelling for existing callers.
	// ServiceNumberDnsSrpUnicast is the service number for DNS/SRP unicast.
	ServiceNumberDnsSrpUnicast uint8 = 0x5d //nolint:revive // Preserve the exported API spelling for existing callers.
)

// ---------------------------------------------------------------------------
// DnsSrpUnicastType
// ---------------------------------------------------------------------------

// DnsSrpUnicastType indicates where the DNS/SRP unicast address is encoded.
type DnsSrpUnicastType uint8 //nolint:revive // Preserve the exported API spelling for existing callers.

const (
	// DnsSrpUnicastAddrInServiceData indicates the address is in the service data.
	DnsSrpUnicastAddrInServiceData DnsSrpUnicastType = iota //nolint:revive // Preserve the exported API spelling for existing callers.
	// DnsSrpUnicastAddrInServerData indicates the address is in the server data.
	DnsSrpUnicastAddrInServerData //nolint:revive // Preserve the exported API spelling for existing callers.
)

// ---------------------------------------------------------------------------
// DnsSrpAnycastInfo
// ---------------------------------------------------------------------------

// DnsSrpAnycastInfo represents a parsed DNS/SRP anycast service entry.
type DnsSrpAnycastInfo struct { //nolint:revive // Preserve the exported API spelling for existing callers.
	// AnycastAddress is the anycast address for the DNS/SRP service.
	AnycastAddress ip6.Address
	// SequenceNumber is the anycast sequence number.
	SequenceNumber uint8
	// Version is the service version number extracted from the Server TLV
	// server data.
	Version uint8
	// RLOC16 is the RLOC16 of the server providing this service.
	RLOC16 uint16
}

// ---------------------------------------------------------------------------
// DnsSrpUnicastInfo
// ---------------------------------------------------------------------------

// DnsSrpUnicastInfo represents a parsed DNS/SRP unicast service entry.
type DnsSrpUnicastInfo struct { //nolint:revive // Preserve the exported API spelling for existing callers.
	// SockAddr is the unicast socket address (IPv6 address + port).
	SockAddr ip6.SockAddr
	// Version is the service version number.
	Version uint8
	// RLOC16 is the RLOC16 of the server providing this service.
	RLOC16 uint16
}

// ---------------------------------------------------------------------------
// BackboneRouterConfig
// ---------------------------------------------------------------------------

// BackboneRouterConfig holds BBR (Backbone Router) service data.
type BackboneRouterConfig struct {
	// SequenceNumber is the BBR sequence number.
	SequenceNumber uint8
	// ReregistrationDelay is the re-registration delay in seconds.
	ReregistrationDelay uint16
	// MlrTimeout is the Multicast Listener Registration timeout in seconds.
	MlrTimeout uint32
	// RLOC16 is the RLOC16 of the BBR.
	RLOC16 uint16
}

// ---------------------------------------------------------------------------
// Serial number arithmetic (RFC 1982)
// ---------------------------------------------------------------------------

// SerialNumberIsGreater implements RFC 1982 serial number comparison for
// 8-bit sequence numbers. It returns true if a is "greater than" b in the
// serial number space.
func SerialNumberIsGreater(a, b uint8) bool {
	return (a != b) && (int8(a-b) > 0)
}

// ---------------------------------------------------------------------------
// ServiceIterator
// ---------------------------------------------------------------------------

// ServiceIterator iterates over service entries in Thread Network Data.
type ServiceIterator struct {
	data      []byte
	outerOff  int // byte offset into data for the outer TLV loop
	innerOff  int // byte offset into current service's sub-TLVs
	serviceID uint8
}

// NewServiceIterator creates a new ServiceIterator over the given raw
// Network Data bytes.
func NewServiceIterator(data []byte) *ServiceIterator {
	return &ServiceIterator{data: data}
}

// Reset resets the iterator to the beginning.
func (it *ServiceIterator) Reset() {
	it.outerOff = 0
	it.innerOff = 0
	it.serviceID = 0
}

// GetNextDnsSrpAnycastInfo returns the next DNS/SRP anycast service entry
// from the Network Data, or errors.ErrNotFound when iteration is complete.
//
// DNS/SRP anycast service data is 1 byte: the sequence number.
// Each Server sub-TLV's server data is 1 byte: the version number.
func (it *ServiceIterator) GetNextDnsSrpAnycastInfo() (DnsSrpAnycastInfo, error) { //nolint:revive // Preserve the exported API spelling for existing callers.
	for it.outerOff+TLVHeaderSize <= len(it.data) {
		typ, stable, length, err := ParseTLVHeader(it.data[it.outerOff:])
		if err != nil {
			return DnsSrpAnycastInfo{}, errors.ErrNotFound
		}
		valueStart := it.outerOff + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > len(it.data) {
			return DnsSrpAnycastInfo{}, errors.ErrNotFound
		}

		if typ != TLVTypeService {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		value := it.data[valueStart:valueEnd]
		svcInfo, parseErr := ParseServiceValue(value, stable)
		if parseErr != nil {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		// Must be Thread enterprise with service data starting with 0x5c.
		// For Thread enterprise services, the service data format is:
		//   [service_number, ...additional_data]
		// So for DNS/SRP anycast (0x5c), service data is [0x5c, seqNum] = 2 bytes.
		if svcInfo.EnterpriseNumber != ThreadEnterpriseNumber ||
			len(svcInfo.ServiceData) < 2 ||
			svcInfo.ServiceData[0] != ServiceNumberDnsSrpAnycast {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		it.serviceID = svcInfo.ServiceID
		seqNum := svcInfo.ServiceData[1]

		// Walk Server sub-TLVs.
		subData := svcInfo.SubTLVsData
		for it.innerOff+TLVHeaderSize <= len(subData) {
			subTyp, _, subLen, subErr := ParseTLVHeader(subData[it.innerOff:])
			if subErr != nil {
				break
			}
			subValueStart := it.innerOff + TLVHeaderSize
			subValueEnd := subValueStart + int(subLen)
			if subValueEnd > len(subData) {
				break
			}

			if subTyp != TLVTypeServer {
				it.innerOff = subValueEnd
				continue
			}

			serverValue := subData[subValueStart:subValueEnd]
			server, srvErr := ParseServerValue(serverValue)
			if srvErr != nil {
				it.innerOff = subValueEnd
				continue
			}

			// Server data for anycast is 1 byte: version.
			if len(server.ServerData) < 1 {
				it.innerOff = subValueEnd
				continue
			}

			version := server.ServerData[0]

			it.innerOff = subValueEnd

			return DnsSrpAnycastInfo{
				SequenceNumber: seqNum,
				Version:        version,
				RLOC16:         server.Server16,
			}, nil
		}

		it.outerOff = valueEnd
		it.innerOff = 0
	}

	return DnsSrpAnycastInfo{}, errors.ErrNotFound
}

// GetNextDnsSrpUnicastInfo returns the next DNS/SRP unicast service entry
// from the Network Data of the specified unicast type, or errors.ErrNotFound
// when iteration is complete.
//
// For DnsSrpUnicastAddrInServiceData: the address and port are in the service
// data (service data = [0x5d, addr(16), port(2)] = 19 bytes total).
//
// For DnsSrpUnicastAddrInServerData: the address and port are in the server
// data of each Server sub-TLV (server data = [addr(16), port(2)] = 18 bytes).
func (it *ServiceIterator) GetNextDnsSrpUnicastInfo(unicastType DnsSrpUnicastType) (DnsSrpUnicastInfo, error) { //nolint:revive // Preserve the exported API spelling for existing callers.
	for it.outerOff+TLVHeaderSize <= len(it.data) {
		typ, stable, length, err := ParseTLVHeader(it.data[it.outerOff:])
		if err != nil {
			return DnsSrpUnicastInfo{}, errors.ErrNotFound
		}
		valueStart := it.outerOff + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > len(it.data) {
			return DnsSrpUnicastInfo{}, errors.ErrNotFound
		}

		if typ != TLVTypeService {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		value := it.data[valueStart:valueEnd]
		svcInfo, parseErr := ParseServiceValue(value, stable)
		if parseErr != nil {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		if svcInfo.EnterpriseNumber != ThreadEnterpriseNumber {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		if len(svcInfo.ServiceData) < 1 || svcInfo.ServiceData[0] != ServiceNumberDnsSrpUnicast {
			it.outerOff = valueEnd
			it.innerOff = 0
			continue
		}

		it.serviceID = svcInfo.ServiceID

		switch unicastType {
		case DnsSrpUnicastAddrInServiceData:
			// Service data: [0x5d, addr(16), port(2)] = 19 bytes.
			if len(svcInfo.ServiceData) < 19 {
				it.outerOff = valueEnd
				it.innerOff = 0
				continue
			}

			var addr ip6.Address
			copy(addr[:], svcInfo.ServiceData[1:17])
			port := encoding.BigEndianReadUint16(svcInfo.ServiceData[17:19])

			// Walk Server sub-TLVs to get the RLOC16 and version.
			subData := svcInfo.SubTLVsData
			for it.innerOff+TLVHeaderSize <= len(subData) {
				subTyp, _, subLen, subErr := ParseTLVHeader(subData[it.innerOff:])
				if subErr != nil {
					break
				}
				subValueStart := it.innerOff + TLVHeaderSize
				subValueEnd := subValueStart + int(subLen)
				if subValueEnd > len(subData) {
					break
				}

				if subTyp != TLVTypeServer {
					it.innerOff = subValueEnd
					continue
				}

				serverValue := subData[subValueStart:subValueEnd]
				server, srvErr := ParseServerValue(serverValue)
				if srvErr != nil {
					it.innerOff = subValueEnd
					continue
				}

				it.innerOff = subValueEnd

				return DnsSrpUnicastInfo{
					SockAddr: ip6.SockAddr{Address: addr, Port: port},
					RLOC16:   server.Server16,
				}, nil
			}

		case DnsSrpUnicastAddrInServerData:
			// Service data: just [0x5d] = 1 byte.
			// Address and port are in server data: [addr(16), port(2)] = 18 bytes.
			subData := svcInfo.SubTLVsData
			for it.innerOff+TLVHeaderSize <= len(subData) {
				subTyp, _, subLen, subErr := ParseTLVHeader(subData[it.innerOff:])
				if subErr != nil {
					break
				}
				subValueStart := it.innerOff + TLVHeaderSize
				subValueEnd := subValueStart + int(subLen)
				if subValueEnd > len(subData) {
					break
				}

				if subTyp != TLVTypeServer {
					it.innerOff = subValueEnd
					continue
				}

				serverValue := subData[subValueStart:subValueEnd]
				server, srvErr := ParseServerValue(serverValue)
				if srvErr != nil {
					it.innerOff = subValueEnd
					continue
				}

				// Server data must be [addr(16), port(2)] = 18 bytes.
				if len(server.ServerData) < 18 {
					it.innerOff = subValueEnd
					continue
				}

				var addr ip6.Address
				copy(addr[:], server.ServerData[0:16])
				port := encoding.BigEndianReadUint16(server.ServerData[16:18])

				it.innerOff = subValueEnd

				return DnsSrpUnicastInfo{
					SockAddr: ip6.SockAddr{Address: addr, Port: port},
					RLOC16:   server.Server16,
				}, nil
			}
		}

		it.outerOff = valueEnd
		it.innerOff = 0
	}

	return DnsSrpUnicastInfo{}, errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// FindPreferredDnsSrpAnycastInfo
// ---------------------------------------------------------------------------

// FindPreferredDnsSrpAnycastInfo finds the preferred DNS/SRP anycast service
// entry from the Network Data using a 3-pass algorithm:
//
//  1. Find the numerically largest sequence number across all entries.
//  2. Verify it beats all others via serial number comparison (RFC 1982).
//     If ambiguous (some entry is not less and not equal), fall back to
//     the numerical maximum.
//  3. Among entries with the winning sequence number, select the one with
//     the minimum version number.
//
// Returns errors.ErrNotFound if no DNS/SRP anycast entries exist.
func FindPreferredDnsSrpAnycastInfo(data []byte) (DnsSrpAnycastInfo, error) { //nolint:revive // Preserve the exported API spelling for existing callers.
	// Pass 1: find the numerically largest sequence number.
	it := NewServiceIterator(data)
	numericallyLargest := uint8(0)
	found := false

	for {
		info, err := it.GetNextDnsSrpAnycastInfo()
		if err != nil {
			break
		}
		if !found || info.SequenceNumber > numericallyLargest {
			numericallyLargest = info.SequenceNumber
		}
		found = true
	}

	if !found {
		return DnsSrpAnycastInfo{}, errors.ErrNotFound
	}

	// Pass 2: verify the numerically largest wins via serial comparison.
	// Check if numericallyLargest beats all others. If any entry exists
	// where SerialNumberIsGreater(entry.SeqNum, numericallyLargest), then
	// the situation is ambiguous and we still use numericallyLargest.
	bestSeqNum := numericallyLargest

	it.Reset()
	for {
		info, err := it.GetNextDnsSrpAnycastInfo()
		if err != nil {
			break
		}
		if SerialNumberIsGreater(info.SequenceNumber, bestSeqNum) {
			bestSeqNum = info.SequenceNumber
		}
	}

	// If bestSeqNum diverged from numericallyLargest, there's ambiguity.
	// In that case, fall back to the numerical max.
	if bestSeqNum != numericallyLargest {
		bestSeqNum = numericallyLargest
	}

	// Pass 3: among entries with bestSeqNum, find the minimum version.
	it.Reset()
	var result DnsSrpAnycastInfo
	resultFound := false

	for {
		info, err := it.GetNextDnsSrpAnycastInfo()
		if err != nil {
			break
		}
		if info.SequenceNumber != bestSeqNum {
			continue
		}
		if !resultFound || info.Version < result.Version {
			result = info
			resultFound = true
		}
	}

	if !resultFound {
		return DnsSrpAnycastInfo{}, errors.ErrNotFound
	}

	return result, nil
}

// ---------------------------------------------------------------------------
// FindBackboneRouterPrimary
// ---------------------------------------------------------------------------

// FindBackboneRouterPrimary finds the primary Backbone Router in the Network
// Data. The selection criteria are:
//
//  1. The leader's RLOC is preferred (matches leaderRLOC16).
//  2. Otherwise, the highest sequence number wins (via serial comparison).
//  3. If sequence numbers are equal, the highest RLOC16 wins.
//
// Returns errors.ErrNotFound if no BBR service entries exist.
func FindBackboneRouterPrimary(data []byte, leaderRLOC16 uint16) (BackboneRouterConfig, error) {
	tlvs := ParseTLVs(data)

	var best BackboneRouterConfig
	found := false

	for _, tlv := range tlvs {
		if tlv.Type != TLVTypeService {
			continue
		}

		svcInfo, err := ParseServiceValue(tlv.Value, tlv.Stable)
		if err != nil {
			continue
		}

		if svcInfo.EnterpriseNumber != ThreadEnterpriseNumber {
			continue
		}

		// BBR service data is [ServiceNumberBackboneRouter] = 1 byte.
		if len(svcInfo.ServiceData) < 1 || svcInfo.ServiceData[0] != ServiceNumberBackboneRouter {
			continue
		}

		// Walk Server sub-TLVs.
		subTLVs := ParseTLVs(svcInfo.SubTLVsData)
		for _, sub := range subTLVs {
			if sub.Type != TLVTypeServer {
				continue
			}

			server, srvErr := ParseServerValue(sub.Value)
			if srvErr != nil {
				continue
			}

			// BBR server data is [seqNum(1), reregDelay(2), mlrTimeout(4)] = 7 bytes.
			if len(server.ServerData) < 7 {
				continue
			}

			config := BackboneRouterConfig{
				SequenceNumber:      server.ServerData[0],
				ReregistrationDelay: encoding.BigEndianReadUint16(server.ServerData[1:3]),
				MlrTimeout:          encoding.BigEndianReadUint32(server.ServerData[3:7]),
				RLOC16:              server.Server16,
			}

			if !found {
				best = config
				found = true
				continue
			}

			// Leader's RLOC is always preferred.
			if config.RLOC16 == leaderRLOC16 && best.RLOC16 != leaderRLOC16 {
				best = config
				continue
			}
			if best.RLOC16 == leaderRLOC16 && config.RLOC16 != leaderRLOC16 {
				continue
			}

			// Highest sequence number wins (serial comparison).
			if SerialNumberIsGreater(config.SequenceNumber, best.SequenceNumber) {
				best = config
			} else if config.SequenceNumber == best.SequenceNumber && config.RLOC16 > best.RLOC16 {
				// Tie-break by highest RLOC16.
				best = config
			}
		}
	}

	if !found {
		return BackboneRouterConfig{}, errors.ErrNotFound
	}

	return best, nil
}

// ---------------------------------------------------------------------------
// GetServiceAloc
// ---------------------------------------------------------------------------

// GetServiceAloc computes the anycast ALOC (Anycast Locator) address for a
// given service ID. The ALOC is derived from the mesh-local prefix with the
// IID set to [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x10 + serviceID].
func GetServiceAloc(meshLocalPrefix ip6.Prefix, serviceID uint8) ip6.Address {
	var addr ip6.Address
	prefixBytes := meshLocalPrefix.GetBytes()
	// Copy the first 8 bytes (64-bit mesh-local prefix).
	copy(addr[:8], prefixBytes[:8])
	// Set the IID to the service ALOC pattern.
	addr[8] = 0x00
	addr[9] = 0x00
	addr[10] = 0x00
	addr[11] = 0xff
	addr[12] = 0xfe
	addr[13] = 0x00
	addr[14] = 0xfc
	addr[15] = 0x10 + serviceID
	return addr
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

// EncodeDnsSrpAnycastServiceData encodes the service data for a DNS/SRP
// anycast service entry. The format is [serviceNumber(1), seqNum(1)].
func EncodeDnsSrpAnycastServiceData(seqNum uint8) []byte { //nolint:revive // Preserve the exported API spelling for existing callers.
	return []byte{ServiceNumberDnsSrpAnycast, seqNum}
}

// EncodeDnsSrpUnicastServiceData encodes the service data for a DNS/SRP
// unicast service entry with the address in the service data. The format is
// [serviceNumber(1), addr(16), port(2)] = 19 bytes.
func EncodeDnsSrpUnicastServiceData(addr ip6.Address, port uint16) []byte { //nolint:revive // Preserve the exported API spelling for existing callers.
	buf := make([]byte, 19)
	buf[0] = ServiceNumberDnsSrpUnicast
	copy(buf[1:17], addr[:])
	encoding.BigEndianWriteUint16(port, buf[17:19])
	return buf
}

// EncodeBbrServerData encodes the server data for a Backbone Router service
// entry. The format is [seqNum(1), reregDelay(2), mlrTimeout(4)] = 7 bytes.
func EncodeBbrServerData(seqNum uint8, reregDelay uint16, mlrTimeout uint32) []byte {
	buf := make([]byte, 7)
	buf[0] = seqNum
	encoding.BigEndianWriteUint16(reregDelay, buf[1:3])
	encoding.BigEndianWriteUint32(mlrTimeout, buf[3:7])
	return buf
}
