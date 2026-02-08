// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package netdata implements Thread Network Data TLV parsing and iteration.
//
// Thread Network Data is a shared set of information that describes the
// services and routing information available in the Thread network. It is
// disseminated as a compact TLV-encoded blob.
//
// This is a Go port of the network data handling in OpenThread's
// src/core/thread/network_data_tlvs.hpp, src/core/thread/network_data_types.hpp,
// and src/core/thread/network_data.cpp.
package netdata

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// TLV Types
// ---------------------------------------------------------------------------

// TLVType represents Thread Network Data TLV type codes.
type TLVType uint8

// Thread Network Data TLV type values.
const (
	TLVTypeHasRoute          TLVType = 0
	TLVTypePrefix            TLVType = 1
	TLVTypeBorderRouter      TLVType = 2
	TLVTypeContext           TLVType = 3
	TLVTypeCommissioningData TLVType = 4
	TLVTypeService           TLVType = 5
	TLVTypeServer            TLVType = 6
)

// ---------------------------------------------------------------------------
// RoutePreference
// ---------------------------------------------------------------------------

// RoutePreference represents the route preference value (per RFC 4191).
type RoutePreference int8

// Route preference values.
const (
	RoutePreferenceHigh   RoutePreference = 1
	RoutePreferenceMedium RoutePreference = 0
	RoutePreferenceLow    RoutePreference = -1
)

// RoutePreferenceToValue converts a route preference to a 2-bit unsigned value
// for wire encoding.
func RoutePreferenceToValue(pref RoutePreference) uint8 {
	// Wire encoding: High=01, Medium=00, Low=11.
	switch pref {
	case RoutePreferenceHigh:
		return 0x01
	case RoutePreferenceLow:
		return 0x03
	default:
		return 0x00 // Medium
	}
}

// RoutePreferenceFromValue converts a 2-bit wire-encoded value to a
// RoutePreference. Only the low 2 bits of v are used.
func RoutePreferenceFromValue(v uint8) RoutePreference {
	switch v & 0x03 {
	case 0x01:
		return RoutePreferenceHigh
	case 0x03:
		return RoutePreferenceLow
	default:
		return RoutePreferenceMedium // 0x00 and 0x02(reserved) both map to Medium
	}
}

// ---------------------------------------------------------------------------
// TLV Header
// ---------------------------------------------------------------------------

// TLVHeaderSize is the size of a Network Data TLV header (type+stable byte + length byte).
const TLVHeaderSize = 2

// ParseTLVHeader parses the type, stable flag, and value length from data.
// It returns the parsed fields and the number of header bytes consumed (always 2),
// or an error if data is too short.
func ParseTLVHeader(data []byte) (typ TLVType, stable bool, length uint8, err error) {
	if len(data) < TLVHeaderSize {
		return 0, false, 0, errors.ErrParse
	}
	b0 := data[0]
	stable = (b0 & 0x01) != 0
	typ = TLVType(b0 >> 1)
	length = data[1]
	return typ, stable, length, nil
}

// ---------------------------------------------------------------------------
// HasRouteEntry (3 bytes: RLOC16 BE + flags)
// ---------------------------------------------------------------------------

// HasRouteEntrySize is the wire size of a single HasRoute entry.
const HasRouteEntrySize = 3

// HasRouteEntry represents a parsed HasRoute entry.
type HasRouteEntry struct {
	RLOC16     uint16
	Preference RoutePreference
	NAT64      bool
	AdvPio     bool
}

// ParseHasRouteEntry parses a single HasRoute entry from data (must be >= 3 bytes).
func ParseHasRouteEntry(data []byte) (HasRouteEntry, error) {
	if len(data) < HasRouteEntrySize {
		return HasRouteEntry{}, errors.ErrParse
	}
	rloc := encoding.BigEndianReadUint16(data[0:2])
	flags := data[2]
	pref := RoutePreferenceFromValue(flags >> 6)
	nat64 := (flags & 0x20) != 0
	advPio := (flags & 0x10) != 0
	return HasRouteEntry{
		RLOC16:     rloc,
		Preference: pref,
		NAT64:      nat64,
		AdvPio:     advPio,
	}, nil
}

// ---------------------------------------------------------------------------
// BorderRouterEntry (4 bytes: RLOC16 BE + flags BE u16)
// ---------------------------------------------------------------------------

// BorderRouterEntrySize is the wire size of a single BorderRouter entry.
const BorderRouterEntrySize = 4

// BorderRouterEntry represents a parsed Border Router entry.
type BorderRouterEntry struct {
	RLOC16       uint16
	Preference   RoutePreference
	Preferred    bool
	SLAAC        bool
	DHCP         bool
	Configure    bool
	DefaultRoute bool
	OnMesh       bool
	NdDNS        bool
	Dp           bool
}

// ParseBorderRouterEntry parses a single Border Router entry from data (must be >= 4 bytes).
func ParseBorderRouterEntry(data []byte) (BorderRouterEntry, error) {
	if len(data) < BorderRouterEntrySize {
		return BorderRouterEntry{}, errors.ErrParse
	}
	rloc := encoding.BigEndianReadUint16(data[0:2])
	flags := encoding.BigEndianReadUint16(data[2:4])
	pref := RoutePreferenceFromValue(uint8(flags >> 14))
	return BorderRouterEntry{
		RLOC16:       rloc,
		Preference:   pref,
		Preferred:    (flags & (1 << 13)) != 0,
		SLAAC:        (flags & (1 << 12)) != 0,
		DHCP:         (flags & (1 << 11)) != 0,
		Configure:    (flags & (1 << 10)) != 0,
		DefaultRoute: (flags & (1 << 9)) != 0,
		OnMesh:       (flags & (1 << 8)) != 0,
		NdDNS:        (flags & (1 << 7)) != 0,
		Dp:           (flags & (1 << 6)) != 0,
	}, nil
}

// ---------------------------------------------------------------------------
// ContextTLV value (2 bytes: flags + contextLength)
// ---------------------------------------------------------------------------

// ContextInfo represents a parsed Context TLV value.
type ContextInfo struct {
	ContextID     uint8
	Compress      bool
	ContextLength uint8
}

// ParseContextValue parses a Context TLV value (must be >= 2 bytes).
func ParseContextValue(data []byte) (ContextInfo, error) {
	if len(data) < 2 {
		return ContextInfo{}, errors.ErrParse
	}
	flags := data[0]
	return ContextInfo{
		ContextID:     flags & 0x0f,
		Compress:      (flags & 0x10) != 0,
		ContextLength: data[1],
	}, nil
}

// ---------------------------------------------------------------------------
// ServerTLV value (2 bytes RLOC16 + variable ServerData)
// ---------------------------------------------------------------------------

// ServerEntry represents a parsed Server TLV value.
type ServerEntry struct {
	Server16   uint16
	ServerData []byte
}

// ParseServerValue parses a Server TLV value (must be >= 2 bytes).
func ParseServerValue(data []byte) (ServerEntry, error) {
	if len(data) < 2 {
		return ServerEntry{}, errors.ErrParse
	}
	s16 := encoding.BigEndianReadUint16(data[0:2])
	sd := make([]byte, len(data)-2)
	copy(sd, data[2:])
	return ServerEntry{Server16: s16, ServerData: sd}, nil
}

// ---------------------------------------------------------------------------
// ServiceTLV
// ---------------------------------------------------------------------------

// ThreadEnterpriseNumber is the IANA enterprise number for Thread Group.
const ThreadEnterpriseNumber uint32 = 44970

// ServiceTLVInfo represents a parsed Service TLV header fields (excluding sub-TLVs).
type ServiceTLVInfo struct {
	ServiceID        uint8
	EnterpriseNumber uint32
	ServiceData      []byte
	SubTLVsData      []byte // raw bytes of sub-TLVs
	Stable           bool
}

// ParseServiceValue parses a Service TLV value.
func ParseServiceValue(value []byte, stable bool) (ServiceTLVInfo, error) {
	if len(value) < 1 {
		return ServiceTLVInfo{}, errors.ErrParse
	}

	flagsServiceID := value[0]
	isThreadEnterprise := (flagsServiceID & 0x80) != 0
	serviceID := flagsServiceID & 0x0f

	offset := 1
	var enterpriseNumber uint32
	if isThreadEnterprise {
		enterpriseNumber = ThreadEnterpriseNumber
	} else {
		if len(value) < offset+4 {
			return ServiceTLVInfo{}, errors.ErrParse
		}
		enterpriseNumber = encoding.BigEndianReadUint32(value[offset : offset+4])
		offset += 4
	}

	if len(value) < offset+1 {
		return ServiceTLVInfo{}, errors.ErrParse
	}
	serviceDataLen := int(value[offset])
	offset++

	if len(value) < offset+serviceDataLen {
		return ServiceTLVInfo{}, errors.ErrParse
	}
	serviceData := make([]byte, serviceDataLen)
	copy(serviceData, value[offset:offset+serviceDataLen])
	offset += serviceDataLen

	subTLVsData := make([]byte, len(value)-offset)
	copy(subTLVsData, value[offset:])

	return ServiceTLVInfo{
		ServiceID:        serviceID,
		EnterpriseNumber: enterpriseNumber,
		ServiceData:      serviceData,
		SubTLVsData:      subTLVsData,
		Stable:           stable,
	}, nil
}

// ---------------------------------------------------------------------------
// Prefix TLV parsing
// ---------------------------------------------------------------------------

// prefixByteSize returns the number of bytes needed to store a prefix of the
// given bit length: ceil(bits/8).
func prefixByteSize(bits uint8) int {
	return (int(bits) + 7) / 8
}

// PrefixTLVInfo represents a parsed Prefix TLV header fields (excluding sub-TLVs).
type PrefixTLVInfo struct {
	DomainID    uint8
	Prefix      ip6.Prefix
	SubTLVsData []byte
	Stable      bool
}

// ParsePrefixValue parses a Prefix TLV value.
// The value starts with DomainID(1), PrefixLength(1), Prefix(variable), then sub-TLVs.
func ParsePrefixValue(value []byte, stable bool) (PrefixTLVInfo, error) {
	if len(value) < 2 {
		return PrefixTLVInfo{}, errors.ErrParse
	}

	domainID := value[0]
	prefixLen := value[1]

	pbs := prefixByteSize(prefixLen)

	// Validate: prefix length must fit in an IPv6 address.
	if prefixLen > 128 {
		return PrefixTLVInfo{}, errors.ErrParse
	}
	if len(value) < 2+pbs {
		return PrefixTLVInfo{}, errors.ErrParse
	}

	var addrBytes [16]byte
	copy(addrBytes[:], value[2:2+pbs])
	prefix := ip6.NewPrefix(addrBytes, prefixLen)

	subTLVsStart := 2 + pbs
	subTLVsData := make([]byte, len(value)-subTLVsStart)
	copy(subTLVsData, value[subTLVsStart:])

	return PrefixTLVInfo{
		DomainID:    domainID,
		Prefix:      prefix,
		SubTLVsData: subTLVsData,
		Stable:      stable,
	}, nil
}

// ---------------------------------------------------------------------------
// ExternalRouteConfig
// ---------------------------------------------------------------------------

// ExternalRouteConfig represents a parsed external route from the Network Data.
type ExternalRouteConfig struct {
	Prefix     ip6.Prefix
	RLOC16     uint16
	Preference RoutePreference
	NAT64      bool
	Stable     bool
}

// ---------------------------------------------------------------------------
// OnMeshPrefixConfig
// ---------------------------------------------------------------------------

// OnMeshPrefixConfig represents a parsed on-mesh prefix from the Network Data.
type OnMeshPrefixConfig struct {
	Prefix       ip6.Prefix
	RLOC16       uint16
	Preference   RoutePreference
	Preferred    bool
	SLAAC        bool
	DHCP         bool
	Configure    bool
	DefaultRoute bool
	OnMesh       bool
	Stable       bool
	NdDNS        bool
	Dp           bool
}

// ---------------------------------------------------------------------------
// TLV
// ---------------------------------------------------------------------------

// TLV represents a single parsed top-level TLV from Network Data.
type TLV struct {
	Type   TLVType
	Stable bool
	Value  []byte
}

// ParseTLVs parses raw Network Data bytes into a slice of TLVs.
// Invalid TLVs (where the declared length exceeds the remaining data) are skipped.
func ParseTLVs(data []byte) []TLV {
	var tlvs []TLV
	offset := 0
	for offset+TLVHeaderSize <= len(data) {
		typ, stable, length, err := ParseTLVHeader(data[offset:])
		if err != nil {
			break
		}
		valueStart := offset + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > len(data) {
			break // truncated TLV
		}
		value := make([]byte, length)
		copy(value, data[valueStart:valueEnd])
		tlvs = append(tlvs, TLV{Type: typ, Stable: stable, Value: value})
		offset = valueEnd
	}
	return tlvs
}

// ---------------------------------------------------------------------------
// Iterator — walks raw Network Data extracting ExternalRouteConfig entries
// ---------------------------------------------------------------------------

// Iterator provides stateful iteration over parsed Network Data.
type Iterator struct {
	data   []byte
	offset int // byte offset into data for the outer TLV loop
	inner  int // byte offset into current prefix sub-TLVs for HasRoute entries
	subOff int // byte offset into HasRoute entries within a HasRoute sub-TLV
}

// NewIterator creates a new iterator over the given raw Network Data bytes.
func NewIterator(data []byte) *Iterator {
	return &Iterator{data: data}
}

// Reset resets the iterator to the beginning.
func (it *Iterator) Reset() {
	it.offset = 0
	it.inner = 0
	it.subOff = 0
}

// NextExternalRoute returns the next ExternalRouteConfig from the Network Data,
// or errors.ErrNotFound when iteration is complete.
func (it *Iterator) NextExternalRoute() (ExternalRouteConfig, error) {
	for it.offset+TLVHeaderSize <= len(it.data) {
		typ, stable, length, err := ParseTLVHeader(it.data[it.offset:])
		if err != nil {
			return ExternalRouteConfig{}, errors.ErrNotFound
		}
		valueStart := it.offset + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > len(it.data) {
			return ExternalRouteConfig{}, errors.ErrNotFound
		}

		if typ != TLVTypePrefix {
			it.offset = valueEnd
			it.inner = 0
			it.subOff = 0
			continue
		}

		value := it.data[valueStart:valueEnd]
		prefixInfo, parseErr := ParsePrefixValue(value, stable)
		if parseErr != nil {
			// Skip invalid prefix TLVs.
			it.offset = valueEnd
			it.inner = 0
			it.subOff = 0
			continue
		}

		// Walk sub-TLVs looking for HasRoute TLVs.
		subData := prefixInfo.SubTLVsData
		for it.inner+TLVHeaderSize <= len(subData) {
			subTyp, subStable, subLen, subErr := ParseTLVHeader(subData[it.inner:])
			if subErr != nil {
				break
			}
			subValueStart := it.inner + TLVHeaderSize
			subValueEnd := subValueStart + int(subLen)
			if subValueEnd > len(subData) {
				break
			}

			if subTyp != TLVTypeHasRoute {
				it.inner = subValueEnd
				it.subOff = 0
				continue
			}

			// Parse HasRoute entries.
			hasRouteValue := subData[subValueStart:subValueEnd]
			for it.subOff+HasRouteEntrySize <= len(hasRouteValue) {
				entry, entryErr := ParseHasRouteEntry(hasRouteValue[it.subOff:])
				if entryErr != nil {
					break
				}
				it.subOff += HasRouteEntrySize
				return ExternalRouteConfig{
					Prefix:     prefixInfo.Prefix,
					RLOC16:     entry.RLOC16,
					Preference: entry.Preference,
					NAT64:      entry.NAT64,
					Stable:     subStable,
				}, nil
			}

			it.inner = subValueEnd
			it.subOff = 0
		}

		// Done with this Prefix TLV's sub-TLVs.
		it.offset = valueEnd
		it.inner = 0
		it.subOff = 0
	}

	return ExternalRouteConfig{}, errors.ErrNotFound
}

// NextOnMeshPrefix returns the next OnMeshPrefixConfig from the Network Data,
// or errors.ErrNotFound when iteration is complete.
func (it *Iterator) NextOnMeshPrefix() (OnMeshPrefixConfig, error) {
	for it.offset+TLVHeaderSize <= len(it.data) {
		typ, stable, length, err := ParseTLVHeader(it.data[it.offset:])
		if err != nil {
			return OnMeshPrefixConfig{}, errors.ErrNotFound
		}
		valueStart := it.offset + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > len(it.data) {
			return OnMeshPrefixConfig{}, errors.ErrNotFound
		}

		if typ != TLVTypePrefix {
			it.offset = valueEnd
			it.inner = 0
			it.subOff = 0
			continue
		}

		value := it.data[valueStart:valueEnd]
		prefixInfo, parseErr := ParsePrefixValue(value, stable)
		if parseErr != nil {
			it.offset = valueEnd
			it.inner = 0
			it.subOff = 0
			continue
		}

		subData := prefixInfo.SubTLVsData
		for it.inner+TLVHeaderSize <= len(subData) {
			subTyp, subStable, subLen, subErr := ParseTLVHeader(subData[it.inner:])
			if subErr != nil {
				break
			}
			subValueStart := it.inner + TLVHeaderSize
			subValueEnd := subValueStart + int(subLen)
			if subValueEnd > len(subData) {
				break
			}

			if subTyp != TLVTypeBorderRouter {
				it.inner = subValueEnd
				it.subOff = 0
				continue
			}

			brValue := subData[subValueStart:subValueEnd]
			for it.subOff+BorderRouterEntrySize <= len(brValue) {
				entry, entryErr := ParseBorderRouterEntry(brValue[it.subOff:])
				if entryErr != nil {
					break
				}
				it.subOff += BorderRouterEntrySize
				return OnMeshPrefixConfig{
					Prefix:       prefixInfo.Prefix,
					RLOC16:       entry.RLOC16,
					Preference:   entry.Preference,
					Preferred:    entry.Preferred,
					SLAAC:        entry.SLAAC,
					DHCP:         entry.DHCP,
					Configure:    entry.Configure,
					DefaultRoute: entry.DefaultRoute,
					OnMesh:       entry.OnMesh,
					Stable:       subStable,
					NdDNS:        entry.NdDNS,
					Dp:           entry.Dp,
				}, nil
			}

			it.inner = subValueEnd
			it.subOff = 0
		}

		it.offset = valueEnd
		it.inner = 0
		it.subOff = 0
	}

	return OnMeshPrefixConfig{}, errors.ErrNotFound
}
