// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// Local represents the local device's contributed Network Data entries.
// It wraps a MutableNetworkData and provides typed add/remove operations.
//
// This is a Go port of OpenThread's Local class from
// src/core/thread/network_data_local.hpp and network_data_local.cpp.
type Local struct {
	data    MutableNetworkData
	changed bool
	rloc16  uint16
}

// NewLocal creates a new empty Local network data store.
func NewLocal() *Local {
	return &Local{}
}

// Data returns the current raw network data.
func (l *Local) Data() []byte {
	return l.data.Data()
}

// Len returns the length of the local data.
func (l *Local) Len() int {
	return l.data.Len()
}

// HasChanged reports whether local data has changed since last sync.
func (l *Local) HasChanged() bool {
	return l.changed
}

// ClearChanged clears the changed flag.
func (l *Local) ClearChanged() {
	l.changed = false
}

// Clear resets all local network data.
func (l *Local) Clear() {
	l.data.Clear()
	l.changed = true
}

// SetRloc16 sets the RLOC16 used for encoding entries.
func (l *Local) SetRloc16(rloc16 uint16) {
	l.rloc16 = rloc16
}

// AddOnMeshPrefix adds a border router on-mesh prefix entry. If an entry for
// the same prefix already exists it is replaced.
func (l *Local) AddOnMeshPrefix(config OnMeshPrefixConfig) error {
	// Remove any existing entry for this prefix.
	l.removePrefix(config.Prefix)

	// Build the BorderRouter sub-TLV containing one entry.
	entry := BorderRouterEntry{
		RLOC16:       l.rloc16,
		Preference:   config.Preference,
		Preferred:    config.Preferred,
		SLAAC:        config.SLAAC,
		DHCP:         config.DHCP,
		Configure:    config.Configure,
		DefaultRoute: config.DefaultRoute,
		OnMesh:       config.OnMesh,
		NdDNS:        config.NdDNS,
		Dp:           config.Dp,
	}

	var subTLV []byte
	subTLV = AppendBorderRouterTLV(subTLV, config.Stable, []BorderRouterEntry{entry})

	// Build the Prefix TLV value.
	prefixInfo := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      config.Prefix,
		SubTLVsData: subTLV,
		Stable:      config.Stable,
	}

	var tlvBytes []byte
	valueLen := PrefixValueSize(prefixInfo)
	tlvBytes = AppendTLVHeader(tlvBytes, TLVTypePrefix, config.Stable, uint8(valueLen))
	tlvBytes = AppendPrefixValue(tlvBytes, prefixInfo)

	if err := l.data.Append(tlvBytes); err != nil {
		return errors.ErrNoBufs
	}

	l.changed = true
	return nil
}

// RemoveOnMeshPrefix removes an on-mesh prefix entry.
func (l *Local) RemoveOnMeshPrefix(prefix ip6.Prefix) error {
	off := l.data.FindPrefix(prefix)
	if off < 0 {
		return errors.ErrNotFound
	}
	if err := l.data.RemoveTLV(off); err != nil {
		return err
	}
	l.changed = true
	return nil
}

// ContainsOnMeshPrefix checks if an on-mesh prefix exists in local data.
func (l *Local) ContainsOnMeshPrefix(prefix ip6.Prefix) bool {
	off := l.data.FindPrefix(prefix)
	if off < 0 {
		return false
	}
	// Verify it contains a BorderRouter sub-TLV.
	return l.data.FindSubTLV(off, TLVTypeBorderRouter) >= 0
}

// AddHasRoutePrefix adds an external route (HasRoute) entry. If an entry for
// the same prefix already exists it is replaced.
func (l *Local) AddHasRoutePrefix(config ExternalRouteConfig) error {
	// Remove any existing entry for this prefix.
	l.removePrefix(config.Prefix)

	// Build the HasRoute sub-TLV containing one entry.
	entry := HasRouteEntry{
		RLOC16:     l.rloc16,
		Preference: config.Preference,
		NAT64:      config.NAT64,
	}

	var subTLV []byte
	subTLV = AppendHasRouteTLV(subTLV, config.Stable, []HasRouteEntry{entry})

	// Build the Prefix TLV value.
	prefixInfo := PrefixTLVInfo{
		DomainID:    0,
		Prefix:      config.Prefix,
		SubTLVsData: subTLV,
		Stable:      config.Stable,
	}

	var tlvBytes []byte
	valueLen := PrefixValueSize(prefixInfo)
	tlvBytes = AppendTLVHeader(tlvBytes, TLVTypePrefix, config.Stable, uint8(valueLen))
	tlvBytes = AppendPrefixValue(tlvBytes, prefixInfo)

	if err := l.data.Append(tlvBytes); err != nil {
		return errors.ErrNoBufs
	}

	l.changed = true
	return nil
}

// RemoveHasRoutePrefix removes an external route entry.
func (l *Local) RemoveHasRoutePrefix(prefix ip6.Prefix) error {
	off := l.data.FindPrefix(prefix)
	if off < 0 {
		return errors.ErrNotFound
	}
	if err := l.data.RemoveTLV(off); err != nil {
		return err
	}
	l.changed = true
	return nil
}

// AddService adds a service TLV with a server sub-TLV. If a service with the
// same enterprise number and service data already exists it is replaced.
func (l *Local) AddService(enterpriseNumber uint32, serviceData []byte, serverStable bool, serverData []byte) error {
	// Remove any existing service with the same key.
	l.removeService(enterpriseNumber, serviceData)

	// Build the Server sub-TLV.
	serverEntry := ServerEntry{
		Server16:   l.rloc16,
		ServerData: serverData,
	}
	var subTLV []byte
	subTLV = AppendServerTLV(subTLV, serverStable, serverEntry)

	// Build the Service TLV value.
	serviceInfo := ServiceTLVInfo{
		ServiceID:        0,
		EnterpriseNumber: enterpriseNumber,
		ServiceData:      serviceData,
		SubTLVsData:      subTLV,
		Stable:           serverStable,
	}

	var tlvBytes []byte
	valueLen := ServiceValueSize(serviceInfo)
	tlvBytes = AppendTLVHeader(tlvBytes, TLVTypeService, serverStable, uint8(valueLen))
	tlvBytes = AppendServiceValue(tlvBytes, serviceInfo)

	if err := l.data.Append(tlvBytes); err != nil {
		return errors.ErrNoBufs
	}

	l.changed = true
	return nil
}

// RemoveService removes a service TLV by enterprise number and service data.
func (l *Local) RemoveService(enterpriseNumber uint32, serviceData []byte) error {
	off := l.data.FindService(enterpriseNumber, serviceData)
	if off < 0 {
		return errors.ErrNotFound
	}
	if err := l.data.RemoveTLV(off); err != nil {
		return err
	}
	l.changed = true
	return nil
}

// UpdateRloc updates the RLOC16 in all local TLV entries to reflect the
// current value. This is called before syncing with the leader.
func (l *Local) UpdateRloc() {
	buf := l.data.Data()
	off := 0

	for off+TLVHeaderSize <= l.data.Len() {
		typ, _, length, err := ParseTLVHeader(buf[off:])
		if err != nil {
			return
		}
		valueStart := off + TLVHeaderSize
		valueEnd := valueStart + int(length)
		if valueEnd > l.data.Len() {
			return
		}

		switch typ {
		case TLVTypePrefix:
			l.updateRlocInPrefix(off, valueStart, valueEnd)
		case TLVTypeService:
			l.updateRlocInService(off, valueStart, valueEnd)
		}

		off = valueEnd
	}
}

// updateRlocInPrefix updates RLOC16 in HasRoute and BorderRouter sub-TLV
// entries within the Prefix TLV at the given offsets.
func (l *Local) updateRlocInPrefix(tlvOffset, valueStart, valueEnd int) {
	buf := l.data.Data()

	// Skip DomainID(1) + PrefixLength(1) + prefix bytes.
	if valueStart+2 > valueEnd {
		return
	}
	prefixLen := buf[valueStart+1]
	pbs := prefixByteSize(prefixLen)
	subOff := valueStart + 2 + pbs
	if subOff > valueEnd {
		return
	}

	for subOff+TLVHeaderSize <= valueEnd {
		subTyp, _, subLen, err := ParseTLVHeader(buf[subOff:])
		if err != nil {
			return
		}
		subValueStart := subOff + TLVHeaderSize
		subValueEnd := subValueStart + int(subLen)
		if subValueEnd > valueEnd {
			return
		}

		switch subTyp {
		case TLVTypeHasRoute:
			entryOff := subValueStart
			for entryOff+HasRouteEntrySize <= subValueEnd {
				encoding.BigEndianWriteUint16(l.rloc16, buf[entryOff:entryOff+2])
				entryOff += HasRouteEntrySize
			}
		case TLVTypeBorderRouter:
			entryOff := subValueStart
			for entryOff+BorderRouterEntrySize <= subValueEnd {
				encoding.BigEndianWriteUint16(l.rloc16, buf[entryOff:entryOff+2])
				entryOff += BorderRouterEntrySize
			}
		}

		subOff = subValueEnd
	}
}

// updateRlocInService updates Server16 in Server sub-TLVs within the Service
// TLV at the given offsets.
func (l *Local) updateRlocInService(tlvOffset, valueStart, valueEnd int) {
	buf := l.data.Data()

	// Skip the service header to find sub-TLVs.
	if valueStart+1 > valueEnd {
		return
	}
	flagsByte := buf[valueStart]
	isThread := (flagsByte & 0x80) != 0
	off := valueStart + 1
	if !isThread {
		off += 4 // enterprise number
	}
	if off+1 > valueEnd {
		return
	}
	sdLen := int(buf[off])
	off += 1 + sdLen
	if off > valueEnd {
		return
	}

	// Walk sub-TLVs.
	for off+TLVHeaderSize <= valueEnd {
		subTyp, _, subLen, err := ParseTLVHeader(buf[off:])
		if err != nil {
			return
		}
		subValueStart := off + TLVHeaderSize
		subValueEnd := subValueStart + int(subLen)
		if subValueEnd > valueEnd {
			return
		}

		if subTyp == TLVTypeServer && subValueEnd-subValueStart >= 2 {
			encoding.BigEndianWriteUint16(l.rloc16, buf[subValueStart:subValueStart+2])
		}

		off = subValueEnd
	}
}

// removePrefix removes the Prefix TLV matching the given prefix, if present.
func (l *Local) removePrefix(prefix ip6.Prefix) {
	off := l.data.FindPrefix(prefix)
	if off >= 0 {
		_ = l.data.RemoveTLV(off)
	}
}

// removeService removes the Service TLV matching the given enterprise number
// and service data, if present.
func (l *Local) removeService(enterpriseNumber uint32, serviceData []byte) {
	off := l.data.FindService(enterpriseNumber, serviceData)
	if off >= 0 {
		_ = l.data.RemoveTLV(off)
	}
}
