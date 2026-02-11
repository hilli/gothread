// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"sync"

	"github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Diagnostic TLV type constants
// ---------------------------------------------------------------------------

// Diagnostic TLV types used when querying routers.
const (
	DiagTLVExtAddress   uint8 = 0
	DiagTLVAddress16    uint8 = 1
	DiagTLVMode         uint8 = 2
	DiagTLVTimeout      uint8 = 3
	DiagTLVConnectivity uint8 = 4
	DiagTLVRoute64      uint8 = 5
	DiagTLVLeaderData   uint8 = 6
	DiagTLVNetworkData  uint8 = 7
	DiagTLVIPv6AddrList uint8 = 8
	DiagTLVMacCounters  uint8 = 9
	DiagTLVChildTable   uint8 = 14
	DiagTLVVersion      uint8 = 24
)

// ---------------------------------------------------------------------------
// RouterInfo
// ---------------------------------------------------------------------------

// RouterInfo contains discovered router information.
type RouterInfo struct {
	Rloc16        uint16
	ExtAddress    [8]byte
	Version       uint16
	IsLeader      bool
	LinkTo        []uint16 // RLOC16 of linked routers
	ChildCount    uint16
	IPv6Addresses [][16]byte
}

// ---------------------------------------------------------------------------
// DiscoveryCallback
// ---------------------------------------------------------------------------

// DiscoveryCallback is called with results for each discovered router.
// A nil error indicates a successful response; a non-nil error indicates
// a failure for that particular router or the end of discovery.
type DiscoveryCallback func(info RouterInfo, err error)

// ---------------------------------------------------------------------------
// DiagSender
// ---------------------------------------------------------------------------

// DiagSender sends diagnostic queries.
type DiagSender interface {
	SendDiagnosticGet(dest [16]byte, tlvTypes []uint8) error
}

// ---------------------------------------------------------------------------
// MeshDiag
// ---------------------------------------------------------------------------

// MeshDiag discovers mesh topology by querying routers with diagnostic
// messages.
type MeshDiag struct {
	mu         sync.Mutex
	sender     DiagSender
	callback   DiscoveryCallback
	active     bool
	discovered []RouterInfo
}

// NewMeshDiag creates a new MeshDiag that uses the given DiagSender.
func NewMeshDiag(sender DiagSender) *MeshDiag {
	return &MeshDiag{
		sender: sender,
	}
}

// DiscoverTopology starts a topology discovery operation by sending
// diagnostic queries to router addresses. Returns ErrInvalidState if a
// discovery is already active, or ErrInvalidArgs if the sender or callback
// is nil.
func (d *MeshDiag) DiscoverTopology(cb DiscoveryCallback) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.active {
		return errors.ErrInvalidState
	}
	if d.sender == nil {
		return errors.ErrInvalidArgs
	}
	if cb == nil {
		return errors.ErrInvalidArgs
	}

	d.callback = cb
	d.discovered = nil
	d.active = true

	return nil
}

// HandleDiagnosticResponse processes a diagnostic response from a router.
// The source is the IPv6 address of the responding router and data is the
// raw diagnostic TLV payload.
func (d *MeshDiag) HandleDiagnosticResponse(source [16]byte, data []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if !d.active {
		return
	}

	info := parseDiagnosticResponse(source, data)
	d.discovered = append(d.discovered, info)

	if d.callback != nil {
		cb := d.callback
		d.mu.Unlock()
		cb(info, nil)
		d.mu.Lock()
	}
}

// parseDiagnosticResponse extracts RouterInfo from raw diagnostic TLV data.
// The data format follows the Thread Diagnostic TLV specification:
// each TLV is encoded as [type, length, value...].
func parseDiagnosticResponse(source [16]byte, data []byte) RouterInfo {
	info := RouterInfo{}

	// Extract RLOC16 from source address bytes 14-15.
	info.Rloc16 = uint16(source[14])<<8 | uint16(source[15])

	// Parse TLVs from the data.
	offset := 0
	for offset+2 <= len(data) {
		tlvType := data[offset]
		tlvLen := int(data[offset+1])
		offset += 2

		if offset+tlvLen > len(data) {
			break
		}

		value := data[offset : offset+tlvLen]
		offset += tlvLen

		switch tlvType {
		case DiagTLVExtAddress:
			if tlvLen >= 8 {
				copy(info.ExtAddress[:], value[:8])
			}
		case DiagTLVAddress16:
			if tlvLen >= 2 {
				info.Rloc16 = uint16(value[0])<<8 | uint16(value[1])
			}
		case DiagTLVVersion:
			if tlvLen >= 2 {
				info.Version = uint16(value[0])<<8 | uint16(value[1])
			}
		case DiagTLVLeaderData:
			// If the responding router's RLOC16 matches the leader
			// RLOC in the leader data TLV, mark it as leader.
			if tlvLen >= 8 {
				leaderRloc := uint16(value[6])<<8 | uint16(value[7])
				if leaderRloc == info.Rloc16 {
					info.IsLeader = true
				}
			}
		case DiagTLVRoute64:
			info.LinkTo = parseRoute64(value)
		case DiagTLVChildTable:
			// Each child entry is 3 bytes (timeout|childID, mode).
			if tlvLen >= 3 {
				info.ChildCount = uint16(tlvLen / 3)
			}
		case DiagTLVIPv6AddrList:
			// Each IPv6 address is 16 bytes.
			for i := 0; i+16 <= tlvLen; i += 16 {
				var addr [16]byte
				copy(addr[:], value[i:i+16])
				info.IPv6Addresses = append(info.IPv6Addresses, addr)
			}
		}
	}

	return info
}

// parseRoute64 extracts linked router RLOC16 values from a Route64 TLV value.
// The Route64 TLV contains a router ID mask (8 bytes) followed by per-router
// entries. Each entry contains link quality data; we consider a link present
// if the quality-in or quality-out is non-zero.
func parseRoute64(value []byte) []uint16 {
	if len(value) < 9 {
		return nil
	}

	// First byte is the router ID sequence, next 8 bytes are the router
	// ID allocation mask (64 bits, one per router ID).
	var links []uint16
	entryOffset := 9 // skip ID sequence (1 byte) + mask (8 bytes)

	for routerID := uint16(0); routerID < 64; routerID++ {
		byteIdx := 1 + routerID/8 // +1 for ID sequence byte
		bitIdx := 7 - (routerID % 8)

		if int(byteIdx) >= len(value) {
			break
		}
		if value[byteIdx]&(1<<bitIdx) == 0 {
			continue // router ID not allocated
		}

		if entryOffset >= len(value) {
			break
		}

		entry := value[entryOffset]
		entryOffset++

		// Each route entry byte: bits 7-6 = link quality out,
		// bits 5-4 = link quality in, bits 3-0 = route cost.
		linkQualityOut := (entry >> 6) & 0x03
		linkQualityIn := (entry >> 4) & 0x03

		if linkQualityOut > 0 || linkQualityIn > 0 {
			rloc16 := routerID << 10
			links = append(links, rloc16)
		}
	}

	return links
}

// Cancel stops a topology discovery in progress.
func (d *MeshDiag) Cancel() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.active = false
	d.callback = nil
}

// IsActive reports whether a topology discovery is in progress.
func (d *MeshDiag) IsActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.active
}

// GetDiscoveredRouters returns a copy of the routers discovered so far.
func (d *MeshDiag) GetDiscoveredRouters() []RouterInfo {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(d.discovered) == 0 {
		return nil
	}
	result := make([]RouterInfo, len(d.discovered))
	copy(result, d.discovered)
	return result
}
