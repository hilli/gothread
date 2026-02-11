// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"encoding/binary"
	"sync"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
)

// TMF URI paths for commissioner management messages.
const (
	uriEnergyScan    = "c/es"
	uriEnergyReport  = "c/er"
	uriAnnounceBegin = "c/ab"
	uriPanIdQuery    = "c/pq"
	uriPanIdConflict = "c/pc"
)

// ---------------------------------------------------------------------------
// Energy Scan Client
// ---------------------------------------------------------------------------

// EnergyScanCallback is invoked with the results of an energy scan.
// channelMask is the scanned channel mask, energyList contains the RSSI
// measurements, and err is non-nil on failure.
type EnergyScanCallback func(channelMask uint32, energyList []byte, err error)

// EnergyScanClient sends energy scan queries to a destination and handles
// the asynchronous energy report responses.
//
// This is a Go port of OpenThread's energy_scan_client.hpp/cpp.
type EnergyScanClient struct {
	mu sync.Mutex

	transport  CommissionerTransport
	addressing CommissionerAddressing
	sessionID  func() uint16
	callback   EnergyScanCallback
	registered bool
}

// NewEnergyScanClient creates a new EnergyScanClient.
// sessionIDFunc should return the current commissioner session ID.
func NewEnergyScanClient(
	transport CommissionerTransport,
	addressing CommissionerAddressing,
	sessionIDFunc func() uint16,
) *EnergyScanClient {
	return &EnergyScanClient{
		transport:  transport,
		addressing: addressing,
		sessionID:  sessionIDFunc,
	}
}

// SendQuery sends an energy scan query to the given destination address.
// The callback is invoked when the energy report is received.
//
// Parameters:
//   - channelMask: bitmask of channels to scan
//   - count: number of energy measurements per channel
//   - period: time between measurements in milliseconds
//   - scanDuration: scan duration per channel in milliseconds
//   - addr: destination IPv6 address (16 bytes)
//   - cb: callback for the energy report
func (esc *EnergyScanClient) SendQuery(
	channelMask uint32,
	count uint8,
	period uint16,
	scanDuration uint16,
	addr [16]byte,
	cb EnergyScanCallback,
) error {
	esc.mu.Lock()
	defer esc.mu.Unlock()

	if esc.callback != nil {
		return goterrors.ErrBusy
	}

	// Register handler for energy report if not already done.
	if !esc.registered {
		esc.transport.RegisterHandler(uriEnergyReport, esc.handleEnergyReport)
		esc.registered = true
	}

	esc.callback = cb

	// Build the payload.
	payload := esc.buildQueryPayload(channelMask, count, period, scanDuration)

	msg := buildCONPost(uriEnergyScan, payload)
	info := esc.buildMessageInfo(addr)

	return esc.transport.SendRequest(msg, info, func(resp *coap.Message, _ coap.MessageInfo, err error) {
		// The query is CON — we expect an ACK. The actual data comes via
		// the energy report URI, not in this response.
		if err != nil {
			esc.mu.Lock()
			cb := esc.callback
			esc.callback = nil
			esc.mu.Unlock()
			if cb != nil {
				cb(0, nil, err)
			}
		}
	})
}

// buildQueryPayload builds the energy scan query TLV payload.
func (esc *EnergyScanClient) buildQueryPayload(channelMask uint32, count uint8, period uint16, scanDuration uint16) []byte {
	var buf []byte

	// Commissioner Session ID.
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, esc.sessionID())
	buf = append(buf, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	// Channel Mask: page(1) + maskLen(1) + mask(4).
	maskBuf := make([]byte, 6)
	maskBuf[0] = 0 // page 0
	maskBuf[1] = 4 // mask length
	binary.BigEndian.PutUint32(maskBuf[2:6], channelMask)
	buf = append(buf, encodeTLV(TLVChannelMask, maskBuf)...)

	// Count.
	buf = append(buf, encodeTLV(TLVCount, []byte{count})...)

	// Period.
	periodBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(periodBytes, period)
	buf = append(buf, encodeTLV(TLVPeriod, periodBytes)...)

	// Scan Duration.
	durBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(durBytes, scanDuration)
	buf = append(buf, encodeTLV(TLVScanDuration, durBytes)...)

	return buf
}

// handleEnergyReport processes incoming energy report messages.
func (esc *EnergyScanClient) handleEnergyReport(msg *coap.Message, info coap.MessageInfo) {
	// ACK the message if confirmable.
	if msg.GetType() == coap.TypeConfirmable {
		_ = esc.transport.SendResponse(coap.CodeChanged, msg, info)
	}

	payload := msg.GetPayload()

	// Parse channel mask.
	var channelMask uint32
	channelMaskTLV := findTLVInBytes(payload, TLVChannelMask)
	if channelMaskTLV != nil && len(channelMaskTLV) >= 6 {
		channelMask = binary.BigEndian.Uint32(channelMaskTLV[2:6])
	}

	// Parse energy list.
	energyList := findTLVInBytes(payload, TLVEnergyList)

	esc.mu.Lock()
	cb := esc.callback
	esc.callback = nil
	esc.mu.Unlock()

	if cb != nil {
		cb(channelMask, energyList, nil)
	}
}

// buildMessageInfo constructs a CoAP MessageInfo for the given destination.
func (esc *EnergyScanClient) buildMessageInfo(addr [16]byte) coap.MessageInfo {
	mlp := esc.addressing.MeshLocalPrefix()
	senderRLOC := esc.addressing.RLOC16()

	var localAddr [16]byte
	localAddr = [16]byte(rlocAddr(mlp, senderRLOC))

	return coap.MessageInfo{
		PeerPort:  61631, // TMF port
		PeerAddr:  addr,
		LocalAddr: localAddr,
	}
}

// ---------------------------------------------------------------------------
// Announce Begin Client
// ---------------------------------------------------------------------------

// AnnounceBeginClient sends Announce Begin requests. This is a fire-and-forget
// message with no response handler.
//
// This is a Go port of OpenThread's announce_begin_client.hpp/cpp.
type AnnounceBeginClient struct {
	transport  CommissionerTransport
	addressing CommissionerAddressing
	sessionID  func() uint16
}

// NewAnnounceBeginClient creates a new AnnounceBeginClient.
func NewAnnounceBeginClient(
	transport CommissionerTransport,
	addressing CommissionerAddressing,
	sessionIDFunc func() uint16,
) *AnnounceBeginClient {
	return &AnnounceBeginClient{
		transport:  transport,
		addressing: addressing,
		sessionID:  sessionIDFunc,
	}
}

// SendRequest sends an Announce Begin request to the given destination address.
//
// Parameters:
//   - channelMask: bitmask of channels
//   - count: number of announcements
//   - period: time between announcements in milliseconds
//   - addr: destination IPv6 address (16 bytes)
func (abc *AnnounceBeginClient) SendRequest(
	channelMask uint32,
	count uint8,
	period uint16,
	addr [16]byte,
) error {
	payload := abc.buildPayload(channelMask, count, period)
	msg := buildNONPost(uriAnnounceBegin, payload)

	mlp := abc.addressing.MeshLocalPrefix()
	senderRLOC := abc.addressing.RLOC16()
	var localAddr [16]byte
	localAddr = [16]byte(rlocAddr(mlp, senderRLOC))

	info := coap.MessageInfo{
		PeerPort:  61631,
		PeerAddr:  addr,
		LocalAddr: localAddr,
	}

	return abc.transport.SendRequest(msg, info, nil)
}

// buildPayload builds the Announce Begin TLV payload.
func (abc *AnnounceBeginClient) buildPayload(channelMask uint32, count uint8, period uint16) []byte {
	var buf []byte

	// Commissioner Session ID.
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, abc.sessionID())
	buf = append(buf, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	// Channel Mask: page(1) + maskLen(1) + mask(4).
	maskBuf := make([]byte, 6)
	maskBuf[0] = 0
	maskBuf[1] = 4
	binary.BigEndian.PutUint32(maskBuf[2:6], channelMask)
	buf = append(buf, encodeTLV(TLVChannelMask, maskBuf)...)

	// Count.
	buf = append(buf, encodeTLV(TLVCount, []byte{count})...)

	// Period.
	periodBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(periodBytes, period)
	buf = append(buf, encodeTLV(TLVPeriod, periodBytes)...)

	return buf
}

// ---------------------------------------------------------------------------
// PAN ID Query Client
// ---------------------------------------------------------------------------

// PanIdConflictCallback is invoked when a PAN ID conflict is reported.
type PanIdConflictCallback func(panID uint16, channelMask uint32)

// PanIdQueryClient sends PAN ID Query requests and handles conflict reports.
//
// This is a Go port of OpenThread's panid_query_client.hpp/cpp.
type PanIdQueryClient struct {
	mu sync.Mutex

	transport  CommissionerTransport
	addressing CommissionerAddressing
	sessionID  func() uint16
	callback   PanIdConflictCallback
	registered bool
}

// NewPanIdQueryClient creates a new PanIdQueryClient.
func NewPanIdQueryClient(
	transport CommissionerTransport,
	addressing CommissionerAddressing,
	sessionIDFunc func() uint16,
) *PanIdQueryClient {
	return &PanIdQueryClient{
		transport:  transport,
		addressing: addressing,
		sessionID:  sessionIDFunc,
	}
}

// SendQuery sends a PAN ID Query to the given destination address.
//
// Parameters:
//   - panID: the PAN ID to query for conflicts
//   - channelMask: bitmask of channels to scan
//   - addr: destination IPv6 address (16 bytes)
//   - cb: callback for PAN ID conflict reports
func (pqc *PanIdQueryClient) SendQuery(
	panID uint16,
	channelMask uint32,
	addr [16]byte,
	cb PanIdConflictCallback,
) error {
	pqc.mu.Lock()
	defer pqc.mu.Unlock()

	if pqc.callback != nil {
		return goterrors.ErrBusy
	}

	// Register handler for PAN ID conflict if not already done.
	if !pqc.registered {
		pqc.transport.RegisterHandler(uriPanIdConflict, pqc.handlePanIdConflict)
		pqc.registered = true
	}

	pqc.callback = cb

	payload := pqc.buildQueryPayload(panID, channelMask)
	msg := buildCONPost(uriPanIdQuery, payload)

	mlp := pqc.addressing.MeshLocalPrefix()
	senderRLOC := pqc.addressing.RLOC16()
	var localAddr [16]byte
	localAddr = [16]byte(rlocAddr(mlp, senderRLOC))

	info := coap.MessageInfo{
		PeerPort:  61631,
		PeerAddr:  addr,
		LocalAddr: localAddr,
	}

	return pqc.transport.SendRequest(msg, info, func(resp *coap.Message, _ coap.MessageInfo, err error) {
		// ACK received — actual conflict data comes via the conflict URI.
		if err != nil {
			pqc.mu.Lock()
			cb := pqc.callback
			pqc.callback = nil
			pqc.mu.Unlock()
			// No error callback for PAN ID query — silently clear.
			_ = cb
		}
	})
}

// buildQueryPayload builds the PAN ID Query TLV payload.
func (pqc *PanIdQueryClient) buildQueryPayload(panID uint16, channelMask uint32) []byte {
	var buf []byte

	// Commissioner Session ID.
	sidBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(sidBytes, pqc.sessionID())
	buf = append(buf, encodeTLV(TLVCommissionerSessionID, sidBytes)...)

	// Channel Mask: page(1) + maskLen(1) + mask(4).
	maskBuf := make([]byte, 6)
	maskBuf[0] = 0
	maskBuf[1] = 4
	binary.BigEndian.PutUint32(maskBuf[2:6], channelMask)
	buf = append(buf, encodeTLV(TLVChannelMask, maskBuf)...)

	// PAN ID.
	panBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(panBytes, panID)
	buf = append(buf, encodeTLV(TLVPanID, panBytes)...)

	return buf
}

// handlePanIdConflict processes incoming PAN ID conflict messages.
func (pqc *PanIdQueryClient) handlePanIdConflict(msg *coap.Message, info coap.MessageInfo) {
	// ACK the message if confirmable.
	if msg.GetType() == coap.TypeConfirmable {
		_ = pqc.transport.SendResponse(coap.CodeChanged, msg, info)
	}

	payload := msg.GetPayload()

	// Parse PAN ID.
	var panID uint16
	panIDTLV := findTLVInBytes(payload, TLVPanID)
	if panIDTLV != nil && len(panIDTLV) >= 2 {
		panID = binary.BigEndian.Uint16(panIDTLV[:2])
	}

	// Parse channel mask.
	var channelMask uint32
	channelMaskTLV := findTLVInBytes(payload, TLVChannelMask)
	if channelMaskTLV != nil && len(channelMaskTLV) >= 6 {
		channelMask = binary.BigEndian.Uint32(channelMaskTLV[2:6])
	}

	pqc.mu.Lock()
	cb := pqc.callback
	pqc.callback = nil
	pqc.mu.Unlock()

	if cb != nil {
		cb(panID, channelMask)
	}
}
