// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package trel

import (
	"sync"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
)

// --------------------------------------------------------------------------
// Counters — traffic counters for the TREL link
// --------------------------------------------------------------------------

// Counters tracks transmit and receive statistics for the TREL link.
type Counters struct {
	TxPackets  uint32
	TxBytes    uint32
	TxFailures uint32
	RxPackets  uint32
	RxBytes    uint32
}

// --------------------------------------------------------------------------
// Link — TREL link coordinator
// --------------------------------------------------------------------------

// Link is the main TREL link coordinator. It manages the state machine,
// translates between IEEE 802.15.4 frames and TREL packets, and drives
// the Interface and PeerTable.
//
// This is a Go port of ot::Trel::Link from OpenThread's
// src/core/radio/trel_link.{hpp,cpp}. It is simplified to be self-contained
// and testable without the full OpenThread Instance, NeighborTable, or MLE.
type Link struct {
	mu sync.Mutex

	state    radio.State
	iface    *Interface
	peers    *PeerTable
	counters Counters

	// extAddr is the local extended MAC address.
	extAddr types.ExtAddress
	// panID is the PAN ID this link is operating on.
	panID types.PanID
	// channel is the current IEEE 802.15.4 channel.
	channel uint8
	// packetNumber is a monotonically increasing per-tx counter used in TREL
	// headers to allow receivers to detect duplicates and match acks.
	packetNumber uint32

	// callbacks delivers radio events back to the stack.
	callbacks radio.Callbacks

	// txPacket holds the TREL packet currently being transmitted.
	txPacket *Packet
	// txFrame is the pre-allocated transmit frame buffer.
	txFrame radio.Frame
}

// NewLink creates a new TREL Link with the given platform implementation
// and optional radio callbacks. Pass nil for callbacks if not needed.
func NewLink(platform Platform, callbacks radio.Callbacks) *Link {
	l := &Link{
		state:     radio.StateDisabled,
		peers:     NewPeerTable(),
		callbacks: callbacks,
	}
	l.iface = NewInterface(platform)
	l.iface.SetRxCallback(l.handleReceived)
	l.txFrame.PSDU = make([]byte, radio.FrameMaxSize)
	return l
}

// --------------------------------------------------------------------------
// Accessors
// --------------------------------------------------------------------------

// GetState returns the current link state.
func (l *Link) GetState() radio.State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

// GetInterface returns the underlying TREL Interface.
func (l *Link) GetInterface() *Interface {
	return l.iface
}

// GetPeerTable returns the peer table.
func (l *Link) GetPeerTable() *PeerTable {
	return l.peers
}

// GetCounters returns a copy of the traffic counters.
func (l *Link) GetCounters() Counters {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.counters
}

// ResetCounters zeroes all traffic counters.
func (l *Link) ResetCounters() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counters = Counters{}
}

// GetTransmitBuffer returns the pre-allocated transmit frame buffer.
func (l *Link) GetTransmitBuffer() *radio.Frame {
	return &l.txFrame
}

// --------------------------------------------------------------------------
// Configuration
// --------------------------------------------------------------------------

// SetExtAddress sets the local extended MAC address used in TREL headers.
func (l *Link) SetExtAddress(addr types.ExtAddress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.extAddr = addr
}

// SetPanID sets the PAN ID used for TREL header filtering.
func (l *Link) SetPanID(panID types.PanID) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.panID = panID
}

// SetChannel sets the channel used for TREL header filtering.
func (l *Link) SetChannel(channel uint8) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.channel = channel
}

// --------------------------------------------------------------------------
// State machine
// --------------------------------------------------------------------------

// Enable enables the TREL link and transitions from Disabled to Sleep.
func (l *Link) Enable() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.state != radio.StateDisabled {
		return errors.ErrInvalidState
	}

	l.iface.Init()
	l.iface.SetEnabled(true, RequesterStack)

	l.state = radio.StateSleep
	return nil
}

// Disable disables the TREL link.
func (l *Link) Disable() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.state == radio.StateDisabled {
		return nil
	}

	l.iface.SetEnabled(false, RequesterStack)
	l.state = radio.StateDisabled
	return nil
}

// Sleep transitions the link to sleep mode.
func (l *Link) Sleep() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	switch l.state {
	case radio.StateDisabled:
		return errors.ErrInvalidState
	case radio.StateSleep:
		return nil
	}

	l.state = radio.StateSleep
	return nil
}

// Receive transitions the link to receive mode on the given channel.
func (l *Link) Receive(channel uint8) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.state == radio.StateDisabled {
		return errors.ErrInvalidState
	}

	l.channel = channel
	l.state = radio.StateReceive
	return nil
}

// --------------------------------------------------------------------------
// Transmit
// --------------------------------------------------------------------------

// Send builds a TREL packet from the given payload and destination address,
// and transmits it via the Interface. The destAddr determines broadcast vs
// unicast: a nil or zero destination sends a broadcast, otherwise unicast.
//
// For unicast packets, an ack is requested by default. The payload is
// typically an IEEE 802.15.4 frame (PSDU).
func (l *Link) Send(payload []byte, destAddr *types.ExtAddress) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.state == radio.StateDisabled {
		return errors.ErrInvalidState
	}

	var pktType Type
	var ackMode AckMode
	isBroadcast := destAddr == nil || *destAddr == (types.ExtAddress{})

	if isBroadcast {
		pktType = TypeBroadcast
		ackMode = AckModeNoAck
	} else {
		pktType = TypeUnicast
		ackMode = AckModeRequested
	}

	hdrSize := int(HeaderSize(pktType))
	buf := make([]byte, hdrSize+len(payload))

	n, err := MarshalHeader(buf, pktType, ackMode, l.channel, l.panID,
		l.packetNumber, l.extAddr, destAddr)
	if err != nil {
		l.counters.TxFailures++
		return err
	}

	copy(buf[n:], payload)
	l.packetNumber++

	pkt := NewPacket(buf)
	l.txPacket = &pkt

	l.state = radio.StateTransmit

	txErr := l.iface.Send(pkt, l.peers)

	l.counters.TxPackets++
	l.counters.TxBytes += uint32(len(buf))

	// Transition back to receive after transmit.
	l.state = radio.StateReceive

	if txErr != nil {
		l.counters.TxFailures++
		if l.callbacks != nil {
			l.callbacks.HandleTransmitDone(&l.txFrame, nil, errors.ErrFailed)
		}
		return txErr
	}

	if l.callbacks != nil {
		l.callbacks.HandleTransmitDone(&l.txFrame, nil, nil)
	}
	return nil
}

// --------------------------------------------------------------------------
// Receive path
// --------------------------------------------------------------------------

// handleReceived is the rx callback registered with the Interface.
func (l *Link) handleReceived(pkt Packet, senderAddr ip6.SockAddr) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.state != radio.StateReceive && l.state != radio.StateTransmit {
		return
	}

	if !pkt.IsHeaderValid() {
		return
	}

	h := pkt.GetHeader()

	// Filter: channel and PAN ID must match.
	if h.GetChannel() != l.channel {
		return
	}
	if h.GetPanID() != l.panID {
		return
	}

	// Ignore packets from ourselves.
	if h.GetSource() == l.extAddr {
		return
	}

	switch h.GetType() {
	case TypeAck:
		l.handleAck(pkt)
	case TypeBroadcast:
		l.handleDataPacket(pkt, senderAddr)
	case TypeUnicast:
		// For unicast, check that the destination is us.
		if h.GetDestination() != l.extAddr {
			return
		}
		l.handleDataPacket(pkt, senderAddr)
		// Send ack if requested.
		if h.GetAckMode() == AckModeRequested {
			l.sendAck(h.GetSource(), h.GetPacketNumber())
		}
	}
}

// handleDataPacket processes a received broadcast or unicast data packet.
func (l *Link) handleDataPacket(pkt Packet, senderAddr ip6.SockAddr) {
	l.counters.RxPackets++
	l.counters.RxBytes += uint32(pkt.GetLength())

	// Update or add the sender in the peer table.
	src := pkt.GetHeader().GetSource()
	l.peers.Add(src, senderAddr)

	if l.callbacks != nil {
		payload := pkt.GetPayload()
		if payload != nil {
			rxFrame := &radio.Frame{
				PSDU:    payload,
				Channel: pkt.GetHeader().GetChannel(),
				RxInfo: &radio.RxInfo{
					RSSI: radio.RSSIInvalid, // TREL doesn't provide RSSI
					LQI:  0,
				},
			}
			l.callbacks.HandleReceiveDone(rxFrame, nil)
		}
	}
}

// handleAck processes a received ack packet.
func (l *Link) handleAck(pkt Packet) {
	h := pkt.GetHeader()

	// Ack must be addressed to us.
	if h.GetDestination() != l.extAddr {
		return
	}

	// Check that this ack matches our most recent transmission.
	if l.txPacket == nil {
		return
	}
	txH := l.txPacket.GetHeader()
	if txH.GetPacketNumber() != h.GetPacketNumber() {
		return
	}

	// Ack received successfully — nothing more to do in the simplified
	// implementation. In the full OpenThread stack this would update
	// neighbor info and frame-pending bits.
}

// sendAck sends a TREL ack packet in response to a received packet that
// requested acknowledgment.
func (l *Link) sendAck(destExtAddr types.ExtAddress, packetNumber uint32) {
	buf := make([]byte, HeaderSizeAck)

	_, err := MarshalHeader(buf, TypeAck, AckModeNoAck, l.channel, l.panID,
		packetNumber, l.extAddr, &destExtAddr)
	if err != nil {
		return
	}

	pkt := NewPacket(buf)
	_ = l.iface.Send(pkt, l.peers)
}

// --------------------------------------------------------------------------
// ProcessReceivedPacket — public entry for platform-delivered packets
// --------------------------------------------------------------------------

// ProcessReceivedPacket is the public entry point for the platform to
// deliver a received TREL packet. It delegates to Interface.HandleReceived.
func (l *Link) ProcessReceivedPacket(data []byte, senderAddr ip6.SockAddr) {
	l.iface.HandleReceived(data, senderAddr)
}
