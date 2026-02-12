// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

// adapters.go contains adapter types, converter functions, and interface
// method implementations that wire the Instance struct to the various
// module interfaces. This file is the glue between separately-designed
// packages that cannot import each other.

import (
	"time"

	"github.com/hilli/gothread/encoding"
	macframe "github.com/hilli/gothread/mac/frame"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/routing"
)

// --------------------------------------------------------------------------
// submacCallbackBridge — breaks SubMac ↔ Mac circular construction dep
// --------------------------------------------------------------------------

// submacCallbackBridge implements submac.Callbacks by forwarding to a
// target that is set after both SubMac and Mac are constructed.
type submacCallbackBridge struct {
	target submac.Callbacks
}

func (b *submacCallbackBridge) ReceiveDone(frame *radio.Frame, err error) {
	if b.target != nil {
		b.target.ReceiveDone(frame, err)
	}
}

func (b *submacCallbackBridge) TransmitDone(frame *radio.Frame, ackFrame *radio.Frame, err error) {
	if b.target != nil {
		b.target.TransmitDone(frame, ackFrame, err)
	}
}

func (b *submacCallbackBridge) RecordFrameTransmitStatus(frame *radio.Frame, err error, retryCount uint8, willRetx bool) {
	if b.target != nil {
		b.target.RecordFrameTransmitStatus(frame, err, retryCount, willRetx)
	}
}

func (b *submacCallbackBridge) RecordCcaStatus(ccaSuccess bool, channel uint8) {
	if b.target != nil {
		b.target.RecordCcaStatus(ccaSuccess, channel)
	}
}

func (b *submacCallbackBridge) EnergyScanDone(maxRSSI int8) {
	if b.target != nil {
		b.target.EnergyScanDone(maxRSSI)
	}
}

func (b *submacCallbackBridge) FrameCounterUsed(counter uint32) {
	if b.target != nil {
		b.target.FrameCounterUsed(counter)
	}
}

// --------------------------------------------------------------------------
// settingsDriverAdapter — bridges platform.Settings → csettings.Driver
// --------------------------------------------------------------------------

// settingsDriverAdapter adapts platform.Settings (using SettingsKey, no
// index parameter) to the csettings.Driver interface (using uint16 key
// with an index parameter).
type settingsDriverAdapter struct {
	ps platform.Settings
}

func (a *settingsDriverAdapter) Init() error { return nil }
func (a *settingsDriverAdapter) Deinit()     {}

func (a *settingsDriverAdapter) Add(key uint16, value []byte) error {
	return a.ps.Add(platform.SettingsKey(key), value)
}

func (a *settingsDriverAdapter) Delete(key uint16, _ int) error {
	return a.ps.Delete(platform.SettingsKey(key))
}

func (a *settingsDriverAdapter) Get(key uint16, _ int) ([]byte, error) {
	return a.ps.Get(platform.SettingsKey(key))
}

func (a *settingsDriverAdapter) Set(key uint16, value []byte) error {
	return a.ps.Set(platform.SettingsKey(key), value)
}

func (a *settingsDriverAdapter) Wipe() error {
	return a.ps.Wipe()
}

// --------------------------------------------------------------------------
// routerCheckerAdapter — bridges routing.RouterTable → netdata.RouterChecker
// --------------------------------------------------------------------------

// routerCheckerAdapter adapts routing.RouterTable.IsAllocated to the
// netdata.RouterChecker interface.
type routerCheckerAdapter struct {
	rt *routing.RouterTable
}

func (a *routerCheckerAdapter) IsRouterIDAllocated(routerID uint8) bool {
	return a.rt.IsAllocated(routerID)
}

// --------------------------------------------------------------------------
// neighborToMLE — converts routing.Neighbor → mle.Neighbor
// --------------------------------------------------------------------------

// neighborToMLE converts a routing-layer Neighbor to an MLE-layer Neighbor.
// The routing package uses uint32 timestamps while MLE uses time.Time;
// we approximate by treating the routing timestamp as milliseconds since
// an arbitrary epoch (this is sufficient for relative age comparisons
// within the same process).
func neighborToMLE(n *routing.Neighbor) *mle.Neighbor {
	if n == nil {
		return nil
	}
	return &mle.Neighbor{
		MacAddr:      n.ExtAddress,
		RLOC16:       n.RLOC16,
		State:        routingStateToMLE(n.State),
		Mode:         n.Mode,
		Version:      n.Version,
		KeySequence:  n.KeySequence,
		LastHeard:    time.UnixMilli(int64(n.LastHeard)),
		LinkInfo:     n.LinkInfo,
		LinkFailures: n.LinkFailures,
		Counters: mle.FrameCounters{
			LinkFrameCounter: n.LinkFrameCounter,
			MleFrameCounter:  n.MleFrameCounter,
		},
		PendingChallenge: mle.Challenge(n.Challenge),
	}
}

// routerToMLE converts a routing-layer Router to an MLE-layer Router.
func routerToMLE(r *routing.Router) *mle.Router {
	if r == nil {
		return nil
	}
	neighbor := neighborToMLE(&r.Neighbor)
	return &mle.Router{
		Neighbor:                     *neighbor,
		NextHop:                      r.NextHop,
		Cost:                         r.Cost,
		LinkQualityOut:               r.LinkQualityOut,
		RemainingLinkRequestAttempts: r.LinkRequestAttempts,
		LinkAcceptCountdown:          r.LinkAcceptTimeout,
	}
}

// routingStateToMLE maps a routing.State to the corresponding mle.NeighborState.
// Both enums have the same numeric values by design.
func routingStateToMLE(s routing.State) mle.NeighborState {
	return mle.NeighborState(s)
}

// --------------------------------------------------------------------------
// Instance implements mac.Callbacks
// --------------------------------------------------------------------------

// HandleFrameRequest is called by the MAC layer when it needs a frame to
// transmit. It dequeues the next message from the mesh forwarder's direct
// queue. If the message has TxMetadata, it builds a complete 802.15.4
// frame with 6LoWPAN-compressed headers; otherwise it copies the raw
// payload directly (legacy behavior). Returns true if a frame was provided.
func (inst *Instance) HandleFrameRequest(frame *radio.Frame) bool {
	if inst.forwarder == nil {
		return false
	}
	msg := inst.forwarder.HandleFrameRequest()
	if msg == nil {
		return false
	}
	if msg.HasMetadata() {
		// Build the full 802.15.4 frame from metadata.
		built, err := mesh.BuildTxFrame(msg, inst.macSeqNum)
		if err != nil {
			return false
		}
		inst.macSeqNum++
		frame.PSDU = built
	} else {
		// Legacy: copy raw data directly into the frame.
		frame.PSDU = make([]byte, len(msg.Data))
		copy(frame.PSDU, msg.Data)
	}
	// Remember the in-flight message so HandleSentFrame can report back.
	inst.pendingTxMsg = msg
	return true
}

// HandleSentFrame is called by the MAC layer after a frame has been sent.
// It reports the transmission result to the mesh forwarder.
func (inst *Instance) HandleSentFrame(frame *radio.Frame, err error) {
	if inst.forwarder == nil || inst.pendingTxMsg == nil {
		return
	}
	msg := inst.pendingTxMsg
	inst.pendingTxMsg = nil
	inst.forwarder.HandleSentFrame(msg, err == nil)
}

// HandleReceivedFrame is called by the MAC layer when a frame is received.
// It processes the raw PSDU through the mesh forwarder, 6LoWPAN
// decompression, and UDP demultiplexing pipeline.
func (inst *Instance) HandleReceivedFrame(frame *radio.Frame) {
	if inst.forwarder == nil || frame == nil || len(frame.PSDU) == 0 {
		return
	}
	info := &mesh.ReceivedFrameInfo{
		Channel: frame.Channel,
	}
	if frame.RxInfo != nil {
		info.Rssi = frame.RxInfo.RSSI
		info.Lqi = frame.RxInfo.LQI
		info.Timestamp = frame.RxInfo.Timestamp
	}

	// Extract MAC source and destination addresses from the 802.15.4
	// frame header. These are needed for 6LoWPAN IPHC decompression
	// when the IPv6 addresses are elided (SAM=11 or DAM=11) and the
	// IID must be derived from the MAC extended address.
	var macAddrs lowpan.AddressContext
	mf := macframe.NewFrame(frame.PSDU)
	if srcAddr, err := mf.GetSrcAddr(); err == nil {
		if srcAddr.IsExtended() {
			macAddrs.SrcExtAddr = srcAddr.GetExtended()
		} else if srcAddr.IsShort() {
			macAddrs.SrcShort = srcAddr.GetShort()
		}
	}
	if dstAddr, err := mf.GetDstAddr(); err == nil {
		if dstAddr.IsExtended() {
			macAddrs.DstExtAddr = dstAddr.GetExtended()
		} else if dstAddr.IsShort() {
			macAddrs.DstShort = dstAddr.GetShort()
		}
	}

	// Step 1: Mesh forwarder strips mesh headers and returns the payload.
	payload, _, err := inst.forwarder.HandleReceivedFrame(frame.PSDU, info)
	if err != nil || len(payload) == 0 {
		return
	}

	// Step 2: Check for 6LoWPAN IPHC dispatch.
	if !lowpan.IsLowpanHc(payload) {
		return // not a 6LoWPAN-compressed frame; drop for now
	}

	// Step 3: Decompress the IPv6 header using the MAC addresses
	// extracted above. When addresses are fully inline (SAM=00,
	// DAM=00) the AddressContext is unused; when elided (SAM=11,
	// DAM=11) the IID is derived from the extended MAC address.
	ipv6Raw, consumed, err := lowpan.DecompressHeader(payload, macAddrs, nil)
	if err != nil {
		return
	}

	hdr := ip6.HeaderFromBytes(ipv6Raw)
	remaining := payload[consumed:]

	// Step 4: Determine if the next header is UDP.
	// NextHeader == ProtoUDP (17) means UDP was carried inline.
	// NextHeader == 0 means the NH was compressed (NHC); attempt UDP
	// decompression from the remaining data.
	nextHdr := hdr.GetNextHeader()
	isUDP := nextHdr == ip6.ProtoUDP
	isNhCompressed := nextHdr == 0

	if !isUDP && !isNhCompressed && nextHdr != ip6.ProtoICMPv6 {
		return // unsupported protocol
	}

	// Dispatch based on next header protocol.
	switch {
	case isUDP || isNhCompressed:
		// UDP path (existing code, unchanged)
		var srcPort, dstPort uint16
		var udpPayload []byte
		if isNhCompressed {
			udpHdr, udpConsumed, err := lowpan.DecompressUDPHeader(remaining)
			if err != nil {
				return
			}
			srcPort = encoding.BigEndianReadUint16(udpHdr[0:2])
			dstPort = encoding.BigEndianReadUint16(udpHdr[2:4])
			udpPayload = remaining[udpConsumed:]
		} else {
			if len(remaining) < 8 {
				return
			}
			srcPort = encoding.BigEndianReadUint16(remaining[0:2])
			dstPort = encoding.BigEndianReadUint16(remaining[2:4])
			udpPayload = remaining[8:]
		}
		messageInfo := &ip6.MessageInfo{
			PeerAddr: hdr.GetSource(),
			PeerPort: srcPort,
			SockAddr: hdr.GetDestination(),
			SockPort: dstPort,
			HopLimit: hdr.GetHopLimit(),
		}
		if inst.udpManager != nil {
			inst.udpManager.HandleMessage(udpPayload, messageInfo)
		}

	case nextHdr == ip6.ProtoICMPv6:
		messageInfo := &ip6.MessageInfo{
			PeerAddr: hdr.GetSource(),
			SockAddr: hdr.GetDestination(),
			HopLimit: hdr.GetHopLimit(),
		}
		if inst.icmpManager != nil {
			inst.icmpManager.HandleMessage(remaining, messageInfo)
		}

	default:
		return // unsupported protocol
	}
}

// --------------------------------------------------------------------------
// Instance implements mle.Transport
// --------------------------------------------------------------------------

// SendMLE sends an MLE message to the given IPv6 destination. The message
// is wrapped in a TxMessage with full IPv6/transport metadata and enqueued
// to the mesh forwarder for transmission. If the destination is a mesh-local
// RLOC, the destination RLOC16 is extracted from the address; otherwise the
// message is sent as a broadcast.
func (inst *Instance) SendMLE(msg []byte, dst ip6.Address) error {
	if inst.forwarder == nil {
		return nil
	}
	// Determine the destination RLOC16. Mesh-local RLOC addresses carry
	// the RLOC16 in the last two bytes of the IID:
	//   [prefix]:0000:00FF:FE00:[RLOC16]
	var dstRLOC uint16 = 0xFFFF // broadcast default
	if dst.IsRoutingLocator() {
		iid := dst.GetIid()
		dstRLOC = iid.GetLocator()
	}

	// Build the source address: use the mesh-local RLOC address for
	// mesh-local destinations, link-local for everything else.
	var srcAddr ip6.Address
	if dst.IsRoutingLocator() || dst.IsAnycastRoutingLocator() {
		srcAddr = inst.GetMeshLocalAddress()
	} else {
		srcAddr = inst.GetLinkLocalAddress()
	}

	// Build TxMetadata for proper 6LoWPAN frame construction.
	meta := mesh.BuildUDPMetadata(srcAddr, dst, mle.UDPPort, mle.UDPPort, 64)
	meta.SrcExtAddr = inst.GetExtAddress()
	meta.UseSrcShort = true
	meta.UseDstShort = (dstRLOC != 0xFFFF) // short for unicast, ext for broadcast
	if inst.mac != nil {
		meta.PanId = uint16(inst.mac.GetPanID())
	}

	txMsg := mesh.NewTxMessageWithMetadata(msg, dstRLOC, inst.rloc16, meta)
	txMsg.Priority = uint8(mesh.PriorityNet)
	return inst.forwarder.SendMessage(txMsg)
}

// GetExtAddress returns the extended MAC address of this device.
func (inst *Instance) GetExtAddress() types.ExtAddress {
	if inst.mac != nil {
		return inst.mac.GetExtAddress()
	}
	return types.ExtAddress{}
}

// GetLinkLocalAddress returns the IPv6 link-local address derived from
// the device's extended MAC address. The address is fe80:: followed by a
// Modified EUI-64 identifier (the extended address with the Universal/Local
// bit toggled, per RFC 4291 Appendix A).
func (inst *Instance) GetLinkLocalAddress() ip6.Address {
	var addr ip6.Address
	addr[0] = 0xfe
	addr[1] = 0x80
	// Bytes 2-7 are zero (link-local prefix is fe80::/64).
	ext := inst.mac.GetExtAddress()
	copy(addr[8:], ext[:])
	addr[8] ^= 0x02 // toggle Universal/Local bit
	return addr
}

// GetMeshLocalAddress returns the IPv6 mesh-local RLOC address. The address
// is formed as [mesh-local-prefix]:0000:00ff:fe00:[RLOC16] per the Thread
// specification.
func (inst *Instance) GetMeshLocalAddress() ip6.Address {
	var addr ip6.Address
	copy(addr[0:8], inst.meshLocalPrefix[:])
	// IID: 0000:00FF:FE00:RLOC16
	addr[11] = 0xff
	addr[12] = 0xfe
	addr[14] = byte(inst.rloc16 >> 8)
	addr[15] = byte(inst.rloc16)
	return addr
}

// GetLinkLocalAllRoutersMulticast returns the link-local all-routers
// multicast address (ff02::2).
func (inst *Instance) GetLinkLocalAllRoutersMulticast() ip6.Address {
	var addr ip6.Address
	addr[0] = 0xff
	addr[1] = 0x02
	addr[15] = 0x02
	return addr
}

// --------------------------------------------------------------------------
// Instance implements mle.KeyProvider (delegates to key.Manager)
// --------------------------------------------------------------------------

// GetCurrentKeySequence delegates to key.Manager.
func (inst *Instance) GetCurrentKeySequence() uint32 {
	return inst.keyManager.GetCurrentKeySequence()
}

// GetCurrentMleKey delegates to key.Manager.
func (inst *Instance) GetCurrentMleKey() key.MleKey {
	return inst.keyManager.GetCurrentMleKey()
}

// GetTemporaryMleKey delegates to key.Manager.
func (inst *Instance) GetTemporaryMleKey(seq uint32) key.MleKey {
	return inst.keyManager.GetTemporaryMleKey(seq)
}

// GetMleFrameCounter delegates to key.Manager.
func (inst *Instance) GetMleFrameCounter() uint32 {
	return inst.keyManager.GetMleFrameCounter()
}

// IncrementMleFrameCounter delegates to key.Manager.
func (inst *Instance) IncrementMleFrameCounter() {
	inst.keyManager.IncrementMleFrameCounter()
}

// GetMacFrameCounter delegates to key.Manager.
func (inst *Instance) GetMacFrameCounter() uint32 {
	return inst.keyManager.GetMacFrameCounter()
}

// SetCurrentKeySequence delegates to key.Manager.
func (inst *Instance) SetCurrentKeySequence(seq uint32, flags key.SeqUpdateFlag) {
	inst.keyManager.SetCurrentKeySequence(seq, flags)
}

// --------------------------------------------------------------------------
// Instance implements mle.RouterLookup
// --------------------------------------------------------------------------

// FindRouterByRLOC16 looks up a router by RLOC16 and converts to MLE type.
func (inst *Instance) FindRouterByRLOC16(rloc16 uint16) *mle.Router {
	r := inst.routerTable.FindRouterByRLOC16(rloc16)
	return routerToMLE(r)
}

// FindRouterByExtAddress looks up a router by extended address and converts
// to MLE type.
func (inst *Instance) FindRouterByExtAddress(addr types.ExtAddress) *mle.Router {
	r := inst.routerTable.FindRouterByExtAddress(addr)
	return routerToMLE(r)
}

// --------------------------------------------------------------------------
// Instance implements mle.RouteDataProvider
// --------------------------------------------------------------------------

// GetRouteData returns the Route64 TLV components for the local router.
func (inst *Instance) GetRouteData(selfRouterID, leaderRouterID uint8) (sequence uint8, mask mle.RouterIDSet, entries []mle.Route64Entry) {
	sequence = inst.routerTable.GetRouterIDSequence()
	mask = inst.routerTable.GetRouterIDSet()

	// Build entries for each allocated router in order.
	for id := uint8(0); id <= mle.MaxRouterID; id++ {
		if !mask.Contains(id) {
			continue
		}
		r := inst.routerTable.FindRouterByID(id)
		if r == nil {
			entries = append(entries, mle.Route64Entry{})
			continue
		}

		entry := mle.Route64Entry{
			LinkQualityOut: r.LinkQualityOut,
			LinkQualityIn:  r.LinkInfo.GetQualityIn(),
			Cost:           r.Cost,
		}

		// For ourselves, cost is 0 and link quality is 0.
		if id == selfRouterID {
			entry.Cost = 0
			entry.LinkQualityOut = 0
			entry.LinkQualityIn = 0
		}

		entries = append(entries, entry)
	}

	return sequence, mask, entries
}

// --------------------------------------------------------------------------
// Instance implements mle.AdvertisementRouterOps
// --------------------------------------------------------------------------

// GetActiveRouterCount delegates to the routing table.
func (inst *Instance) GetActiveRouterCount() int {
	return inst.routerTable.GetActiveRouterCount()
}

// GetNeighborCount delegates to the routing table.
func (inst *Instance) GetNeighborCount(minLinkQuality uint8) int {
	return inst.routerTable.GetNeighborCount(minLinkQuality)
}

// IsAllocated delegates to the routing table.
func (inst *Instance) IsAllocated(routerID uint8) bool {
	return inst.routerTable.IsAllocated(routerID)
}

// GetRouterIDSequence delegates to the routing table.
func (inst *Instance) GetRouterIDSequence() uint8 {
	return inst.routerTable.GetRouterIDSequence()
}

// IsRouteTlvIDSequenceMoreRecent delegates to the routing table.
func (inst *Instance) IsRouteTlvIDSequenceMoreRecent(sequence uint8) bool {
	return inst.routerTable.IsRouteTlvIDSequenceMoreRecent(sequence)
}

// UpdateRouterIDSet delegates to the routing table.
func (inst *Instance) UpdateRouterIDSet(sequence uint8, idSet mle.RouterIDSet, nowMs uint32) bool {
	return inst.routerTable.UpdateRouterIDSet(sequence, idSet, nowMs)
}

// UpdateRoutes converts the raw Route64 components into a RouteTlvData
// and delegates to the routing table.
func (inst *Instance) UpdateRoutes(sequence uint8, mask mle.RouterIDSet, entries []mle.Route64Entry, neighborID uint8, selfRouterID uint8) bool {
	tlv := &routing.RouteTlvData{
		Sequence:     sequence,
		RouterIDMask: mask,
		Entries:      entries,
	}
	return inst.routerTable.UpdateRoutes(tlv, neighborID, selfRouterID)
}

// UpdateRouterOnFtdChild converts raw Route64 components and delegates
// to the routing table.
func (inst *Instance) UpdateRouterOnFtdChild(sequence uint8, mask mle.RouterIDSet, entries []mle.Route64Entry, parentID uint8) {
	tlv := &routing.RouteTlvData{
		Sequence:     sequence,
		RouterIDMask: mask,
		Entries:      entries,
	}
	inst.routerTable.UpdateRouterOnFtdChild(tlv, parentID)
}

// FindRouterByID looks up a router by ID and converts to MLE type.
func (inst *Instance) FindRouterByID(routerID uint8) *mle.Router {
	r := inst.routerTable.FindRouterByID(routerID)
	return routerToMLE(r)
}

// RemoveRouterLink removes the link to the router matching the given MLE
// Router. It locates the routing-layer Router by extended address and
// delegates removal to the routing table.
func (inst *Instance) RemoveRouterLink(router *mle.Router) {
	if router == nil {
		return
	}
	r := inst.routerTable.FindRouterByExtAddress(router.MacAddr)
	if r != nil {
		inst.routerTable.RemoveRouterLink(r)
	}
}

// --------------------------------------------------------------------------
// Instance implements mle.ConnectivityProvider
// --------------------------------------------------------------------------

// GetConnectivityTLV builds and returns the Connectivity TLV data.
func (inst *Instance) GetConnectivityTLV() mle.ConnectivityTLV {
	return mle.ConnectivityTLV{
		LinkQuality3:  uint8(inst.routerTable.GetNeighborCount(3)),
		LinkQuality2:  uint8(inst.routerTable.GetNeighborCount(2)),
		LinkQuality1:  uint8(inst.routerTable.GetNeighborCount(1)),
		ActiveRouters: uint8(inst.routerTable.GetActiveRouterCount()),
		IDSequence:    inst.routerTable.GetRouterIDSequence(),
		// LeaderCost, SEDBufferSize, SEDDatagramCount, Flags are
		// populated when the router's full leader routing state is
		// available (Phase 28b+).
	}
}

// --------------------------------------------------------------------------
// Instance implements mle.NetworkInfoProvider
// --------------------------------------------------------------------------

// GetNetworkName returns the Thread network name.
func (inst *Instance) GetNetworkName() string {
	return inst.networkName
}

// GetExtendedPanID returns the 8-byte Extended PAN ID.
func (inst *Instance) GetExtendedPanID() [8]byte {
	return inst.extendedPanID
}

// GetSteeringData returns the steering data for Joiner filtering.
func (inst *Instance) GetSteeringData() []byte {
	return inst.steeringData
}

// IsNativeCommissioner reports whether native commissioning is enabled.
func (inst *Instance) IsNativeCommissioner() bool {
	return inst.nativeCommissioner
}

// --------------------------------------------------------------------------
// Helper: scheduleTimerDirect — schedules a timer on the event loop
// --------------------------------------------------------------------------

// scheduleTimerDirect schedules a timer directly on the timer scheduler.
// This is safe to call from the event loop goroutine (during module
// construction or from within a posted task). It does NOT go through
// PostTask to avoid deadlock during construction.
func (inst *Instance) scheduleTimerDirect(delay time.Duration, fn func()) {
	inst.timers.schedule(delay, fn)
}

// --------------------------------------------------------------------------
// Helper: postTask — lowercase wrapper for internal use
// --------------------------------------------------------------------------

// postTask is a lowercase wrapper around PostTask for passing to module
// Config structs. It schedules a function to run on the event loop.
func (inst *Instance) postTask(fn func()) {
	inst.PostTask(fn)
}

// --------------------------------------------------------------------------
// Helper: sendCoAP — satisfies coap.Sender func type
// --------------------------------------------------------------------------

// sendCoAP is a function satisfying coap.Sender that transmits CoAP
// data through the Instance's mesh forwarder. The peer address from the
// MessageInfo is used to determine the destination RLOC16, and full
// TxMetadata is populated for proper 6LoWPAN frame construction.
func (inst *Instance) sendCoAP(data []byte, info coap.MessageInfo) error {
	if inst.forwarder == nil {
		return nil
	}
	// Derive destination RLOC16 from the peer address.
	var peerAddr ip6.Address
	copy(peerAddr[:], info.PeerAddr[:])
	var dstRLOC uint16 = 0xFFFF // broadcast default
	if peerAddr.IsRoutingLocator() {
		iid := peerAddr.GetIid()
		dstRLOC = iid.GetLocator()
	}

	// Build TxMetadata for proper 6LoWPAN frame construction.
	var srcAddr [16]byte
	copy(srcAddr[:], info.LocalAddr[:])
	meta := mesh.BuildUDPMetadata(srcAddr, info.PeerAddr, udp.TmfPort, info.PeerPort, 64)
	meta.SrcExtAddr = inst.GetExtAddress()
	meta.UseSrcShort = true
	meta.UseDstShort = (dstRLOC != 0xFFFF) // short for unicast
	if inst.mac != nil {
		meta.PanId = uint16(inst.mac.GetPanID())
	}

	txMsg := mesh.NewTxMessageWithMetadata(data, dstRLOC, inst.rloc16, meta)
	txMsg.Priority = uint8(mesh.PriorityNormal)
	return inst.forwarder.SendMessage(txMsg)
}
