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
	"github.com/hilli/gothread/meshcop"
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
	"github.com/hilli/gothread/thread/supervision"
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

func (a *settingsDriverAdapter) Delete(key uint16, index int) error {
	return a.ps.Delete(platform.SettingsKey(key), index)
}

func (a *settingsDriverAdapter) Get(key uint16, index int) ([]byte, error) {
	return a.ps.Get(platform.SettingsKey(key), index)
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

// childToMLE converts a routing-layer Child to an MLE-layer Child.
// The routing package stores IP6Addresses as a slice while MLE uses a
// fixed-size array; RequestTLVs differ in capacity (6 vs 5).
func childToMLE(c *routing.Child) *mle.Child {
	if c == nil {
		return nil
	}
	neighbor := neighborToMLE(&c.Neighbor)
	mc := &mle.Child{
		Neighbor:                *neighbor,
		Timeout:                 c.Timeout,
		MeshLocalIID:            c.MeshLocalIID,
		NetworkDataVersion:      c.NetworkDataVersion,
		SupervisionInterval:     c.SupervisionInterval,
		SecondsSinceSupervision: c.SecondsSinceSupervision,
	}
	// Copy IP6 addresses (routing uses slice, mle uses fixed array).
	for i := 0; i < len(c.IP6Addresses) && i < mle.MaxChildIPAddresses; i++ {
		mc.IP6Addresses[i] = c.IP6Addresses[i]
	}
	mc.IP6AddressCount = uint8(len(c.IP6Addresses))
	if mc.IP6AddressCount > mle.MaxChildIPAddresses {
		mc.IP6AddressCount = mle.MaxChildIPAddresses
	}
	// Copy RequestTLVs (routing has [6], mle has [5]).
	n := len(c.RequestTLVs)
	if n > mle.MaxRequestTLVs {
		n = mle.MaxRequestTLVs
	}
	for i := 0; i < n; i++ {
		mc.RequestTLVs[i] = c.RequestTLVs[i]
	}
	mc.RequestTLVCount = uint8(n)
	return mc
}

// --------------------------------------------------------------------------
// childProviderAdapter — bridges routing.ChildTable → supervision.ChildProvider
// --------------------------------------------------------------------------

// childProviderAdapter implements supervision.ChildProvider by returning
// mle.Child copies converted from the routing.ChildTable. It caches the
// mapping so that mutations made by the Supervisor (e.g. incrementing
// SecondsSinceSupervision) can be written back to the routing entries.
type childProviderAdapter struct {
	childTable  *routing.ChildTable
	lastMLE     []*mle.Child     // cached from last GetChildren()
	lastRouting []*routing.Child // parallel slice of routing children
}

// GetChildren returns mle.Child pointers converted from the routing table.
func (a *childProviderAdapter) GetChildren() []*mle.Child {
	a.lastRouting = a.childTable.Children(routing.FilterValid)
	a.lastMLE = make([]*mle.Child, 0, len(a.lastRouting))
	for _, rc := range a.lastRouting {
		a.lastMLE = append(a.lastMLE, childToMLE(rc))
	}
	return a.lastMLE
}

// WriteBack syncs supervision counters from the cached mle.Child copies
// back to the routing-layer children.
func (a *childProviderAdapter) WriteBack() {
	for i, mc := range a.lastMLE {
		if i < len(a.lastRouting) {
			a.lastRouting[i].SecondsSinceSupervision = mc.SecondsSinceSupervision
		}
	}
}

// Compile-time assertion.
var _ supervision.ChildProvider = (*childProviderAdapter)(nil)

// --------------------------------------------------------------------------
// supervisionMessageSender — sends empty supervision frames via forwarder
// --------------------------------------------------------------------------

// supervisionMessageSender implements supervision.MessageSender by sending
// an empty data frame to the child's RLOC16 through the mesh forwarder.
type supervisionMessageSender struct {
	inst *Instance
}

// SendSupervisionMessage sends an empty supervision frame to the child.
func (s *supervisionMessageSender) SendSupervisionMessage(child *mle.Child) error {
	if s.inst.forwarder == nil {
		return nil
	}
	msg := mesh.NewTxMessage(nil, child.RLOC16, s.inst.rloc16)
	msg.Priority = uint8(mesh.PriorityNet)
	return s.inst.forwarder.SendMessage(msg)
}

// Compile-time assertion.
var _ supervision.MessageSender = (*supervisionMessageSender)(nil)

// --------------------------------------------------------------------------
// parentLossHandler — triggers re-attach on supervision timeout
// --------------------------------------------------------------------------

// parentLossHandler implements supervision.ParentLossHandler by detaching
// and starting a fresh attach sequence.
type parentLossHandler struct {
	inst *Instance
}

// HandleParentLoss detaches from the current parent and begins re-attachment.
func (h *parentLossHandler) HandleParentLoss() {
	if h.inst.mleService == nil {
		return
	}
	_ = h.inst.mleService.Mle().BecomeDetached()
	h.inst.mleService.Attacher.Start(mle.AttachAnyPartition)
	h.inst.scheduleAttachTimer()
}

// Compile-time assertion.
var _ supervision.ParentLossHandler = (*parentLossHandler)(nil)

// --------------------------------------------------------------------------
// realTimer — wraps time.Timer for supervision.Timer
// --------------------------------------------------------------------------

// realTimer implements supervision.Timer using the standard library's
// time.Timer. It is used by the SupervisionListener to detect parent loss.
type realTimer struct {
	t *time.Timer
}

// newRealTimer creates a realTimer in the stopped state.
func newRealTimer() *realTimer {
	t := time.NewTimer(time.Hour)
	t.Stop()
	return &realTimer{t: t}
}

// Reset reschedules the timer to fire after d.
func (rt *realTimer) Reset(d time.Duration) { rt.t.Reset(d) }

// Stop cancels the pending timer.
func (rt *realTimer) Stop() bool { return rt.t.Stop() }

// C returns the channel on which the timer fires.
func (rt *realTimer) C() <-chan time.Time { return rt.t.C }

// Compile-time assertion.
var _ supervision.Timer = (*realTimer)(nil)

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

	// Update child supervision listener — any received frame from the
	// parent resets the supervision timeout so we don't falsely detect
	// parent loss.
	if inst.supervisionListener != nil && inst.supervisionListener.IsRunning() {
		inst.supervisionListener.UpdateOnReceive()
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
		linkInfo := &ip6.LinkInfo{
			SrcExtAddr: macAddrs.SrcExtAddr,
			RSSI:       info.Rssi,
		}
		messageInfo := &ip6.MessageInfo{
			PeerAddr: hdr.GetSource(),
			PeerPort: srcPort,
			SockAddr: hdr.GetDestination(),
			SockPort: dstPort,
			HopLimit: hdr.GetHopLimit(),
			LinkInfo: linkInfo,
		}
		if inst.udpManager != nil {
			inst.udpManager.HandleMessage(udpPayload, messageInfo)
		}

	case nextHdr == ip6.ProtoICMPv6:
		messageInfo := &ip6.MessageInfo{
			PeerAddr: hdr.GetSource(),
			SockAddr: hdr.GetDestination(),
			HopLimit: hdr.GetHopLimit(),
			LinkInfo: &ip6.LinkInfo{
				SrcExtAddr: macAddrs.SrcExtAddr,
				RSSI:       info.Rssi,
			},
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
	var leaderCost uint8
	if inst.mleService != nil {
		leaderRouterID := inst.mleService.Mle().GetLeaderData().LeaderRouterID
		leaderRLOC16 := uint16(leaderRouterID) << 10
		leaderCost = inst.routerTable.GetPathCostToLeader(leaderRLOC16)
	}
	return mle.ConnectivityTLV{
		Flags:            inst.parentPriority << 6,
		LinkQuality3:     uint8(inst.routerTable.GetNeighborCount(3)),
		LinkQuality2:     uint8(inst.routerTable.GetNeighborCount(2)),
		LinkQuality1:     uint8(inst.routerTable.GetNeighborCount(1)),
		ActiveRouters:    uint8(inst.routerTable.GetActiveRouterCount()),
		IDSequence:       inst.routerTable.GetRouterIDSequence(),
		LeaderCost:       leaderCost,
		SEDBufferSize:    inst.sedBufferSize,
		SEDDatagramCount: inst.sedDatagramCount,
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
// Instance implements mle.DatasetProvider
// --------------------------------------------------------------------------

// GetActiveTimestamp returns the timestamp from the Active Operational Dataset.
func (inst *Instance) GetActiveTimestamp() meshcop.Timestamp {
	return inst.activeDataset.GetTimestamp()
}

// GetPendingTimestamp returns the timestamp from the Pending Operational Dataset.
func (inst *Instance) GetPendingTimestamp() meshcop.Timestamp {
	return inst.pendingDataset.GetTimestamp()
}

// ReadActiveDataset returns the serialised Active Operational Dataset, or
// nil if the dataset is empty or an error occurs.
func (inst *Instance) ReadActiveDataset() []byte {
	ds, err := inst.activeDataset.Read()
	if err != nil || ds == nil {
		return nil
	}
	return ds.Bytes()
}

// ReadPendingDataset returns the serialised Pending Operational Dataset, or
// nil if the dataset is empty or an error occurs.
func (inst *Instance) ReadPendingDataset() []byte {
	ds, err := inst.pendingDataset.Read()
	if err != nil || ds == nil {
		return nil
	}
	return ds.Bytes()
}

// --------------------------------------------------------------------------
// Instance implements mle.NetworkDataProvider
// --------------------------------------------------------------------------

// GetNetworkData returns the current network data bytes. When stableOnly
// is true, only TLVs with the stable bit set are included.
func (inst *Instance) GetNetworkData(stableOnly bool) []byte {
	if inst.netdataLeader == nil {
		return nil
	}
	if stableOnly {
		return inst.netdataLeader.StableData()
	}
	return inst.netdataLeader.Data()
}

// --------------------------------------------------------------------------
// Instance implements mle.MacInfoProvider
// --------------------------------------------------------------------------

// GetPanID returns the PAN ID of the MAC layer.
func (inst *Instance) GetPanID() uint16 {
	if inst.mac == nil {
		return 0
	}
	return uint16(inst.mac.GetPanID())
}

// GetPanChannel returns the operating channel of the MAC layer.
func (inst *Instance) GetPanChannel() uint8 {
	if inst.mac == nil {
		return 0
	}
	return inst.mac.GetPanChannel()
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

// --------------------------------------------------------------------------
// PollTransmitter adapter — bridges supervision.DataPollSender to mac.Mac
// --------------------------------------------------------------------------

// macPollTransmitter implements supervision.PollTransmitter by delegating
// to the Mac layer's RequestDataPollTransmission method.
type macPollTransmitter struct {
	inst *Instance
}

// TransmitDataPoll triggers a MAC-layer data poll (802.15.4 Data Request).
func (t *macPollTransmitter) TransmitDataPoll() error {
	if t.inst.mac != nil {
		t.inst.mac.RequestDataPollTransmission()
	}
	return nil
}
