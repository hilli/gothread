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

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
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
// transmit. Returns true if a frame was provided.
func (inst *Instance) HandleFrameRequest(frame *radio.Frame) bool {
	// TODO(Phase 28b): Wire to MLE/mesh forwarding for frame production.
	_ = frame
	return false
}

// HandleSentFrame is called by the MAC layer after a frame has been sent.
func (inst *Instance) HandleSentFrame(frame *radio.Frame, err error) {
	// TODO(Phase 28b): Wire to MLE for acknowledgement processing.
	_ = frame
	_ = err
}

// HandleReceivedFrame is called by the MAC layer when a frame is received.
func (inst *Instance) HandleReceivedFrame(frame *radio.Frame) {
	// TODO(Phase 28b): Wire to MLE/mesh forwarding for frame dispatch.
	_ = frame
}

// --------------------------------------------------------------------------
// Instance implements mle.Transport
// --------------------------------------------------------------------------

// SendMLE sends an MLE message to the given IPv6 destination.
func (inst *Instance) SendMLE(msg []byte, dst ip6.Address) error {
	// TODO(Phase 28b): Wire through UDP/IPv6 stack.
	_ = msg
	_ = dst
	return nil
}

// GetExtAddress returns the extended MAC address of this device.
func (inst *Instance) GetExtAddress() types.ExtAddress {
	if inst.mac != nil {
		return inst.mac.GetExtAddress()
	}
	return types.ExtAddress{}
}

// GetLinkLocalAddress returns the IPv6 link-local address.
func (inst *Instance) GetLinkLocalAddress() ip6.Address {
	// TODO(Phase 28b): Derive from MAC extended address.
	return ip6.Address{}
}

// GetMeshLocalAddress returns the IPv6 mesh-local address.
func (inst *Instance) GetMeshLocalAddress() ip6.Address {
	// TODO(Phase 28b): Derive from mesh-local prefix + RLOC16.
	return ip6.Address{}
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
// data through the Instance's UDP/IPv6 stack.
func (inst *Instance) sendCoAP(data []byte, info coap.MessageInfo) error {
	// TODO(Phase 28b): Wire through UDP socket to IPv6 stack.
	_ = data
	_ = info
	return nil
}
