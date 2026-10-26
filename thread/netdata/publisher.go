// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package netdata

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Publisher events
// ---------------------------------------------------------------------------

// PublisherEvent represents what happened to a published entry.
type PublisherEvent uint8

const (
	// PublisherEventEntryAdded indicates an entry was added to the network data.
	PublisherEventEntryAdded PublisherEvent = iota
	// PublisherEventEntryRemoved indicates an entry was removed from the network data.
	PublisherEventEntryRemoved
)

// ---------------------------------------------------------------------------
// Publisher callbacks
// ---------------------------------------------------------------------------

// PublisherPrefixCallback is called when a prefix entry is added to or removed
// from the Thread Network Data.
type PublisherPrefixCallback func(event PublisherEvent, prefix ip6.Prefix)

// PublisherDnsSrpCallback is called when a DNS/SRP service entry changes.
type PublisherDnsSrpCallback func(event PublisherEvent) //nolint:revive // Preserve the exported API spelling for existing callers.

// ---------------------------------------------------------------------------
// Publisher requester
// ---------------------------------------------------------------------------

// PublisherRequester identifies who requested a publish operation.
type PublisherRequester uint8

const (
	// PublisherRequesterUser indicates the entry was requested by the user/application.
	PublisherRequesterUser PublisherRequester = iota
	// PublisherRequesterRoutingManager indicates the entry was requested by the routing manager.
	PublisherRequesterRoutingManager
)

// publisherRequesterCount is the number of requester types.
const publisherRequesterCount = 2

// ---------------------------------------------------------------------------
// Entry state machine
// ---------------------------------------------------------------------------

// publisherEntryState is the state machine for each published entry.
//
// State transitions:
//
//	NoEntry -> ToAdd (on Publish)
//	ToAdd -> Adding (when count < desired, random delay started)
//	Adding -> Added (when delay expires)
//	Adding -> ToAdd (when count >= desired before delay expires)
//	Added -> Removing (when count > desired, random delay started)
//	Removing -> NoEntry (when delay expires)
//	Removing -> Added (when count <= desired before delay expires)
type publisherEntryState uint8

const (
	publisherStateNoEntry publisherEntryState = iota
	publisherStateToAdd
	publisherStateAdding
	publisherStateAdded
	publisherStateRemoving
)

// ---------------------------------------------------------------------------
// Desired counts for duplicate limiting
// ---------------------------------------------------------------------------

const (
	// DesiredNumOnMeshPrefix is the desired number of matching on-mesh prefix
	// entries in the network data before a new one is suppressed.
	DesiredNumOnMeshPrefix = 3

	// DesiredNumExternalRoute is the desired number of matching external route
	// entries in the network data before a new one is suppressed.
	DesiredNumExternalRoute = 3

	// DesiredNumDnsSrpAnycast is the desired number of DNS/SRP anycast service
	// entries.
	DesiredNumDnsSrpAnycast = 8 //nolint:revive // Preserve the exported API spelling for existing callers.

	// DesiredNumDnsSrpUnicast is the desired number of DNS/SRP unicast service
	// entries.
	DesiredNumDnsSrpUnicast = 2 //nolint:revive // Preserve the exported API spelling for existing callers.
)

// ---------------------------------------------------------------------------
// Delay constants (milliseconds)
// ---------------------------------------------------------------------------

const (
	// publisherAddDelayMax is the maximum random delay before adding an entry.
	publisherAddDelayMax uint32 = 500
	// publisherRemoveDelayMax is the maximum random delay before removing an
	// entry (used for preferred entries to give non-preferred ones time to add).
	publisherRemoveDelayMax uint32 = 2000
)

// ---------------------------------------------------------------------------
// Max prefix entries
// ---------------------------------------------------------------------------

// MaxPublisherPrefixEntries is the maximum number of prefix entries per requester.
const MaxPublisherPrefixEntries = 6

// totalPrefixEntries is the total number of prefix entry slots.
const totalPrefixEntries = MaxPublisherPrefixEntries * publisherRequesterCount

// ---------------------------------------------------------------------------
// DNS/SRP type constants
// ---------------------------------------------------------------------------

const (
	dnsSrpTypeAnycast            uint8 = 0
	dnsSrpTypeUnicastServiceData uint8 = 1
	dnsSrpTypeUnicastServerData  uint8 = 2
)

// ---------------------------------------------------------------------------
// PrefixEntry
// ---------------------------------------------------------------------------

// PrefixEntry represents a single published prefix entry with its state machine.
type PrefixEntry struct {
	state      publisherEntryState
	isOnMesh   bool // true for OnMeshPrefix, false for ExternalRoute
	requester  PublisherRequester
	prefix     ip6.Prefix
	preference RoutePreference
	stable     bool
	// flags stores packed BorderRouterEntry flags for on-mesh prefixes.
	flags uint16
	// timer is the countdown in milliseconds (0 = ready to act).
	timer uint32
}

// isActive reports whether the entry is in use (any state other than NoEntry).
func (e *PrefixEntry) isActive() bool {
	return e.state != publisherStateNoEntry
}

// matchesPrefix reports whether the entry matches the given prefix.
func (e *PrefixEntry) matchesPrefix(prefix ip6.Prefix) bool {
	return e.isActive() && e.prefix.IsEqual(prefix)
}

// ---------------------------------------------------------------------------
// PublisherAction
// ---------------------------------------------------------------------------

// PublisherActionType indicates whether the publisher wants to add or remove.
type PublisherActionType uint8

const (
	// PublisherActionAdd requests adding an entry to the local network data.
	PublisherActionAdd PublisherActionType = iota
	// PublisherActionRemove requests removing an entry from the local network data.
	PublisherActionRemove
)

// PublisherAction represents an action the publisher wants to take on the local
// network data.
type PublisherAction struct {
	Type     PublisherActionType
	IsOnMesh bool
	Prefix   ip6.Prefix
	// OnMesh contains the full config when adding an on-mesh prefix.
	OnMesh OnMeshPrefixConfig
	// ExtRoute contains the full config when adding an external route.
	ExtRoute ExternalRouteConfig
	// Service fields for DNS/SRP service entries.
	ServiceNum   uint8
	ServiceData  []byte
	ServerData   []byte
	ServerStable bool
}

// ---------------------------------------------------------------------------
// Publisher
// ---------------------------------------------------------------------------

// Publisher manages intelligent publishing of entries into Thread Network Data.
// It monitors the Leader's Network Data and uses randomized delays to
// add/remove entries, preventing thundering-herd effects when multiple devices
// publish similar entries.
type Publisher struct {
	prefixEntries  [totalPrefixEntries]PrefixEntry
	prefixCallback PublisherPrefixCallback
	dnsSrpCallback PublisherDnsSrpCallback

	// DNS/SRP service state
	dnsSrpState   publisherEntryState
	dnsSrpType    uint8 // dnsSrpTypeAnycast, etc.
	dnsSrpSeqNum  uint8
	dnsSrpVersion uint8
	dnsSrpAddr    ip6.Address
	dnsSrpPort    uint16
	dnsSrpTimer   uint32

	// Device identity
	rloc16   uint16
	isRouter bool

	// randFunc provides random numbers for delay calculations.
	// If nil, crypto/rand is used.
	randFunc func(limit uint32) uint32
}

// PublisherOption is a functional option for Publisher.
type PublisherOption func(*Publisher)

// WithPublisherRand sets the random function used for delay calculations.
// This is primarily useful for deterministic testing.
func WithPublisherRand(fn func(limit uint32) uint32) PublisherOption {
	return func(p *Publisher) {
		p.randFunc = fn
	}
}

// NewPublisher creates a new Publisher with the given options.
func NewPublisher(opts ...PublisherOption) *Publisher {
	p := &Publisher{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// ---------------------------------------------------------------------------
// Configuration setters
// ---------------------------------------------------------------------------

// SetPrefixCallback registers a callback for prefix add/remove events.
func (p *Publisher) SetPrefixCallback(cb PublisherPrefixCallback) {
	p.prefixCallback = cb
}

// SetDnsSrpCallback registers a callback for DNS/SRP service events.
func (p *Publisher) SetDnsSrpCallback(cb PublisherDnsSrpCallback) { //nolint:revive // Preserve the exported API spelling for existing callers.
	p.dnsSrpCallback = cb
}

// SetRloc16 updates the publisher's RLOC16. This affects "preferred" status
// calculations: a smaller RLOC16 is preferred among devices of the same type.
func (p *Publisher) SetRloc16(rloc16 uint16) {
	p.rloc16 = rloc16
}

// SetIsRouter updates whether the device is currently a router. Routers are
// preferred over end devices when deciding which entries to keep.
func (p *Publisher) SetIsRouter(isRouter bool) {
	p.isRouter = isRouter
}

// ---------------------------------------------------------------------------
// Prefix publishing
// ---------------------------------------------------------------------------

// PublishOnMeshPrefix publishes an on-mesh prefix. If the same prefix is
// already being published (by the same requester), the entry is updated.
// Returns errors.ErrNoBufs if there are no available prefix entry slots,
// or errors.ErrAlready if the prefix is already published with the same config.
func (p *Publisher) PublishOnMeshPrefix(config OnMeshPrefixConfig, requester PublisherRequester) error {
	entry := p.findPrefixEntry(config.Prefix, requester)
	if entry != nil {
		// Update existing entry.
		if entry.isOnMesh &&
			entry.preference == config.Preference &&
			entry.stable == config.Stable &&
			entry.flags == packOnMeshFlags(config) {
			return errors.ErrAlready
		}
		entry.isOnMesh = true
		entry.preference = config.Preference
		entry.stable = config.Stable
		entry.flags = packOnMeshFlags(config)
		if entry.state == publisherStateAdded {
			// Config changed while added — need to re-add.
			entry.state = publisherStateToAdd
		}
		return nil
	}

	entry = p.allocPrefixEntry(requester)
	if entry == nil {
		return errors.ErrNoBufs
	}

	entry.state = publisherStateToAdd
	entry.isOnMesh = true
	entry.requester = requester
	entry.prefix = config.Prefix
	entry.preference = config.Preference
	entry.stable = config.Stable
	entry.flags = packOnMeshFlags(config)
	entry.timer = 0
	return nil
}

// PublishExternalRoute publishes an external route. If the same prefix is
// already being published (by the same requester), the entry is updated.
// Returns errors.ErrNoBufs if there are no available prefix entry slots,
// or errors.ErrAlready if the prefix is already published with the same config.
func (p *Publisher) PublishExternalRoute(config ExternalRouteConfig, requester PublisherRequester) error {
	entry := p.findPrefixEntry(config.Prefix, requester)
	if entry != nil {
		if !entry.isOnMesh &&
			entry.preference == config.Preference &&
			entry.stable == config.Stable {
			return errors.ErrAlready
		}
		entry.isOnMesh = false
		entry.preference = config.Preference
		entry.stable = config.Stable
		entry.flags = 0
		if entry.state == publisherStateAdded {
			entry.state = publisherStateToAdd
		}
		return nil
	}

	entry = p.allocPrefixEntry(requester)
	if entry == nil {
		return errors.ErrNoBufs
	}

	entry.state = publisherStateToAdd
	entry.isOnMesh = false
	entry.requester = requester
	entry.prefix = config.Prefix
	entry.preference = config.Preference
	entry.stable = config.Stable
	entry.flags = 0
	entry.timer = 0
	return nil
}

// UnpublishPrefix unpublishes a prefix entry. It searches all requesters.
// Returns errors.ErrNotFound if no matching entry exists.
func (p *Publisher) UnpublishPrefix(prefix ip6.Prefix) error {
	found := false
	for i := range p.prefixEntries {
		e := &p.prefixEntries[i]
		if e.matchesPrefix(prefix) {
			oldState := e.state
			e.state = publisherStateNoEntry
			found = true
			if oldState == publisherStateAdded && p.prefixCallback != nil {
				p.prefixCallback(PublisherEventEntryRemoved, prefix)
			}
		}
	}
	if !found {
		return errors.ErrNotFound
	}
	return nil
}

// IsPrefixAdded checks if a prefix is currently in the Added state for any
// requester.
func (p *Publisher) IsPrefixAdded(prefix ip6.Prefix) bool {
	for i := range p.prefixEntries {
		if p.prefixEntries[i].matchesPrefix(prefix) &&
			p.prefixEntries[i].state == publisherStateAdded {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// DNS/SRP service publishing
// ---------------------------------------------------------------------------

// PublishDnsSrpServiceAnycast publishes a DNS/SRP anycast service with the
// given sequence number and version.
func (p *Publisher) PublishDnsSrpServiceAnycast(seqNum, version uint8) { //nolint:revive // Preserve the exported API spelling for existing callers.
	p.dnsSrpType = dnsSrpTypeAnycast
	p.dnsSrpSeqNum = seqNum
	p.dnsSrpVersion = version
	p.dnsSrpAddr = ip6.Address{}
	p.dnsSrpPort = 0

	if p.dnsSrpState == publisherStateNoEntry {
		p.dnsSrpState = publisherStateToAdd
		p.dnsSrpTimer = 0
	}
}

// PublishDnsSrpServiceUnicast publishes a DNS/SRP unicast service with the
// given address and port encoded in the service data.
func (p *Publisher) PublishDnsSrpServiceUnicast(addr ip6.Address, port uint16, version uint8) { //nolint:revive // Preserve the exported API spelling for existing callers.
	p.dnsSrpType = dnsSrpTypeUnicastServiceData
	p.dnsSrpAddr = addr
	p.dnsSrpPort = port
	p.dnsSrpVersion = version
	p.dnsSrpSeqNum = 0

	if p.dnsSrpState == publisherStateNoEntry {
		p.dnsSrpState = publisherStateToAdd
		p.dnsSrpTimer = 0
	}
}

// UnpublishDnsSrpService unpublishes the DNS/SRP service entry.
func (p *Publisher) UnpublishDnsSrpService() { //nolint:revive // Preserve the exported API spelling for existing callers.
	oldState := p.dnsSrpState
	p.dnsSrpState = publisherStateNoEntry
	if oldState == publisherStateAdded && p.dnsSrpCallback != nil {
		p.dnsSrpCallback(PublisherEventEntryRemoved)
	}
}

// IsDnsSrpServiceAdded checks if the DNS/SRP service is in the Added state.
func (p *Publisher) IsDnsSrpServiceAdded() bool { //nolint:revive // Preserve the exported API spelling for existing callers.
	return p.dnsSrpState == publisherStateAdded
}

// ---------------------------------------------------------------------------
// Process — the main state machine driver
// ---------------------------------------------------------------------------

// Process evaluates the publisher state machine against the current leader
// network data. It returns a list of actions (add/remove) that should be
// applied to the local network data.
//
// This should be called whenever the leader network data changes or a timer
// expires.
func (p *Publisher) Process(leaderData []byte) []PublisherAction {
	var actions []PublisherAction

	// Process prefix entries.
	for i := range p.prefixEntries {
		e := &p.prefixEntries[i]
		if !e.isActive() {
			continue
		}

		var currentCount int
		var desiredCount int

		if e.isOnMesh {
			currentCount = p.countOnMeshPrefix(leaderData, e.prefix)
			desiredCount = DesiredNumOnMeshPrefix
		} else {
			currentCount = p.countExternalRoute(leaderData, e.prefix)
			desiredCount = DesiredNumExternalRoute
		}

		action := p.updatePrefixState(e, currentCount, desiredCount)
		if action != nil {
			actions = append(actions, *action)
		}
	}

	// Process DNS/SRP service entry.
	if p.dnsSrpState != publisherStateNoEntry {
		var currentCount int
		var desiredCount int

		switch p.dnsSrpType {
		case dnsSrpTypeAnycast:
			currentCount = p.countDNSSrpAnycast(leaderData)
			desiredCount = DesiredNumDnsSrpAnycast
		default:
			currentCount = p.countDNSSrpUnicast(leaderData)
			desiredCount = DesiredNumDnsSrpUnicast
		}

		action := p.updateDNSSrpState(currentCount, desiredCount)
		if action != nil {
			actions = append(actions, *action)
		}
	}

	return actions
}

// ---------------------------------------------------------------------------
// State machine updates
// ---------------------------------------------------------------------------

// updatePrefixState applies the state machine logic for a single prefix entry
// and returns an action if one is needed, or nil if no action is required yet.
func (p *Publisher) updatePrefixState(e *PrefixEntry, currentCount, desiredCount int) *PublisherAction {
	switch e.state {
	case publisherStateToAdd:
		if currentCount < desiredCount {
			// Start the adding delay.
			e.state = publisherStateAdding
			e.timer = p.randomDelay(publisherAddDelayMax)
			if e.timer > 0 {
				return nil
			}
			// Timer is zero — fall through to Adding check.
		} else {
			return nil
		}
		fallthrough

	case publisherStateAdding:
		if currentCount >= desiredCount {
			// Enough entries exist now — go back to waiting.
			e.state = publisherStateToAdd
			return nil
		}
		if e.timer > 0 {
			// Still waiting for delay.
			return nil
		}
		// Delay expired — transition to Added and emit add action.
		e.state = publisherStateAdded
		if p.prefixCallback != nil {
			p.prefixCallback(PublisherEventEntryAdded, e.prefix)
		}
		return p.buildPrefixAddAction(e)

	case publisherStateAdded:
		if currentCount > desiredCount {
			// Too many entries — start removing (with delay for preferred).
			e.state = publisherStateRemoving
			if p.isPreferred(e) {
				e.timer = p.randomDelay(publisherRemoveDelayMax)
			} else {
				e.timer = 0
			}
		}
		return nil

	case publisherStateRemoving:
		if currentCount <= desiredCount {
			// Count dropped back — cancel removal.
			e.state = publisherStateAdded
			return nil
		}
		if e.timer > 0 {
			// Still waiting for delay.
			return nil
		}
		// Delay expired — remove.
		e.state = publisherStateNoEntry
		if p.prefixCallback != nil {
			p.prefixCallback(PublisherEventEntryRemoved, e.prefix)
		}
		return p.buildPrefixRemoveAction(e)
	}

	return nil
}

// updateDNSSrpState applies the state machine logic for the DNS/SRP service
// entry and returns an action if one is needed.
func (p *Publisher) updateDNSSrpState(currentCount, desiredCount int) *PublisherAction {
	switch p.dnsSrpState {
	case publisherStateToAdd:
		if currentCount < desiredCount {
			p.dnsSrpState = publisherStateAdding
			p.dnsSrpTimer = p.randomDelay(publisherAddDelayMax)
			if p.dnsSrpTimer > 0 {
				return nil
			}
			// Timer is zero — fall through to Adding check.
		} else {
			return nil
		}
		fallthrough

	case publisherStateAdding:
		if currentCount >= desiredCount {
			p.dnsSrpState = publisherStateToAdd
			return nil
		}
		if p.dnsSrpTimer > 0 {
			return nil
		}
		p.dnsSrpState = publisherStateAdded
		if p.dnsSrpCallback != nil {
			p.dnsSrpCallback(PublisherEventEntryAdded)
		}
		return p.buildDNSSrpAddAction()

	case publisherStateAdded:
		if currentCount > desiredCount {
			p.dnsSrpState = publisherStateRemoving
			p.dnsSrpTimer = p.randomDelay(publisherRemoveDelayMax)
		}
		return nil

	case publisherStateRemoving:
		if currentCount <= desiredCount {
			p.dnsSrpState = publisherStateAdded
			return nil
		}
		if p.dnsSrpTimer > 0 {
			return nil
		}
		p.dnsSrpState = publisherStateNoEntry
		if p.dnsSrpCallback != nil {
			p.dnsSrpCallback(PublisherEventEntryRemoved)
		}
		return p.buildDNSSrpRemoveAction()
	}

	return nil
}

// ---------------------------------------------------------------------------
// Preferred status
// ---------------------------------------------------------------------------

// isPreferred reports whether this publisher is "preferred" for keeping the
// given entry. A router is preferred over an end device; among the same device
// type, a smaller RLOC16 wins. Preferred entries use a longer random delay
// before removing, giving non-preferred entries a chance to remove first.
func (p *Publisher) isPreferred(e *PrefixEntry) bool {
	// A router is always considered preferred in removal decisions.
	// Among routers (or among end devices), smaller RLOC16 wins.
	// Since we don't know the other publishers' RLOC16s, we use a
	// heuristic: routers get the longer delay.
	return p.isRouter
}

// ---------------------------------------------------------------------------
// Action builders
// ---------------------------------------------------------------------------

func (p *Publisher) buildPrefixAddAction(e *PrefixEntry) *PublisherAction {
	a := &PublisherAction{
		Type:     PublisherActionAdd,
		IsOnMesh: e.isOnMesh,
		Prefix:   e.prefix,
	}
	if e.isOnMesh {
		a.OnMesh = OnMeshPrefixConfig{
			Prefix:       e.prefix,
			RLOC16:       p.rloc16,
			Preference:   e.preference,
			Stable:       e.stable,
			Preferred:    (e.flags & flagPreferred) != 0,
			SLAAC:        (e.flags & flagSLAAC) != 0,
			DHCP:         (e.flags & flagDHCP) != 0,
			Configure:    (e.flags & flagConfigure) != 0,
			DefaultRoute: (e.flags & flagDefaultRoute) != 0,
			OnMesh:       (e.flags & flagOnMesh) != 0,
			NdDNS:        (e.flags & flagNdDNS) != 0,
			Dp:           (e.flags & flagDp) != 0,
		}
	} else {
		a.ExtRoute = ExternalRouteConfig{
			Prefix:     e.prefix,
			RLOC16:     p.rloc16,
			Preference: e.preference,
			Stable:     e.stable,
		}
	}
	return a
}

func (p *Publisher) buildPrefixRemoveAction(e *PrefixEntry) *PublisherAction {
	return &PublisherAction{
		Type:     PublisherActionRemove,
		IsOnMesh: e.isOnMesh,
		Prefix:   e.prefix,
	}
}

func (p *Publisher) buildDNSSrpAddAction() *PublisherAction {
	a := &PublisherAction{
		Type:         PublisherActionAdd,
		ServiceNum:   p.dnsSrpVersion,
		ServerStable: true,
	}

	switch p.dnsSrpType {
	case dnsSrpTypeAnycast:
		a.ServiceData = []byte{p.dnsSrpSeqNum}
		a.ServerData = nil
	case dnsSrpTypeUnicastServiceData:
		// Service data contains address (16 bytes) + port (2 bytes).
		sd := make([]byte, 18)
		copy(sd[0:16], p.dnsSrpAddr[:])
		sd[16] = byte(p.dnsSrpPort >> 8)
		sd[17] = byte(p.dnsSrpPort)
		a.ServiceData = sd
		a.ServerData = nil
	case dnsSrpTypeUnicastServerData:
		a.ServiceData = nil
		sd := make([]byte, 18)
		copy(sd[0:16], p.dnsSrpAddr[:])
		sd[16] = byte(p.dnsSrpPort >> 8)
		sd[17] = byte(p.dnsSrpPort)
		a.ServerData = sd
	}

	return a
}

func (p *Publisher) buildDNSSrpRemoveAction() *PublisherAction {
	a := &PublisherAction{
		Type:       PublisherActionRemove,
		ServiceNum: p.dnsSrpVersion,
	}

	switch p.dnsSrpType {
	case dnsSrpTypeAnycast:
		a.ServiceData = []byte{p.dnsSrpSeqNum}
	case dnsSrpTypeUnicastServiceData:
		sd := make([]byte, 18)
		copy(sd[0:16], p.dnsSrpAddr[:])
		sd[16] = byte(p.dnsSrpPort >> 8)
		sd[17] = byte(p.dnsSrpPort)
		a.ServiceData = sd
	case dnsSrpTypeUnicastServerData:
		// Server data removal uses RLOC-based matching; no special data needed.
	}

	return a
}

// ---------------------------------------------------------------------------
// Counting entries in leader data
// ---------------------------------------------------------------------------

// countOnMeshPrefix counts the number of on-mesh prefix entries in the leader
// network data that match the given prefix.
func (p *Publisher) countOnMeshPrefix(leaderData []byte, prefix ip6.Prefix) int {
	count := 0
	it := NewIterator(leaderData)
	for {
		cfg, err := it.NextOnMeshPrefix()
		if err != nil {
			break
		}
		if cfg.Prefix.IsEqual(prefix) {
			count++
		}
	}
	return count
}

// countExternalRoute counts the number of external route entries in the leader
// network data that match the given prefix.
func (p *Publisher) countExternalRoute(leaderData []byte, prefix ip6.Prefix) int {
	count := 0
	it := NewIterator(leaderData)
	for {
		cfg, err := it.NextExternalRoute()
		if err != nil {
			break
		}
		if cfg.Prefix.IsEqual(prefix) {
			count++
		}
	}
	return count
}

// countDNSSrpAnycast counts DNS/SRP anycast service entries in the leader data.
func (p *Publisher) countDNSSrpAnycast(leaderData []byte) int {
	count := 0
	tlvs := ParseTLVs(leaderData)
	for _, tlv := range tlvs {
		if tlv.Type != TLVTypeService {
			continue
		}
		svc, err := ParseServiceValue(tlv.Value, tlv.Stable)
		if err != nil {
			continue
		}
		if svc.EnterpriseNumber != ThreadEnterpriseNumber {
			continue
		}
		// DNS/SRP anycast service data is 1 byte (sequence number).
		if len(svc.ServiceData) == 1 {
			count++
		}
	}
	return count
}

// countDNSSrpUnicast counts DNS/SRP unicast service entries in the leader data.
func (p *Publisher) countDNSSrpUnicast(leaderData []byte) int {
	count := 0
	tlvs := ParseTLVs(leaderData)
	for _, tlv := range tlvs {
		if tlv.Type != TLVTypeService {
			continue
		}
		svc, err := ParseServiceValue(tlv.Value, tlv.Stable)
		if err != nil {
			continue
		}
		if svc.EnterpriseNumber != ThreadEnterpriseNumber {
			continue
		}
		// DNS/SRP unicast: service data is 18 bytes (addr+port) or server data
		// contains addr+port.
		if len(svc.ServiceData) == 18 {
			count++
		} else if len(svc.ServiceData) == 0 {
			// Check for unicast via server data.
			subTLVs := ParseTLVs(svc.SubTLVsData)
			for _, sub := range subTLVs {
				if sub.Type == TLVTypeServer {
					srv, sErr := ParseServerValue(sub.Value)
					if sErr == nil && len(srv.ServerData) == 18 {
						count++
					}
				}
			}
		}
	}
	return count
}

// ---------------------------------------------------------------------------
// Prefix entry management
// ---------------------------------------------------------------------------

// findPrefixEntry finds an existing prefix entry for the given prefix and
// requester. Returns nil if not found.
func (p *Publisher) findPrefixEntry(prefix ip6.Prefix, requester PublisherRequester) *PrefixEntry {
	start, end := p.requesterSlots(requester)
	for i := start; i < end; i++ {
		if p.prefixEntries[i].matchesPrefix(prefix) {
			return &p.prefixEntries[i]
		}
	}
	return nil
}

// allocPrefixEntry allocates an unused prefix entry slot for the given
// requester. Returns nil if no slots are available.
func (p *Publisher) allocPrefixEntry(requester PublisherRequester) *PrefixEntry {
	start, end := p.requesterSlots(requester)
	for i := start; i < end; i++ {
		if !p.prefixEntries[i].isActive() {
			return &p.prefixEntries[i]
		}
	}
	return nil
}

// requesterSlots returns the [start, end) index range for the given requester.
func (p *Publisher) requesterSlots(requester PublisherRequester) (startIndex, endIndex int) {
	start := int(requester) * MaxPublisherPrefixEntries
	return start, start + MaxPublisherPrefixEntries
}

// ---------------------------------------------------------------------------
// On-mesh prefix flag packing
// ---------------------------------------------------------------------------

const (
	flagPreferred    uint16 = 1 << 0
	flagSLAAC        uint16 = 1 << 1
	flagDHCP         uint16 = 1 << 2
	flagConfigure    uint16 = 1 << 3
	flagDefaultRoute uint16 = 1 << 4
	flagOnMesh       uint16 = 1 << 5
	flagNdDNS        uint16 = 1 << 6
	flagDp           uint16 = 1 << 7
)

// packOnMeshFlags packs an OnMeshPrefixConfig's boolean flags into a uint16.
func packOnMeshFlags(c OnMeshPrefixConfig) uint16 {
	var f uint16
	if c.Preferred {
		f |= flagPreferred
	}
	if c.SLAAC {
		f |= flagSLAAC
	}
	if c.DHCP {
		f |= flagDHCP
	}
	if c.Configure {
		f |= flagConfigure
	}
	if c.DefaultRoute {
		f |= flagDefaultRoute
	}
	if c.OnMesh {
		f |= flagOnMesh
	}
	if c.NdDNS {
		f |= flagNdDNS
	}
	if c.Dp {
		f |= flagDp
	}
	return f
}

// ---------------------------------------------------------------------------
// Random delay
// ---------------------------------------------------------------------------

// randomDelay returns a random delay in milliseconds in the range [0, max).
func (p *Publisher) randomDelay(limit uint32) uint32 {
	if limit == 0 {
		return 0
	}
	if p.randFunc != nil {
		return p.randFunc(limit)
	}
	return cryptoRandUint32(limit)
}

// cryptoRandUint32 returns a random uint32 in [0, limit) using crypto/rand.
func cryptoRandUint32(limit uint32) uint32 {
	var buf [4]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		// Fallback to 0 if crypto/rand fails (should not happen in practice).
		return 0
	}
	v := binary.LittleEndian.Uint32(buf[:])
	return v % limit
}

// ---------------------------------------------------------------------------
// Timer helpers (for external tick-based usage)
// ---------------------------------------------------------------------------

// AdvanceTime advances all active timers by the given number of milliseconds.
// This should be called periodically (e.g., every 100ms) to drive the state
// machine timers forward.
func (p *Publisher) AdvanceTime(deltaMs uint32) {
	for i := range p.prefixEntries {
		e := &p.prefixEntries[i]
		if e.state == publisherStateAdding || e.state == publisherStateRemoving {
			if e.timer <= deltaMs {
				e.timer = 0
			} else {
				e.timer -= deltaMs
			}
		}
	}

	if p.dnsSrpState == publisherStateAdding || p.dnsSrpState == publisherStateRemoving {
		if p.dnsSrpTimer <= deltaMs {
			p.dnsSrpTimer = 0
		} else {
			p.dnsSrpTimer -= deltaMs
		}
	}
}

// NextTimerMs returns the time in milliseconds until the next timer fires,
// or 0 if no timers are active. This can be used to schedule the next call
// to AdvanceTime + Process.
func (p *Publisher) NextTimerMs() uint32 {
	var minTimer uint32
	found := false

	for i := range p.prefixEntries {
		e := &p.prefixEntries[i]
		if e.state == publisherStateAdding || e.state == publisherStateRemoving {
			if !found || e.timer < minTimer {
				minTimer = e.timer
				found = true
			}
		}
	}

	if p.dnsSrpState == publisherStateAdding || p.dnsSrpState == publisherStateRemoving {
		if !found || p.dnsSrpTimer < minTimer {
			minTimer = p.dnsSrpTimer
		}
	}

	return minTimer
}

// HasPendingTimers reports whether any timers are currently running.
func (p *Publisher) HasPendingTimers() bool {
	for i := range p.prefixEntries {
		e := &p.prefixEntries[i]
		if e.state == publisherStateAdding || e.state == publisherStateRemoving {
			return true
		}
	}
	return p.dnsSrpState == publisherStateAdding || p.dnsSrpState == publisherStateRemoving
}
