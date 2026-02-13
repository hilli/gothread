// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package instance provides the central Instance struct and event loop for
// gothread. Instance owns all Thread stack modules and drives them via a
// single-goroutine cooperative event loop.
//
// This is a Go port of the Instance, Tasklet, Timer, and Notifier
// subsystems from OpenThread's src/core/instance/ and
// src/core/common/ directories.
package instance

import (
	"sync"
	"time"

	"github.com/hilli/gothread/common/message"
	cnotifier "github.com/hilli/gothread/common/notifier"
	csettings "github.com/hilli/gothread/common/settings"
	"github.com/hilli/gothread/mac"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/icmp6"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/addrresolver"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/indirect"
	"github.com/hilli/gothread/thread/link"
	"github.com/hilli/gothread/thread/diag"
	"github.com/hilli/gothread/thread/linkmetrics"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
	"github.com/hilli/gothread/thread/routing"
	"github.com/hilli/gothread/thread/supervision"
	"github.com/hilli/gothread/thread/tmf"
)

// --------------------------------------------------------------------------
// Notifier — event flag dispatch
// --------------------------------------------------------------------------

// Event is a bitmask of state-change events that modules can signal.
type Event uint32

const (
	// EventIPv6AddressAdded signals that an IPv6 address was added.
	EventIPv6AddressAdded Event = 1 << 0
	// EventIPv6AddressRemoved signals that an IPv6 address was removed.
	EventIPv6AddressRemoved Event = 1 << 1
	// EventThreadRoleChanged signals that the Thread device role changed.
	EventThreadRoleChanged Event = 1 << 2
	// EventThreadLinkLocalAddrChanged signals a link-local address change.
	EventThreadLinkLocalAddrChanged Event = 1 << 3
	// EventThreadMeshLocalAddrChanged signals a mesh-local address change.
	EventThreadMeshLocalAddrChanged Event = 1 << 4
	// EventThreadRlocAdded signals that an RLOC address was added.
	EventThreadRlocAdded Event = 1 << 5
	// EventThreadRlocRemoved signals that an RLOC address was removed.
	EventThreadRlocRemoved Event = 1 << 6
	// EventThreadNetDataChanged signals a network data change.
	EventThreadNetDataChanged Event = 1 << 7
	// EventThreadChildAdded signals that a child was added.
	EventThreadChildAdded Event = 1 << 8
	// EventThreadChildRemoved signals that a child was removed.
	EventThreadChildRemoved Event = 1 << 9
	// EventChannelChanged signals that the radio channel changed.
	EventChannelChanged Event = 1 << 10
	// EventSecurityPolicyChanged signals a security policy change.
	EventSecurityPolicyChanged Event = 1 << 11
	// EventActiveDatasetChanged signals an active dataset change.
	EventActiveDatasetChanged Event = 1 << 12
	// EventPendingDatasetChanged signals a pending dataset change.
	EventPendingDatasetChanged Event = 1 << 13
)

// NotifierCallback is a function invoked when notifier events are dispatched.
type NotifierCallback func(events Event)

// notifier tracks pending events and dispatches them to registered callbacks.
type notifier struct {
	pending   Event
	callbacks []NotifierCallback
}

// signal sets the given events as pending.
func (n *notifier) signal(events Event) {
	n.pending |= events
}

// process dispatches all pending events to registered callbacks, then
// clears the pending flags. Returns true if any events were dispatched.
func (n *notifier) process() bool {
	if n.pending == 0 {
		return false
	}
	events := n.pending
	n.pending = 0
	for _, cb := range n.callbacks {
		cb(events)
	}
	return true
}

// register adds a callback for notifier events.
func (n *notifier) register(cb NotifierCallback) {
	n.callbacks = append(n.callbacks, cb)
}

// --------------------------------------------------------------------------
// Timer — sorted timer list
// --------------------------------------------------------------------------

// timer represents a scheduled callback that fires after a delay.
type timer struct {
	fireAt    time.Time
	fn        func()
	cancelled bool
}

// timerScheduler maintains a sorted list of pending timers.
type timerScheduler struct {
	timers []*timer
}

// schedule adds a timer that fires after delay, calling fn.
func (ts *timerScheduler) schedule(delay time.Duration, fn func()) {
	ts.scheduleWithCancel(delay, fn)
}

// scheduleWithCancel adds a timer that fires after delay, calling fn.
// It returns a cancel function that, when called, prevents the timer
// from firing. Calling cancel more than once is safe (no-op).
func (ts *timerScheduler) scheduleWithCancel(delay time.Duration, fn func()) func() {
	fireAt := time.Now().Add(delay)
	t := &timer{fireAt: fireAt, fn: fn}
	// Insert in sorted order (earliest first).
	idx := 0
	for idx < len(ts.timers) && ts.timers[idx].fireAt.Before(fireAt) {
		idx++
	}
	ts.timers = append(ts.timers, nil)
	copy(ts.timers[idx+1:], ts.timers[idx:])
	ts.timers[idx] = t
	return func() { t.cancelled = true }
}

// processExpired fires all timers whose deadline has passed, skipping
// any that have been cancelled. Returns the number of timers fired.
func (ts *timerScheduler) processExpired() int {
	now := time.Now()
	fired := 0
	for len(ts.timers) > 0 && !ts.timers[0].fireAt.After(now) {
		t := ts.timers[0]
		ts.timers = ts.timers[1:]
		if t.cancelled {
			continue
		}
		t.fn()
		fired++
	}
	return fired
}

// nextDeadline returns the time until the next timer fires, or 0 if there
// are no pending timers. The bool return is false if no timers are pending.
func (ts *timerScheduler) nextDeadline() (time.Duration, bool) {
	if len(ts.timers) == 0 {
		return 0, false
	}
	d := time.Until(ts.timers[0].fireAt)
	if d < 0 {
		d = 0
	}
	return d, true
}

// count returns the number of pending timers.
func (ts *timerScheduler) count() int {
	return len(ts.timers)
}

// --------------------------------------------------------------------------
// Config — dependency injection
// --------------------------------------------------------------------------

// Config holds the platform dependencies injected into an Instance.
type Config struct {
	// Alarm provides millisecond-precision timing.
	Alarm platform.Alarm
	// Entropy provides cryptographic random bytes.
	Entropy platform.Entropy
	// Settings provides persistent non-volatile storage.
	Settings platform.Settings
	// Logger provides platform logging.
	Logger platform.Logger
	// Radio provides IEEE 802.15.4 radio access.
	Radio radio.Radio

	// ParentPriority is the parent priority value (0-3) placed in the
	// top 2 bits of the Connectivity TLV Flags byte.
	ParentPriority uint8
	// SEDBufferSize is the SED buffer size advertised in the Connectivity TLV.
	SEDBufferSize uint16
	// SEDDatagramCount is the SED datagram count advertised in the Connectivity TLV.
	SEDDatagramCount uint8
}

// --------------------------------------------------------------------------
// Instance — the central Thread stack object
// --------------------------------------------------------------------------

// Instance is the central object that owns all Thread stack modules and
// drives them via a single-goroutine cooperative event loop.
//
// The event loop processes tasks (posted functions), timers, and notifier
// events. All stack operations run on the event loop goroutine, avoiding
// the need for locks within individual modules.
type Instance struct {
	// Platform interfaces
	alarm        platform.Alarm
	entropy      platform.Entropy
	platSettings platform.Settings
	logger       platform.Logger
	platRadio    radio.Radio

	// Event loop
	taskCh chan func()
	stopCh chan struct{}
	doneCh chan struct{}

	// Timer scheduler (accessed only from event loop goroutine)
	timers *timerScheduler

	// Notifier (accessed only from event loop goroutine)
	notifier *notifier

	// running tracks whether the event loop is active.
	running   bool
	runningMu sync.Mutex

	// ifConfigUp tracks whether the IP6/MAC interface is enabled
	// (equivalent to otIp6SetEnabled).
	ifConfigUp bool

	// threadEnabled tracks whether the Thread protocol is enabled
	// (equivalent to otThreadSetEnabled).
	threadEnabled bool

	// ---------------------------------------------------------------
	// Tier 1 — Radio / MAC / Key core
	// ---------------------------------------------------------------

	// messagePool is the shared message buffer pool.
	messagePool *message.Pool

	// stackSettings wraps the platform.Settings driver for use by
	// protocol modules.
	stackSettings *csettings.Settings

	// stackNotifier is the protocol-level event bus (distinct from
	// the instance-level notifier above which drives the event loop).
	stackNotifier *cnotifier.Notifier

	// keyManager owns MLE/MAC key material, frame counters, and
	// key rotation.
	keyManager *key.Manager

	// activeDataset manages the Active Operational Dataset.
	activeDataset *meshcop.ActiveDatasetManager

	// pendingDataset manages the Pending Operational Dataset.
	pendingDataset *meshcop.PendingDatasetManager

	// subMac implements CSMA-CA, retransmissions, and energy scanning.
	subMac *submac.SubMac

	// mac implements the IEEE 802.15.4 MAC layer.
	mac *mac.Mac

	// ---------------------------------------------------------------
	// Tier 2 — Routing / MLE / Network
	// ---------------------------------------------------------------

	// routerTable manages the set of known routers.
	routerTable *routing.RouterTable

	// childTable manages the set of known children.
	childTable *routing.ChildTable

	// neighborTable provides unified neighbor lookup across router
	// and child tables.
	neighborTable *routing.NeighborTable

	// mleService is the top-level MLE protocol service.
	mleService *mle.Service

	// netif is the IPv6 network interface.
	netif *ip6.Netif

	// udpManager manages UDP sockets.
	udpManager *udp.UDP

	// icmpManager manages ICMPv6 handlers.
	icmpManager *icmp6.Icmp

	// slaacManager generates and manages SLAAC addresses from
	// on-mesh prefixes advertised in Thread Network Data.
	slaacManager *slaac.Manager

	// ---------------------------------------------------------------
	// Tier 3 — Application layer (CoAP, TMF, Mesh forwarding)
	// ---------------------------------------------------------------

	// coapEngine handles CoAP message exchange.
	coapEngine *coap.Engine

	// tmfAgent is the TMF CoAP agent for Thread management messages.
	tmfAgent *tmf.Agent

	// tmfLeaderService handles Address Solicit/Release requests when
	// this device is the Leader.
	tmfLeaderService *tmf.LeaderService

	// tmfServerDataService handles Server Data Register/Unregister
	// requests from border routers and service servers.
	tmfServerDataService *tmf.ServerDataService

	// tmfCommissionerDataService handles Commissioner Petition/KeepAlive
	// and dataset set requests.
	tmfCommissionerDataService *tmf.CommissionerDataService

	// netdataLeader manages the Thread Network Data.
	netdataLeader *netdata.Leader

	// netdataLocal manages this device's local Network Data
	// contributions (on-mesh prefixes, external routes, services).
	netdataLocal *netdata.Local

	// netdataNotifier synchronises the local Network Data with the
	// leader, triggering registration when local data changes.
	netdataNotifier *netdata.Notifier

	// netdataPublisher automatically publishes and unpublishes
	// prefixes and services based on leader Network Data.
	netdataPublisher *netdata.Publisher

	// forwarder handles mesh frame forwarding.
	forwarder *mesh.Forwarder

	// addrResolver resolves EID-to-RLOC16 mappings for IPv6 destination
	// addresses using Address Query/Notification TMF messages.
	addrResolver *addrresolver.Resolver

	// linkMetricsSubject handles incoming Link Metrics Management
	// and Enhanced-ACK Based Probing requests from peers.
	linkMetricsSubject *linkmetrics.Subject

	// linkMetricsInitiator sends Link Metrics queries and processes
	// the corresponding reports from peers.
	linkMetricsInitiator *linkmetrics.Initiator

	// diagClient manages outgoing network diagnostic queries.
	diagClient *diag.Client

	// diagServer handles incoming network diagnostic requests.
	diagServer *diag.Server

	// ---------------------------------------------------------------
	// Configuration
	// ---------------------------------------------------------------

	// networkName is the Thread network name.
	networkName string

	// extendedPanID is the 8-byte extended PAN ID.
	extendedPanID [8]byte

	// steeringData is the Bloom-filter steering data for joiners.
	steeringData []byte

	// nativeCommissioner indicates whether native commissioning is enabled.
	nativeCommissioner bool

	// meshLocalPrefix is the 64-bit mesh-local prefix (e.g. fd-prefixed ULA).
	meshLocalPrefix [8]byte

	// rloc16 is the 16-bit Routing Locator of this device.
	rloc16 uint16

	// parentPriority is the parent priority (0-3) for Connectivity TLV Flags.
	parentPriority uint8

	// sedBufferSize is the SED buffer size for Connectivity TLV.
	sedBufferSize uint16

	// sedDatagramCount is the SED datagram count for Connectivity TLV.
	sedDatagramCount uint8

	// pendingTxMsg holds the TxMessage currently being transmitted by the
	// MAC layer, so HandleSentFrame can report completion back to the
	// mesh forwarder.
	pendingTxMsg *mesh.TxMessage

	// macSeqNum is the MAC-layer sequence number counter, incremented
	// with each transmitted frame.
	macSeqNum uint8

	// subMacTimerCancel cancels the currently pending SubMac timer
	// (if any). Used to implement SubMac.StopTimer.
	subMacTimerCancel func()

	// macTimerCancel cancels the currently pending Mac timer
	// (if any). Used to implement Mac.StopTimer.
	macTimerCancel func()

	// dataPollSender manages periodic 802.15.4 data poll requests
	// when this device is operating as a sleepy end device (SED).
	dataPollSender *supervision.DataPollSender

	// supervisor sends periodic supervision messages to sleepy children
	// when this device operates as a parent (router/leader).
	supervisor *supervision.Supervisor

	// supervisionListener monitors messages from the parent when this
	// device operates as a child (SED/MED).
	supervisionListener *supervision.SupervisionListener

	// childProvider caches child conversions for supervision write-back.
	childProvider *childProviderAdapter

	// dataPollHandler manages indirect frame transmissions to sleepy
	// children when this device operates as a parent/router (FTD).
	dataPollHandler *supervision.DataPollHandler

	// sourceMatchController manages the radio source address match table
	// for indirect frame transmission to sleepy children.
	sourceMatchController *indirect.SourceMatchController

	// indirectSender manages buffering and transmission of indirect
	// frames to sleepy end devices.
	indirectSender *indirect.Sender

	// keyRotationTickCounter counts 1-second ticks toward the hourly
	// key rotation check. When it reaches 3600 the key manager's
	// HandleKeyRotationTick is called and the counter resets.
	keyRotationTickCounter uint32

	// droppedNonIPHC counts received frames that were not 6LoWPAN IPHC
	// compressed and were silently dropped during RX processing.
	droppedNonIPHC uint64
}

// New creates a new Instance with the given platform configuration.
// All Thread stack modules are created and wired together during
// construction. Call Start() to begin the event loop.
func New(config Config) *Instance {
	inst := &Instance{
		alarm:            config.Alarm,
		entropy:          config.Entropy,
		platSettings:     config.Settings,
		logger:           config.Logger,
		platRadio:        config.Radio,
		taskCh:           make(chan func(), 256),
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
		timers:           &timerScheduler{},
		notifier:         &notifier{},
		parentPriority:   config.ParentPriority,
		sedBufferSize:    config.SEDBufferSize,
		sedDatagramCount: config.SEDDatagramCount,
	}

	inst.wireModules()
	return inst
}

// wireModules creates and connects all Thread stack modules.
// This is called from New() and runs in the constructor goroutine.
func (inst *Instance) wireModules() {
	// ---------------------------------------------------------------
	// Tier 1 — Radio / MAC / Key core
	// ---------------------------------------------------------------

	inst.messagePool = message.NewPool(256)
	inst.stackNotifier = cnotifier.New()
	inst.keyManager = key.NewManager()

	inst.activeDataset = meshcop.NewActiveDatasetManager(
		meshcop.NewMemoryDatasetStore(),
		func(dt meshcop.DatasetType) { inst.stackNotifier.Signal(cnotifier.Events(EventActiveDatasetChanged)) },
	)
	inst.pendingDataset = meshcop.NewPendingDatasetManager(
		meshcop.NewMemoryDatasetStore(),
		func(dt meshcop.DatasetType) { inst.stackNotifier.Signal(cnotifier.Events(EventPendingDatasetChanged)) },
	)

	// Restore datasets from persistent storage. With MemoryDatasetStore
	// this is a no-op, but a real persistent store needs it to hydrate
	// the manager's localSaved/timestamp state on restart.
	_ = inst.activeDataset.Restore()
	_ = inst.pendingDataset.Restore()

	if inst.platSettings != nil {
		inst.stackSettings = csettings.New(&settingsDriverAdapter{ps: inst.platSettings})
	}

	// SubMac wraps the radio with CSMA-CA and retransmission logic.
	// Mac serves as the SubMac's Callbacks (it implements the interface).
	// We use a callbackBridge to break the circular dependency:
	// SubMac needs Callbacks at construction, Mac needs SubMac at
	// construction. The bridge starts empty and gets populated after
	// both are created.
	bridge := &submacCallbackBridge{}

	inst.subMac = submac.New(submac.Config{
		Radio:     inst.platRadio,
		Callbacks: bridge,
		ScheduleTimer: func(delay time.Duration, fn func()) {
			if inst.subMacTimerCancel != nil {
				inst.subMacTimerCancel()
			}
			inst.subMacTimerCancel = inst.timers.scheduleWithCancel(delay, fn)
		},
		StopTimer: func() {
			if inst.subMacTimerCancel != nil {
				inst.subMacTimerCancel()
				inst.subMacTimerCancel = nil
			}
		},
	})

	inst.mac = mac.New(mac.Config{
		SubMac:    inst.subMac,
		Callbacks: inst, // Instance implements mac.Callbacks
		ScheduleTimer: func(delay time.Duration, fn func()) {
			if inst.macTimerCancel != nil {
				inst.macTimerCancel()
			}
			inst.macTimerCancel = inst.timers.scheduleWithCancel(delay, fn)
		},
		StopTimer: func() {
			if inst.macTimerCancel != nil {
				inst.macTimerCancel()
				inst.macTimerCancel = nil
			}
		},
		PostOperation: inst.postTask,
	})

	// Now wire Mac as the SubMac's callback receiver.
	bridge.target = inst.mac

	// Wire frame counter callback: when the MAC consumes a frame
	// counter, forward it to the key manager so it can persist
	// the high-water mark.
	inst.mac.SetOnFrameCounterUsed(func(counter uint32) {
		inst.keyManager.MacFrameCounterUsed(counter)
	})

	// ---------------------------------------------------------------
	// Tier 2 — Routing / MLE / Network
	// ---------------------------------------------------------------

	inst.routerTable = routing.NewRouterTable()
	inst.childTable = routing.NewChildTable()
	inst.neighborTable = routing.NewNeighborTable(inst.routerTable, inst.childTable)

	inst.netif = ip6.NewNetif()
	inst.udpManager = udp.New()
	inst.icmpManager = icmp6.New()

	inst.mleService = mle.NewService(mle.ServiceConfig{
		Transport:    inst, // Instance implements mle.Transport
		KeyProvider:  inst, // Instance delegates to keyManager
		RouterLookup: inst, // Instance delegates to routerTable
		RouteData:    inst, // Instance delegates to routerTable
		RouterOps:    inst, // Instance delegates to routerTable
		Connectivity: inst, // Instance provides connectivity data
		NetworkInfo:  inst, // Instance provides network identity
		Datasets:     inst, // Instance provides dataset access
		NetworkData:  inst, // Instance delegates to netdataLeader
		MacInfo:      inst, // Instance delegates to mac layer
		NeighborLookup: func(addr types.ExtAddress) *mle.Neighbor {
			n := inst.neighborTable.FindNeighborByExtAddress(addr, routing.FilterValid)
			if n == nil {
				return nil
			}
			return neighborToMLE(n)
		},
	})

	// Wire AnnounceHandler's OnSignal callback so that when a newer
	// Announce is received, the instance switches channel/PAN and
	// initiates a fresh attach.
	inst.mleService.AnnounceHandler.OnSignal = inst.processAnnounce

	// Wire role-change callback so that Instance reacts to every MLE
	// role transition. The callback is invoked from within Mle.setRole()
	// with m.mu held, so it MUST NOT call any Mle method that acquires
	// mu (IsChild, GetParent, etc.). Instead we use the oldRole/newRole
	// parameters and defer heavier sync work via signal+periodic tick.
	inst.mleService.Mle().SetRoleChangeCallback(func(oldRole, newRole mle.DeviceRole) {
		inst.notifier.signal(EventThreadRoleChanged)
		// Update publisher's router flag — safe because this doesn't
		// call any Mle method that acquires mu.
		if inst.netdataPublisher != nil {
			isRouter := newRole == mle.RoleRouter || newRole == mle.RoleLeader
			inst.netdataPublisher.SetIsRouter(isRouter)
		}
	})

	// DataPollSender manages periodic data poll requests when this device
	// operates as a sleepy end device (SED). The macPollTransmitter
	// adapter bridges to Mac.RequestDataPollTransmission().
	inst.dataPollSender = supervision.NewDataPollSender(
		supervision.WithPollTransmitter(&macPollTransmitter{inst: inst}),
	)

	// Child Supervision — parent side (Supervisor).
	// Sends periodic supervision frames to sleepy children when this
	// device operates as a router or leader.
	inst.childProvider = &childProviderAdapter{childTable: inst.childTable}
	inst.supervisor = supervision.NewSupervisor(
		supervision.WithChildProvider(inst.childProvider),
		supervision.WithMessageSender(&supervisionMessageSender{inst: inst}),
	)

	// Child Supervision — child side (SupervisionListener).
	// Monitors frames from the parent and triggers re-attach on loss.
	inst.supervisionListener = supervision.NewSupervisionListener(
		supervision.WithTimer(newRealTimer()),
		supervision.WithParentLossHandler(&parentLossHandler{inst: inst}),
	)

	// Data Poll Handler — parent side.
	// Manages indirect frame transmissions to sleepy children upon
	// receiving data poll (MAC Data Request) frames.

	// Wire real indirect sender when a radio is available.
	var srcMatch *indirect.SourceMatchController
	if inst.platRadio != nil {
		srcMatch = indirect.NewSourceMatchController(&radioSourceMatchAdapter{radio: inst.platRadio})
	}
	inst.sourceMatchController = srcMatch

	var indSender supervision.IndirectSender
	if srcMatch != nil {
		frameSender := &indirectFrameSender{inst: inst}
		inst.indirectSender = indirect.NewSender(frameSender, srcMatch)
		indSender = &realIndirectSenderAdapter{sender: inst.indirectSender}
	} else {
		indSender = &indirectSenderAdapter{} // fallback stub for no-radio
	}

	inst.dataPollHandler = supervision.NewDataPollHandler(
		supervision.WithHandlerChildProvider(inst.childProvider),
		supervision.WithIndirectSender(indSender),
	)

	// ---------------------------------------------------------------
	// Tier 3 — Application layer
	// ---------------------------------------------------------------

	inst.coapEngine = coap.NewEngine(inst.sendCoAP)
	inst.tmfAgent = tmf.NewAgent(inst.coapEngine)
	inst.netdataLeader = netdata.NewLeader(&routerCheckerAdapter{rt: inst.routerTable})
	inst.netdataLeader.SetOnChanged(func() {
		inst.notifier.signal(EventThreadNetDataChanged)
		// Sync network-data version numbers into MLE LeaderData so that
		// advertisements and responses carry current values.  Only the
		// leader originates these versions; other roles receive them via
		// incoming advertisements.
		if inst.mleService != nil && inst.mleService.Mle().IsLeader() {
			m := inst.mleService.Mle()
			ld := m.GetLeaderData()
			ld.DataVersion = inst.netdataLeader.Version()
			ld.StableDataVersion = inst.netdataLeader.StableVersion()
			m.SetLeaderData(ld)
		}
		// Update SLAAC addresses based on the new on-mesh prefixes.
		inst.updateSlaacAddresses()
	})
	inst.forwarder = mesh.NewForwarder()

	// TMF services — register handlers with the TMF agent for
	// Address Solicit/Release (Leader), Server Data (network data
	// registration), and Commissioner Data (commissioning).
	routerTableAdapter := tmf.NewRouterTableAdapter(inst.routerTable)
	inst.tmfLeaderService = tmf.NewLeaderService(inst.tmfAgent, routerTableAdapter, 16)
	inst.tmfServerDataService = tmf.NewServerDataService(inst.tmfAgent, inst.netdataLeader)
	inst.tmfCommissionerDataService = tmf.NewCommissionerDataService(inst.tmfAgent, inst.netdataLeader)

	// Address Resolver — resolves EID-to-RLOC16 mappings via
	// TMF Address Query / Notification messages.
	inst.addrResolver = addrresolver.NewResolver()
	inst.addrResolver.SetQueryCallback(func(target ip6.Address) {
		// TODO: Send TMF Address Query (a/aq) via CoAP to realm-local all-routers
	})
	inst.addrResolver.SetNotificationCallback(func(target ip6.Address, rloc16 uint16, err error) {
		// TODO: Resume queued messages for this EID
	})

	// Network Data Local — manages this device's own Network Data
	// contributions that are registered with the leader.
	inst.netdataLocal = netdata.NewLocal()
	inst.netdataNotifier = netdata.NewNotifier(inst.netdataLocal)
	inst.netdataNotifier.SetSyncCallback(func(oldRloc16 uint16, data []byte) error {
		if inst.mleService != nil && inst.mleService.Mle().IsLeader() {
			return inst.netdataLeader.RegisterNetworkData(inst.rloc16, data)
		}
		// TODO: Send CoAP POST to leader RLOC for non-leader devices
		return nil
	})
	inst.netdataPublisher = netdata.NewPublisher()

	// SLAAC Manager — generates IPv6 addresses from on-mesh prefixes.
	{
		var secretKey [32]byte
		if inst.stackSettings != nil {
			if data, err := inst.stackSettings.ReadSlaacIidSecretKey(); err == nil && len(data) == 32 {
				copy(secretKey[:], data)
			} else {
				if inst.entropy != nil {
					_ = inst.entropy.Fill(secretKey[:])
				}
				if inst.stackSettings != nil {
					_ = inst.stackSettings.WriteSlaacIidSecretKey(secretKey[:])
				}
			}
		}
		extAddr := inst.mac.GetExtAddress()
		iidGen := slaac.NewDefaultIIDGenerator(secretKey, [8]byte(extAddr))
		inst.slaacManager = slaac.NewManager(iidGen)
	}

	// ---------------------------------------------------------------
	// Link Metrics Subject + Initiator
	// ---------------------------------------------------------------
	inst.linkMetricsSubject = linkmetrics.NewSubject()
	inst.linkMetricsInitiator = linkmetrics.NewInitiator()

	// ---------------------------------------------------------------
	// Network Diagnostics Client + Server
	// ---------------------------------------------------------------
	inst.diagClient = diag.NewClient()
	inst.diagServer = diag.NewServer(&diagProviderAdapter{inst: inst})

	// ---------------------------------------------------------------
	// Tier 4 — UDP receiver registrations (RX path dispatch)
	// ---------------------------------------------------------------

	// MLE receiver intercepts UDP messages on the MLE port (19788).
	mleReceiver := udp.NewReceiver(func(payload []byte, mi *ip6.MessageInfo) bool {
		if mi.SockPort != mle.UDPPort {
			return false
		}
		// Extract the source extended address and compute link margin
		// from the MAC-layer metadata attached during RX processing.
		var srcExt types.ExtAddress
		var linkMargin uint8
		if mi.LinkInfo != nil {
			srcExt = mi.LinkInfo.SrcExtAddr
			// Compute link margin using the radio's actual receive
			// sensitivity as the noise floor reference.
			noiseFloor := inst.subMac.GetNoiseFloor()
			linkMargin = link.ComputeLinkMargin(noiseFloor, mi.LinkInfo.RSSI)
		}
		_ = inst.mleService.HandleReceive(payload, srcExt, mi.PeerAddr, mi.SockAddr, linkMargin)
		// Schedule attacher timer if the received message advanced the
		// attach state machine.
		inst.scheduleAttachTimer()
		// If the child detected stale network data, send a Data Request.
		if m := inst.mleService.Mle(); m.IsDataRequestPending() && m.IsChild() {
			m.SetDataRequestPending(false)
			_ = inst.mleService.ChildHandlers.SendDataRequest()
		}
		return true
	})
	_ = inst.udpManager.AddReceiver(mleReceiver)

	// CoAP/TMF receiver intercepts UDP messages on the TMF port (61631).
	coapReceiver := udp.NewReceiver(func(payload []byte, mi *ip6.MessageInfo) bool {
		if mi.SockPort != udp.TmfPort {
			return false
		}
		coapInfo := coap.MessageInfo{
			PeerAddr:  mi.PeerAddr,
			PeerPort:  mi.PeerPort,
			LocalAddr: mi.SockAddr,
		}
		inst.coapEngine.Receive(payload, coapInfo)
		return true
	})
	_ = inst.udpManager.AddReceiver(coapReceiver)

	// Push initial MAC keys to the SubMac/radio.
	inst.updateMacKeys()
}

// Start launches the event loop goroutine. It is an error to call Start
// on an already-running Instance.
func (inst *Instance) Start() error {
	inst.runningMu.Lock()
	if inst.running {
		inst.runningMu.Unlock()
		return errAlreadyRunning
	}
	inst.running = true
	inst.runningMu.Unlock()

	go inst.eventLoop()
	return nil
}

// Stop signals the event loop to shut down and waits for it to finish.
func (inst *Instance) Stop() {
	inst.runningMu.Lock()
	if !inst.running {
		inst.runningMu.Unlock()
		return
	}
	inst.runningMu.Unlock()

	close(inst.stopCh)
	<-inst.doneCh

	inst.runningMu.Lock()
	inst.running = false
	// Reset channels for potential restart.
	inst.stopCh = make(chan struct{})
	inst.doneCh = make(chan struct{})
	inst.runningMu.Unlock()
}

// --------------------------------------------------------------------------
// Interface / Thread lifecycle
// --------------------------------------------------------------------------

// IfConfigUp enables the network interface: MAC and mesh forwarder are
// enabled so frames can be sent and received. This is the equivalent of
// OpenThread's otIp6SetEnabled(true).
//
// Must be called before ThreadStart. Safe to call from any goroutine;
// the work is posted to the event loop.
func (inst *Instance) IfConfigUp() error {
	if inst.ifConfigUp {
		return errAlready
	}
	// Enable MAC only if a radio is available. Software-only instances
	// (no radio) skip MAC enable and rely on the forwarder alone.
	if inst.platRadio != nil {
		if err := inst.mac.Enable(); err != nil {
			return err
		}
	}
	inst.forwarder.SetEnabled(true)
	if inst.slaacManager != nil {
		inst.slaacManager.Enable()
	}
	inst.ifConfigUp = true
	return nil
}

// IfConfigDown disables the network interface. Thread must be stopped
// first via ThreadStop. This is the equivalent of
// OpenThread's otIp6SetEnabled(false).
func (inst *Instance) IfConfigDown() error {
	if !inst.ifConfigUp {
		return errAlready
	}
	if inst.threadEnabled {
		return errThreadStillRunning
	}
	if inst.slaacManager != nil {
		inst.slaacManager.Disable()
	}
	inst.forwarder.SetEnabled(false)
	if inst.platRadio != nil {
		if err := inst.mac.Disable(); err != nil {
			return err
		}
	}
	inst.ifConfigUp = false
	return nil
}

// IsIfConfigUp reports whether the network interface (MAC + forwarder)
// is enabled.
func (inst *Instance) IsIfConfigUp() bool { return inst.ifConfigUp }

// ThreadStart enables the Thread protocol: MLE transitions from
// Disabled to Detached and the attach process begins. The network
// interface must be up (IfConfigUp) first. This is the equivalent of
// OpenThread's otThreadSetEnabled(true).
func (inst *Instance) ThreadStart() error {
	if inst.threadEnabled {
		return errAlready
	}
	if !inst.ifConfigUp {
		return errInterfaceDown
	}

	// Apply the Active Operational Dataset (channel, PAN ID, network key,
	// etc.) before enabling MLE so the device attaches with the correct
	// credentials and radio parameters.
	inst.applyActiveDataset()

	m := inst.mleService.Mle()
	if err := m.Enable(); err != nil {
		return err
	}
	inst.threadEnabled = true

	// Kick off the attach state machine.
	inst.mleService.Attacher.Start(mle.AttachAnyPartition)
	inst.scheduleAttachTimer()
	return nil
}

// applyActiveDataset reads the Active Operational Dataset and applies its
// parameters to the MAC, key manager, and network identity fields. This
// ensures the device starts on the correct channel, PAN ID, and network
// key before MLE is enabled.
func (inst *Instance) applyActiveDataset() {
	if inst.activeDataset == nil {
		return
	}
	ds, err := inst.activeDataset.Read()
	if err != nil || ds == nil {
		return
	}
	info := ds.ConvertToInfo()

	if info.Components.Channel {
		inst.mac.SetPanChannel(uint8(info.Channel))
	}
	if info.Components.PanID {
		inst.mac.SetPanID(types.PanID(info.PanID))
	}
	if info.Components.NetworkKey {
		inst.keyManager.SetNetworkKey(key.NetworkKey(info.NetworkKey))
	}
	if info.Components.PSKc {
		inst.keyManager.SetPskc(key.Pskc(info.PSKc))
	}
	if info.Components.SecurityPolicy {
		inst.keyManager.SetSecurityPolicy(info.SecurityPolicy)
	}
	if info.Components.MeshLocalPrefix {
		inst.SetMeshLocalPrefix(info.MeshLocalPrefix)
	}
	if info.Components.NetworkName {
		inst.networkName = info.NetworkName
		inst.mac.SetNetworkName(info.NetworkName)
	}
	if info.Components.ExtendedPanID {
		inst.extendedPanID = info.ExtendedPanID
		inst.mac.SetExtendedPanID(info.ExtendedPanID)
	}
	inst.updateMacKeys()
}

// ThreadStop disables the Thread protocol: MLE returns to Disabled,
// clearing routing state and detaching from the network. This is the
// equivalent of OpenThread's otThreadSetEnabled(false).
func (inst *Instance) ThreadStop() error {
	if !inst.threadEnabled {
		return errAlready
	}
	m := inst.mleService.Mle()
	_ = m.Disable()
	inst.threadEnabled = false
	return nil
}

// IsThreadRunning reports whether the Thread protocol is enabled.
func (inst *Instance) IsThreadRunning() bool { return inst.threadEnabled }

// IsRunning reports whether the event loop is active.
func (inst *Instance) IsRunning() bool {
	inst.runningMu.Lock()
	defer inst.runningMu.Unlock()
	return inst.running
}

// PostTask schedules a function to run on the event loop goroutine.
// It is safe to call from any goroutine. If the task channel is full,
// PostTask blocks until space is available.
func (inst *Instance) PostTask(fn func()) {
	inst.taskCh <- fn
}

// ScheduleTimer schedules a function to run after the given delay on
// the event loop goroutine.
func (inst *Instance) ScheduleTimer(delay time.Duration, fn func()) {
	inst.PostTask(func() {
		inst.timers.schedule(delay, fn)
	})
}

// SignalEvents signals notifier events from within the event loop.
// Must be called from the event loop goroutine (e.g. from a posted task).
func (inst *Instance) SignalEvents(events Event) {
	inst.notifier.signal(events)
}

// RegisterNotifier registers a callback for notifier events. Must be
// called before Start() or from within a posted task.
func (inst *Instance) RegisterNotifier(cb NotifierCallback) {
	inst.notifier.register(cb)
}

// Alarm returns the platform Alarm interface.
func (inst *Instance) Alarm() platform.Alarm { return inst.alarm }

// Entropy returns the platform Entropy interface.
func (inst *Instance) Entropy() platform.Entropy { return inst.entropy }

// Settings returns the platform Settings interface.
func (inst *Instance) Settings() platform.Settings { return inst.platSettings }

// Logger returns the platform Logger interface.
func (inst *Instance) Logger() platform.Logger { return inst.logger }

// Radio returns the platform Radio interface.
func (inst *Instance) Radio() radio.Radio { return inst.platRadio }

// Mac returns the MAC layer.
func (inst *Instance) Mac() *mac.Mac { return inst.mac }

// SubMac returns the Sub-MAC layer.
func (inst *Instance) SubMac() *submac.SubMac { return inst.subMac }

// KeyManager returns the key manager.
func (inst *Instance) KeyManager() *key.Manager { return inst.keyManager }

// MessagePool returns the message buffer pool.
func (inst *Instance) MessagePool() *message.Pool { return inst.messagePool }

// RouterTable returns the router table.
func (inst *Instance) RouterTable() *routing.RouterTable { return inst.routerTable }

// ChildTable returns the child table.
func (inst *Instance) ChildTable() *routing.ChildTable { return inst.childTable }

// NeighborTable returns the neighbor table.
func (inst *Instance) NeighborTable() *routing.NeighborTable { return inst.neighborTable }

// MleService returns the MLE protocol service.
func (inst *Instance) MleService() *mle.Service { return inst.mleService }

// Netif returns the IPv6 network interface.
func (inst *Instance) Netif() *ip6.Netif { return inst.netif }

// UDPManager returns the UDP manager.
func (inst *Instance) UDPManager() *udp.UDP { return inst.udpManager }

// IcmpManager returns the ICMPv6 manager.
func (inst *Instance) IcmpManager() *icmp6.Icmp { return inst.icmpManager }

// CoapEngine returns the CoAP engine.
func (inst *Instance) CoapEngine() *coap.Engine { return inst.coapEngine }

// TmfAgent returns the TMF agent.
func (inst *Instance) TmfAgent() *tmf.Agent { return inst.tmfAgent }

// TmfLeaderService returns the TMF Leader service (Address Solicit/Release).
func (inst *Instance) TmfLeaderService() *tmf.LeaderService { return inst.tmfLeaderService }

// TmfServerDataService returns the TMF Server Data service.
func (inst *Instance) TmfServerDataService() *tmf.ServerDataService { return inst.tmfServerDataService }

// TmfCommissionerDataService returns the TMF Commissioner Data service.
func (inst *Instance) TmfCommissionerDataService() *tmf.CommissionerDataService {
	return inst.tmfCommissionerDataService
}

// NetdataLeader returns the network data leader.
func (inst *Instance) NetdataLeader() *netdata.Leader { return inst.netdataLeader }

// Forwarder returns the mesh forwarder.
func (inst *Instance) Forwarder() *mesh.Forwarder { return inst.forwarder }

// AddrResolver returns the EID-to-RLOC16 address resolver.
func (inst *Instance) AddrResolver() *addrresolver.Resolver { return inst.addrResolver }

// NetdataLocal returns the local Network Data manager.
func (inst *Instance) NetdataLocal() *netdata.Local { return inst.netdataLocal }

// NetdataNotifier returns the Network Data sync notifier.
func (inst *Instance) NetdataNotifier() *netdata.Notifier { return inst.netdataNotifier }

// NetdataPublisher returns the Network Data publisher.
func (inst *Instance) NetdataPublisher() *netdata.Publisher { return inst.netdataPublisher }

// SlaacManager returns the SLAAC address manager.
func (inst *Instance) SlaacManager() *slaac.Manager { return inst.slaacManager }

// LinkMetricsSubject returns the Link Metrics Subject instance.
func (inst *Instance) LinkMetricsSubject() *linkmetrics.Subject { return inst.linkMetricsSubject }

// LinkMetricsInitiator returns the Link Metrics Initiator instance.
func (inst *Instance) LinkMetricsInitiator() *linkmetrics.Initiator { return inst.linkMetricsInitiator }

// DiagClient returns the network diagnostics client.
func (inst *Instance) DiagClient() *diag.Client { return inst.diagClient }

// DiagServer returns the network diagnostics server.
func (inst *Instance) DiagServer() *diag.Server { return inst.diagServer }

// DataPollSender returns the data poll sender (SED polling manager).
func (inst *Instance) DataPollSender() *supervision.DataPollSender { return inst.dataPollSender }

// Supervisor returns the child supervisor (parent-side).
func (inst *Instance) Supervisor() *supervision.Supervisor { return inst.supervisor }

// SupervisionListener returns the supervision listener (child-side).
func (inst *Instance) SupervisionListener() *supervision.SupervisionListener {
	return inst.supervisionListener
}

// DataPollHandler returns the data poll handler (parent-side indirect TX).
func (inst *Instance) DataPollHandler() *supervision.DataPollHandler {
	return inst.dataPollHandler
}

// SourceMatchController returns the source address match controller (may be nil).
func (inst *Instance) SourceMatchController() *indirect.SourceMatchController {
	return inst.sourceMatchController
}

// IndirectSender returns the indirect frame sender (may be nil).
func (inst *Instance) IndirectSender() *indirect.Sender {
	return inst.indirectSender
}

// DroppedNonIPHC returns the count of received frames dropped because
// they were not 6LoWPAN IPHC compressed.
func (inst *Instance) DroppedNonIPHC() uint64 { return inst.droppedNonIPHC }

// SetMeshLocalPrefix sets the 64-bit mesh-local prefix used for RLOC
// and other mesh-local addresses.
func (inst *Instance) SetMeshLocalPrefix(prefix [8]byte) { inst.meshLocalPrefix = prefix }

// MeshLocalPrefix returns the 64-bit mesh-local prefix.
func (inst *Instance) MeshLocalPrefix() [8]byte { return inst.meshLocalPrefix }

// SetRLOC16 sets the 16-bit Routing Locator of this device.
func (inst *Instance) SetRLOC16(rloc16 uint16) {
	inst.rloc16 = rloc16
	if inst.netdataLocal != nil {
		inst.netdataLocal.SetRloc16(rloc16)
	}
	if inst.netdataPublisher != nil {
		inst.netdataPublisher.SetRloc16(rloc16)
	}
	if inst.netdataNotifier != nil {
		inst.netdataNotifier.SetOldRloc16(rloc16)
	}
}

// RLOC16 returns the 16-bit Routing Locator of this device.
func (inst *Instance) RLOC16() uint16 { return inst.rloc16 }

// --------------------------------------------------------------------------
// Internal helpers
// --------------------------------------------------------------------------

// scheduleAttachTimer schedules a self-re-arming timer for the MLE
// Attacher state machine.
func (inst *Instance) scheduleAttachTimer() {
	a := inst.mleService.Attacher
	if a.NextTimerDelay > 0 {
		// Enable fast polling during attach.
		if inst.dataPollSender != nil {
			inst.dataPollSender.SetAttachMode(true)
		}
		delay := a.NextTimerDelay
		inst.timers.schedule(delay, func() {
			_ = a.HandleTimer()
			inst.syncParentAddress()
			inst.scheduleAttachTimer() // re-arm if needed
		})
	} else {
		// Attach sequence complete — disable attach-mode polling.
		if inst.dataPollSender != nil {
			inst.dataPollSender.SetAttachMode(false)
		}
	}
}

// syncParentAddress ensures the Mac layer's parent short address
// matches the MLE parent's RLOC16 when we are in the Child role,
// and is cleared otherwise.
func (inst *Instance) syncParentAddress() {
	m := inst.mleService.Mle()
	if m.IsChild() {
		parent := m.GetParent()
		inst.mac.SetParentShortAddress(types.ShortAddress(parent.RLOC16))
	} else {
		inst.mac.SetParentShortAddress(0)
	}
	inst.syncDataPolling()
	inst.syncSupervision()
}

// syncDataPolling starts the DataPollSender when the device becomes a
// child (SED) and stops it otherwise (detached, router, leader).
func (inst *Instance) syncDataPolling() {
	if inst.dataPollSender == nil {
		return
	}
	m := inst.mleService.Mle()
	if m.IsChild() {
		if !inst.dataPollSender.IsEnabled() {
			inst.dataPollSender.Start()
		}
	} else {
		if inst.dataPollSender.IsEnabled() {
			inst.dataPollSender.Stop()
		}
	}
}

// syncSupervision starts the SupervisionListener when the device is a
// child (so it can detect parent loss) and stops it otherwise. The
// Supervisor (parent-side) is driven by handlePeriodicTick rather than
// a role-based start/stop because HandleTimer already checks the role.
func (inst *Instance) syncSupervision() {
	if inst.supervisionListener == nil {
		return
	}
	m := inst.mleService.Mle()
	if m.IsChild() {
		if !inst.supervisionListener.IsRunning() {
			inst.supervisionListener.Start()
		}
	} else {
		if inst.supervisionListener.IsRunning() {
			inst.supervisionListener.Stop()
		}
	}
}

// updateSlaacAddresses iterates on-mesh prefixes from the leader
// Network Data and drives the SLAAC manager to generate or remove
// IPv6 addresses accordingly.
func (inst *Instance) updateSlaacAddresses() {
	if inst.slaacManager == nil || !inst.slaacManager.IsEnabled() {
		return
	}
	if inst.netdataLeader == nil {
		return
	}
	it := netdata.NewIterator(inst.netdataLeader.Data())
	var prefixes []slaac.Prefix
	for {
		cfg, err := it.NextOnMeshPrefix()
		if err != nil {
			break
		}
		var flags uint8
		if cfg.OnMesh {
			flags |= slaac.FlagOnMesh
		}
		if cfg.SLAAC {
			flags |= slaac.FlagSlaac
		}
		if cfg.DHCP {
			flags |= slaac.FlagDhcp
		}
		if cfg.Configure {
			flags |= slaac.FlagConfigure
		}
		if cfg.DefaultRoute {
			flags |= slaac.FlagDefaultRoute
		}
		if cfg.Preferred {
			flags |= slaac.FlagPreferred
		}
		pfxBytes := cfg.Prefix.GetBytes()
		prefixes = append(prefixes, slaac.Prefix{
			Prefix: pfxBytes,
			Length: cfg.Prefix.GetLength(),
			Flags:  flags,
		})
	}
	inst.slaacManager.Update(prefixes)
}

// processAnnounce is invoked by the AnnounceHandler when a received
// Announce carries a newer or equal timestamp. The instance switches
// to the announced channel/PAN, detaches, and starts a fresh attach.
func (inst *Instance) processAnnounce(channel uint16, panID uint16) {
	inst.mac.SetPanChannel(uint8(channel))
	inst.mac.SetPanID(types.PanID(panID))
	_ = inst.mleService.Mle().BecomeDetached()
	inst.mleService.Attacher.Start(mle.AttachAnyPartition)
	inst.scheduleAttachTimer()
}

// --------------------------------------------------------------------------
// Periodic tick
// --------------------------------------------------------------------------

// periodicTickInterval is the interval for the 1-second periodic tick
// that drives time-based state machines (router role transition,
// router table ID reuse, trickle timers, neighbor aging, etc.).
const periodicTickInterval = 1 * time.Second

// startPeriodicTick schedules the first periodic tick. Subsequent ticks
// are self-re-arming via handlePeriodicTick.
func (inst *Instance) startPeriodicTick() {
	inst.timers.schedule(periodicTickInterval, inst.handlePeriodicTick)
}

// handlePeriodicTick is called once per second from the timer scheduler.
// It drives all time-based state machines and then re-arms itself.
func (inst *Instance) handlePeriodicTick() {
	// Router ID reuse delay counters.
	inst.routerTable.HandleTimeTick()

	// Router role transition countdown (REED → Router upgrade jitter).
	m := inst.mleService.Mle()
	if m.GetRouterRoleTransition().HandleTimeTick() {
		// Transition timer expired — attempt BecomeRouter.
		_ = m.BecomeRouter()
	}

	// Neighbor aging and Link Accept countdown (Phase 31y/z).
	inst.handleRouterNeighborTimers(m)

	// Sync parent short address to MAC layer on role changes.
	inst.syncParentAddress()

	// Flush any pending Parent Response messages whose scheduled
	// delay has elapsed (Phase 31aa).
	if inst.mleService.ParentRequestHandler != nil {
		_, _ = inst.mleService.ParentRequestHandler.FlushPendingResponses()
	}

	// Flush any delayed Link Accept messages for multicast-received
	// Link Requests whose delay has elapsed (Phase 31ab).
	if inst.mleService.LinkHandlers != nil {
		_, _ = inst.mleService.LinkHandlers.FlushPendingAccepts()
	}

	// Advertisement trickle timer — drives periodic MLE advertisements.
	// Start the timer when we become a Router/Leader; stop it otherwise.
	trickle := inst.mleService.AdvTrickle
	if m.IsRouterOrLeader() && !trickle.IsRunning() {
		trickle.Start()
	} else if !m.IsRouterOrLeader() && trickle.IsRunning() {
		trickle.Stop()
	}
	inst.mleService.HandleAdvTick(periodicTickInterval)

	// Child supervision — tick the supervisor for parent-side supervision.
	// When this device is a router or leader it sends periodic supervision
	// frames to sleepy children that haven't been heard from recently.
	if inst.supervisor != nil && m.IsRouterOrLeader() {
		inst.supervisor.HandleTimer()
		if inst.childProvider != nil {
			inst.childProvider.WriteBack()
		}
	}

	// 6LoWPAN fragment reassembly timeout — remove stale entries from the
	// forwarder's reassembly table so incomplete fragments don't leak memory.
	if inst.forwarder != nil {
		inst.forwarder.CleanupExpiredReassemblies()
	}

	// Key rotation — once per hour, advance the key manager's rotation
	// timer and push any updated keys to the radio.
	inst.keyRotationTickCounter++
	if inst.keyRotationTickCounter >= 3600 {
		inst.keyRotationTickCounter = 0
		inst.keyManager.HandleKeyRotationTick()
		inst.updateMacKeys()
	}

	// Address Resolver — drive retry/timeout timers for pending EID queries.
	if inst.addrResolver != nil {
		inst.addrResolver.HandleTimer(time.Now())
	}

	// Network Data Notifier — check if local data needs to be synced
	// with the leader and drive the notifier's retry timer.
	if inst.netdataNotifier != nil {
		if inst.netdataNotifier.NeedsSync() {
			inst.netdataNotifier.HandleTimerFired()
		}
	}

	// Network Data Publisher — process prefix/service publishing against
	// current leader data and advance publisher timers.
	if inst.netdataPublisher != nil && inst.netdataLeader != nil {
		actions := inst.netdataPublisher.Process(inst.netdataLeader.Data())
		for _, a := range actions {
			inst.applyPublisherAction(a)
		}
		inst.netdataPublisher.AdvanceTime(1000) // 1 second in ms
	}

	// Re-arm for the next tick.
	inst.timers.schedule(periodicTickInterval, inst.handlePeriodicTick)
}

// applyPublisherAction applies a single PublisherAction from the
// Publisher to the local Network Data.
func (inst *Instance) applyPublisherAction(a netdata.PublisherAction) {
	if inst.netdataLocal == nil {
		return
	}
	switch a.Type {
	case netdata.PublisherActionAdd:
		if a.IsOnMesh {
			_ = inst.netdataLocal.AddOnMeshPrefix(a.OnMesh)
		} else {
			_ = inst.netdataLocal.AddHasRoutePrefix(a.ExtRoute)
		}
	case netdata.PublisherActionRemove:
		if a.IsOnMesh {
			_ = inst.netdataLocal.RemoveOnMeshPrefix(a.OnMesh.Prefix)
		} else {
			_ = inst.netdataLocal.RemoveHasRoutePrefix(a.ExtRoute.Prefix)
		}
	}
	if inst.netdataLocal.HasChanged() {
		inst.netdataLocal.ClearChanged()
		inst.netdataNotifier.HandleServerDataUpdated()
	}
}

// handleRouterNeighborTimers performs per-router-neighbor aging and Link
// Accept countdown processing. This runs once per second as part of the
// periodic tick.
//
// For each valid router neighbor, the age (time since last heard) is
// compared against a threshold. If the neighbor is stale, its link is
// removed.
//
// For each router waiting for a Link Accept, the countdown is
// decremented. When the countdown expires, a retry Link Request is
// sent if attempts remain; otherwise the link is removed.
func (inst *Instance) handleRouterNeighborTimers(m *mle.Mle) {
	// Determine the age threshold based on our current role.
	maxAge := mle.MaxNeighborAge
	if m.IsChild() {
		maxAge = mle.MaxNeighborAgeOnChild
	}

	nowMs := uint32(time.Now().UnixMilli())
	routers := inst.routerTable.Routers()

	for i := range routers {
		r := &routers[i]

		if !r.IsStateValid() {
			// Phase 31z: Link Accept countdown for non-valid routers
			// that are waiting for a Link Accept response.
			if r.IsWaitingForLinkAccept() {
				r.DecrementLinkAcceptTimeout()
				if !r.IsWaitingForLinkAccept() {
					// Timeout expired — retry or give up.
					if r.HasRemainingLinkRequestAttempts() {
						r.DecrementLinkRequestAttempts()
						inst.sendLinkRequestToRouter(r)
					} else {
						inst.routerTable.RemoveRouterLink(r)
					}
				}
			}
			continue
		}

		// Phase 31y: Neighbor aging — evict stale valid neighbors.
		ageMs := nowMs - r.LastHeard
		if time.Duration(ageMs)*time.Millisecond > maxAge {
			inst.routerTable.RemoveRouterLink(r)
		}
	}
}

// sendLinkRequestToRouter converts a routing-layer router to an MLE-layer
// router and sends a unicast Link Request. The resulting challenge and
// link accept timeout are synced back to the routing-layer router.
func (inst *Instance) sendLinkRequestToRouter(r *routing.Router) {
	mleRouter := routerToMLE(r)
	challenge, err := mle.SendLinkRequest(
		inst.mleService.Mle(),
		inst.mleService.Dispatcher(),
		inst.mleService.Transport(),
		mleRouter,
	)
	if err != nil {
		return
	}
	// Sync state back: SendLinkRequest stores the challenge on the MLE
	// router and restarts its link accept timeout.
	r.Challenge = [8]byte(challenge)
	r.LinkAcceptTimeout = routing.DefaultLinkAcceptTimeout
}

// --------------------------------------------------------------------------
// Event loop
// --------------------------------------------------------------------------

// eventLoop is the main processing loop. It runs in a single goroutine
// and processes tasks, timers, and notifier events cooperatively.
func (inst *Instance) eventLoop() {
	defer close(inst.doneCh)

	// Start the 1-second periodic tick.
	inst.startPeriodicTick()

	for {
		// Determine how long to wait for the next timer.
		var timerCh <-chan time.Time
		if d, ok := inst.timers.nextDeadline(); ok {
			timerCh = time.After(d)
		}

		select {
		case <-inst.stopCh:
			// Drain remaining tasks before exit.
			inst.drainTasks()
			return

		case fn := <-inst.taskCh:
			fn()
			// After running a task, process any timers and notifier events.
			inst.timers.processExpired()
			inst.notifier.process()
			inst.stackNotifier.Process()

		case <-timerCh:
			inst.timers.processExpired()
			inst.notifier.process()
			inst.stackNotifier.Process()
		}
	}
}

// drainTasks processes any remaining tasks in the channel.
func (inst *Instance) drainTasks() {
	for {
		select {
		case fn := <-inst.taskCh:
			fn()
		default:
			return
		}
	}
}

// --------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------

// errAlreadyRunning is returned when Start is called on a running Instance.
var errAlreadyRunning = &instanceError{msg: "instance: already running"}

// errAlready is returned when a lifecycle method is called but the state
// is already in the requested state (e.g. IfConfigUp when already up).
var errAlready = &instanceError{msg: "instance: already in requested state"}

// errThreadStillRunning is returned when IfConfigDown is called while
// the Thread protocol is still enabled.
var errThreadStillRunning = &instanceError{msg: "instance: thread protocol still running; call ThreadStop first"}

// errInterfaceDown is returned when ThreadStart is called but the
// network interface is not enabled (IfConfigUp not called).
var errInterfaceDown = &instanceError{msg: "instance: network interface not enabled; call IfConfigUp first"}

type instanceError struct {
	msg string
}

func (e *instanceError) Error() string {
	return e.msg
}
