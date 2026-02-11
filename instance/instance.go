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
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
	"github.com/hilli/gothread/thread/routing"
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
	fireAt time.Time
	fn     func()
}

// timerScheduler maintains a sorted list of pending timers.
type timerScheduler struct {
	timers []timer
}

// schedule adds a timer that fires after delay, calling fn.
func (ts *timerScheduler) schedule(delay time.Duration, fn func()) {
	fireAt := time.Now().Add(delay)
	// Insert in sorted order (earliest first).
	idx := 0
	for idx < len(ts.timers) && ts.timers[idx].fireAt.Before(fireAt) {
		idx++
	}
	ts.timers = append(ts.timers, timer{})
	copy(ts.timers[idx+1:], ts.timers[idx:])
	ts.timers[idx] = timer{fireAt: fireAt, fn: fn}
}

// processExpired fires all timers whose deadline has passed. Returns the
// number of timers fired.
func (ts *timerScheduler) processExpired() int {
	now := time.Now()
	fired := 0
	for len(ts.timers) > 0 && !ts.timers[0].fireAt.After(now) {
		fn := ts.timers[0].fn
		ts.timers = ts.timers[1:]
		fn()
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

	// ---------------------------------------------------------------
	// Tier 3 — Application layer (CoAP, TMF, Mesh forwarding)
	// ---------------------------------------------------------------

	// coapEngine handles CoAP message exchange.
	coapEngine *coap.Engine

	// tmfAgent is the TMF CoAP agent for Thread management messages.
	tmfAgent *tmf.Agent

	// netdataLeader manages the Thread Network Data.
	netdataLeader *netdata.Leader

	// forwarder handles mesh frame forwarding.
	forwarder *mesh.Forwarder

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
}

// New creates a new Instance with the given platform configuration.
// All Thread stack modules are created and wired together during
// construction. Call Start() to begin the event loop.
func New(config Config) *Instance {
	inst := &Instance{
		alarm:        config.Alarm,
		entropy:      config.Entropy,
		platSettings: config.Settings,
		logger:       config.Logger,
		platRadio:    config.Radio,
		taskCh:       make(chan func(), 256),
		stopCh:       make(chan struct{}),
		doneCh:       make(chan struct{}),
		timers:       &timerScheduler{},
		notifier:     &notifier{},
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
		Radio:         inst.platRadio,
		Callbacks:     bridge,
		ScheduleTimer: inst.scheduleTimerDirect,
		StopTimer:     func() {}, // no-op; timers expire naturally
	})

	inst.mac = mac.New(mac.Config{
		SubMac:        inst.subMac,
		Callbacks:     inst, // Instance implements mac.Callbacks
		ScheduleTimer: inst.scheduleTimerDirect,
		StopTimer:     func() {},
		PostOperation: inst.postTask,
	})

	// Now wire Mac as the SubMac's callback receiver.
	bridge.target = inst.mac

	// ---------------------------------------------------------------
	// Tier 2 — Routing / MLE / Network
	// ---------------------------------------------------------------

	inst.routerTable = routing.NewRouterTable()
	inst.childTable = routing.NewChildTable()
	inst.neighborTable = routing.NewNeighborTable(inst.routerTable, inst.childTable)

	inst.netif = ip6.NewNetif()
	inst.udpManager = udp.New()

	inst.mleService = mle.NewService(mle.ServiceConfig{
		Transport:    inst, // Instance implements mle.Transport
		KeyProvider:  inst, // Instance delegates to keyManager
		RouterLookup: inst, // Instance delegates to routerTable
		RouteData:    inst, // Instance delegates to routerTable
		RouterOps:    inst, // Instance delegates to routerTable
		Connectivity: inst, // Instance provides connectivity data
		NetworkInfo:  inst, // Instance provides network identity
		NeighborLookup: func(addr types.ExtAddress) *mle.Neighbor {
			n := inst.neighborTable.FindNeighborByExtAddress(addr, routing.FilterValid)
			if n == nil {
				return nil
			}
			return neighborToMLE(n)
		},
	})

	// ---------------------------------------------------------------
	// Tier 3 — Application layer
	// ---------------------------------------------------------------

	inst.coapEngine = coap.NewEngine(inst.sendCoAP)
	inst.tmfAgent = tmf.NewAgent(inst.coapEngine)
	inst.netdataLeader = netdata.NewLeader(&routerCheckerAdapter{rt: inst.routerTable})
	inst.forwarder = mesh.NewForwarder()
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

// CoapEngine returns the CoAP engine.
func (inst *Instance) CoapEngine() *coap.Engine { return inst.coapEngine }

// TmfAgent returns the TMF agent.
func (inst *Instance) TmfAgent() *tmf.Agent { return inst.tmfAgent }

// NetdataLeader returns the network data leader.
func (inst *Instance) NetdataLeader() *netdata.Leader { return inst.netdataLeader }

// Forwarder returns the mesh forwarder.
func (inst *Instance) Forwarder() *mesh.Forwarder { return inst.forwarder }

// --------------------------------------------------------------------------
// Event loop
// --------------------------------------------------------------------------

// eventLoop is the main processing loop. It runs in a single goroutine
// and processes tasks, timers, and notifier events cooperatively.
func (inst *Instance) eventLoop() {
	defer close(inst.doneCh)

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

		case <-timerCh:
			inst.timers.processExpired()
			inst.notifier.process()
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

type instanceError struct {
	msg string
}

func (e *instanceError) Error() string {
	return e.msg
}
