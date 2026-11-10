// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

// Package srp implements the Service Registration Protocol (SRP) client
// for DNS-SD service registration as defined in RFC 2136 (DNS Update)
// with SIG(0) authentication (RFC 2931) and EDNS Update Lease (draft).
//
// This is a port of the OpenThread SRP client implementation.
package srp

import (
	"encoding/binary"
	"io"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// Constants
// -------------------------------------------------------

const (
	// DefaultDomainName is the default SRP domain name.
	DefaultDomainName = "default.service.arpa."

	// DefaultLease is the default lease interval in seconds (2 hours).
	DefaultLease uint32 = 7200

	// DefaultKeyLease is the default key lease interval in seconds (7 days).
	DefaultKeyLease uint32 = 604800

	// LeaseRenewGuardInterval is the minimum time before lease expiry
	// at which we start the renewal process (seconds).
	LeaseRenewGuardInterval uint32 = 120

	// LeaseRenewJitter is the maximum random jitter added to lease
	// renewal scheduling (milliseconds).
	LeaseRenewJitter uint32 = 15000

	// MaxLease is the maximum lease value in seconds (~24.8 days).
	MaxLease uint32 = 2147483

	// UDPPayloadSize is the maximum DNS UDP payload size for IPv6.
	// IPv6 min MTU (1280) - IPv6 header (40) - UDP header (8).
	UDPPayloadSize uint16 = 1232

	// MinTxJitter is the minimum transmit jitter in milliseconds.
	MinTxJitter uint32 = 10

	// MaxTxJitterDefault is the default maximum transmit jitter (ms).
	MaxTxJitterDefault uint32 = 500

	// MaxTxJitterOnReboot is the max tx jitter on device reboot (ms).
	MaxTxJitterOnReboot uint32 = 700

	// MaxTxJitterOnServerChange is the max tx jitter when server
	// changes, restarts, or SLAAC addr changes (ms).
	MaxTxJitterOnServerChange uint32 = 10000

	// TxFailureRetryInterval is the base retry interval on tx failure (ms).
	TxFailureRetryInterval uint32 = 250

	// TxFailureRetryJitter is the max jitter added to tx failure retries (ms).
	TxFailureRetryJitter uint32 = 10

	// MaxTxFailureRetries is the existing bound on consecutive local build/send
	// failures. A successful send resets it; server responses do not consume it.
	MaxTxFailureRetries uint8 = 8

	// MinRetryWaitInterval is the minimum retry wait interval (ms).
	MinRetryWaitInterval uint32 = 1800

	// MaxRetryWaitInterval is the maximum retry wait interval (ms).
	MaxRetryWaitInterval uint32 = 1036800

	// RetryGrowthNumerator is the numerator for retry interval growth.
	RetryGrowthNumerator uint32 = 17

	// RetryGrowthDenominator is the denominator for retry interval growth.
	RetryGrowthDenominator uint32 = 10

	// RetryIntervalJitter is max jitter added to retry interval (ms).
	RetryIntervalJitter uint32 = 2000

	// RetryJitterDivisor divides the retry wait interval for jitter range.
	RetryJitterDivisor uint32 = 5

	// EarlyLeaseRenewNumerator is the numerator of the lease fraction
	// at which early renewal is triggered (1/2).
	EarlyLeaseRenewNumerator uint32 = 1
	// EarlyLeaseRenewDenominator is the denominator of the early-renewal fraction.
	EarlyLeaseRenewDenominator uint32 = 2

	// UnspecifiedInterval indicates the user has not set a value.
	UnspecifiedInterval uint32 = 0
)

// -------------------------------------------------------
// Enums
// -------------------------------------------------------

// ItemState represents the state of a host info entry or service.
type ItemState uint8

const (
	// ItemStateToAdd indicates the item needs to be added.
	ItemStateToAdd ItemState = iota
	// ItemStateAdding indicates the item is being added.
	ItemStateAdding
	// ItemStateToRefresh indicates the item needs a refresh.
	ItemStateToRefresh
	// ItemStateRefreshing indicates the item is being refreshed.
	ItemStateRefreshing
	// ItemStateToRemove indicates the item needs removal.
	ItemStateToRemove
	// ItemStateRemoving indicates the item is being removed.
	ItemStateRemoving
	// ItemStateRegistered indicates the item is registered.
	ItemStateRegistered
	// ItemStateRemoved indicates the item has been removed.
	ItemStateRemoved
)

// String returns the string representation of an ItemState.
func (s ItemState) String() string {
	switch s {
	case ItemStateToAdd:
		return "ToAdd"
	case ItemStateAdding:
		return "Adding"
	case ItemStateToRefresh:
		return "ToRefresh"
	case ItemStateRefreshing:
		return "Refreshing"
	case ItemStateToRemove:
		return "ToRemove"
	case ItemStateRemoving:
		return "Removing"
	case ItemStateRegistered:
		return "Registered"
	case ItemStateRemoved:
		return "Removed"
	default:
		return "Unknown"
	}
}

// State represents the overall client state.
type State uint8

const (
	// StateStopped means the client is not running.
	StateStopped State = iota
	// StatePaused means the client is paused.
	StatePaused
	// StateToUpdate means an update message needs to be sent.
	StateToUpdate
	// StateUpdating means an update message is in flight.
	StateUpdating
	// StateUpdated means the client is quiescent after success or a terminal
	// error. Host/service ItemState and the callback distinguish these cases.
	StateUpdated
	// StateToRetry means we need to retry after a failure.
	StateToRetry
)

// String returns the string representation of a State.
func (s State) String() string {
	switch s {
	case StateStopped:
		return "Stopped"
	case StatePaused:
		return "Paused"
	case StateToUpdate:
		return "ToUpdate"
	case StateUpdating:
		return "Updating"
	case StateUpdated:
		return "Updated"
	case StateToRetry:
		return "ToRetry"
	default:
		return "Unknown"
	}
}

// -------------------------------------------------------
// State transition tables
// -------------------------------------------------------

// newStateOnStop maps current ItemState to new state when Stop() is called.
var newStateOnStop = [8]ItemState{
	ItemStateToAdd,     // ToAdd -> ToAdd
	ItemStateToRefresh, // Adding -> ToRefresh
	ItemStateToRefresh, // ToRefresh -> ToRefresh
	ItemStateToRefresh, // Refreshing -> ToRefresh
	ItemStateToRemove,  // ToRemove -> ToRemove
	ItemStateToRemove,  // Removing -> ToRemove
	ItemStateToRefresh, // Registered -> ToRefresh
	ItemStateRemoved,   // Removed -> Removed
}

// newStateOnPause maps current ItemState to new state when Pause() is called.
var newStateOnPause = [8]ItemState{
	ItemStateToAdd,      // ToAdd -> ToAdd
	ItemStateToRefresh,  // Adding -> ToRefresh
	ItemStateToRefresh,  // ToRefresh -> ToRefresh
	ItemStateToRefresh,  // Refreshing -> ToRefresh
	ItemStateToRemove,   // ToRemove -> ToRemove
	ItemStateToRemove,   // Removing -> ToRemove
	ItemStateRegistered, // Registered -> Registered
	ItemStateRemoved,    // Removed -> Removed
}

// newStateOnMessageTx maps current ItemState to new state when a
// DNS Update message is transmitted.
var newStateOnMessageTx = [8]ItemState{
	ItemStateAdding,     // ToAdd -> Adding
	ItemStateAdding,     // Adding -> Adding
	ItemStateRefreshing, // ToRefresh -> Refreshing
	ItemStateRefreshing, // Refreshing -> Refreshing
	ItemStateRemoving,   // ToRemove -> Removing
	ItemStateRemoving,   // Removing -> Removing
	ItemStateRegistered, // Registered -> Registered
	ItemStateRemoved,    // Removed -> Removed
}

// newStateOnSingleServiceMode maps current ItemState to new state
// when falling back to single-service mode (message too large).
var newStateOnSingleServiceMode = [8]ItemState{
	ItemStateToAdd,      // ToAdd -> ToAdd
	ItemStateToRefresh,  // Adding -> ToRefresh
	ItemStateToRefresh,  // ToRefresh -> ToRefresh
	ItemStateToRefresh,  // Refreshing -> ToRefresh
	ItemStateToRemove,   // ToRemove -> ToRemove
	ItemStateToRemove,   // Removing -> ToRemove
	ItemStateRegistered, // Registered -> Registered
	ItemStateRemoved,    // Removed -> Removed
}

// newStateOnUpdateDone maps current ItemState to new state when the
// server responds with success.
var newStateOnUpdateDone = [8]ItemState{
	ItemStateToAdd,      // ToAdd -> ToAdd
	ItemStateRegistered, // Adding -> Registered
	ItemStateToRefresh,  // ToRefresh -> ToRefresh
	ItemStateRegistered, // Refreshing -> Registered
	ItemStateToRemove,   // ToRemove -> ToRemove
	ItemStateRemoved,    // Removing -> Removed
	ItemStateRegistered, // Registered -> Registered
	ItemStateRemoved,    // Removed -> Removed
}

// -------------------------------------------------------
// Types
// -------------------------------------------------------

// HostInfo represents the host information registered with the SRP server.
type HostInfo struct {
	Name        string
	Addresses   []ip6.Address
	AutoAddress bool
	State       ItemState
}

// Service represents a service to be registered via SRP.
type Service struct {
	// Name is the service type (e.g., "_chip._udp").
	Name string
	// InstanceName is the service instance label.
	InstanceName string
	// SubTypeLabels contains sub-type labels for the service.
	SubTypeLabels []string
	// Port is the port number the service is listening on.
	Port uint16
	// Priority is the SRV record priority.
	Priority uint16
	// Weight is the SRV record weight.
	Weight uint16
	// TxtEntries contains the TXT record key-value pairs.
	TxtEntries []dns.TxtEntry
	// Lease is the requested lease interval in seconds (0 = use default).
	Lease uint32
	// KeyLease is the requested key lease interval in seconds (0 = use default).
	KeyLease uint32
	// State is the current registration state of this service.
	State ItemState

	// appendedInMessage tracks whether this service was included in
	// the current DNS Update message being built.
	appendedInMessage bool
}

// Callback is the function signature for SRP update completion notifications.
type Callback func(err error, hostInfo *HostInfo, services []*Service, removedServices []*Service)

// UDPSender is the interface for sending UDP packets.
type UDPSender interface {
	Send(data []byte, dest ip6.SockAddr) error
}

// Timer is the interface for a cancellable timer.
type Timer interface {
	Stop() bool
}

// -------------------------------------------------------
// Client options
// -------------------------------------------------------

// Option configures the Client.
type Option func(*Client)

// WithAfterFunc sets a custom timer factory for testing.
// The factory must schedule the callback, not invoke it inline.
func WithAfterFunc(af func(time.Duration, func()) Timer) Option {
	return func(c *Client) {
		c.afterFunc = af
	}
}

// WithNow sets a custom time source for testing.
func WithNow(now func() time.Time) Option {
	return func(c *Client) {
		c.now = now
	}
}

// WithRandUint32 sets a custom random number generator for testing.
func WithRandUint32(f func(uint32) uint32) Option {
	return func(c *Client) {
		c.randUint32 = f
	}
}

// WithKeyPair sets a pre-generated ECDSA key pair instead of
// generating one on Start().
func WithKeyPair(kp *ecdsa.KeyPair) Option {
	return func(c *Client) {
		c.keyPair = kp
	}
}

// WithEntropy directs key creation and every SIG(0) signature to the provided
// qualified source. Standalone callers omitting this keep the existing default.
func WithEntropy(reader io.Reader) Option {
	return func(c *Client) { c.entropy = reader }
}

// WithSingleServiceUpdates limits each UPDATE to one pending service. The
// remaining services stay pending until their own actual response. This bounds
// native UDP datagrams without truncating registrations; standalone defaults
// remain unchanged.
func WithSingleServiceUpdates() Option {
	return func(c *Client) { c.singleServiceUpdates = true }
}

// -------------------------------------------------------
// msgInfo — internal state for DNS Update message construction
// -------------------------------------------------------

type msgInfo struct {
	buf               []byte
	singleServiceMode bool
	domainNameOffset  uint16
	hostNameOffset    uint16
	recordCount       uint16
	sigRecordOffset   int
}

// -------------------------------------------------------
// Client
// -------------------------------------------------------

// Client implements the SRP client protocol.
type Client struct {
	mu sync.Mutex

	state      State
	serverAddr ip6.SockAddr

	hostInfo HostInfo
	services []*Service

	domainName           string
	callback             Callback
	sender               UDPSender
	keyPair              *ecdsa.KeyPair
	entropy              io.Reader
	singleServiceUpdates bool

	curMessageID         uint16
	attemptEpoch         uint64
	txFailureRetryCount  uint8
	shouldRemoveKeyLease bool

	retryWaitInterval uint32
	leaseRenewTime    time.Time

	ttl             uint32
	lease           uint32
	keyLease        uint32
	defaultLease    uint32
	defaultKeyLease uint32

	timer      Timer
	timerEpoch uint64
	afterFunc  func(time.Duration, func()) Timer
	now        func() time.Time
	randUint32 func(uint32) uint32
}

// NewClient creates a new SRP client with the given UDP sender and options.
func NewClient(sender UDPSender, opts ...Option) *Client {
	c := &Client{
		state:           StateStopped,
		sender:          sender,
		domainName:      DefaultDomainName,
		defaultLease:    DefaultLease,
		defaultKeyLease: DefaultKeyLease,
		hostInfo: HostInfo{
			State: ItemStateRemoved,
		},
		afterFunc: func(d time.Duration, f func()) Timer {
			t := time.AfterFunc(d, f)
			return t
		},
		now: time.Now,
		randUint32: func(max uint32) uint32 {
			if max == 0 {
				return 0
			}
			return rand.Uint32N(max)
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// -------------------------------------------------------
// Public — lifecycle
// -------------------------------------------------------

// Start starts the SRP client, targeting the given server address.
// A key pair is generated if one was not provided via WithKeyPair.
func (c *Client) Start(serverAddr ip6.SockAddr) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StateStopped {
		return errors.ErrInvalidState
	}

	if c.keyPair == nil {
		var kp *ecdsa.KeyPair
		var err error
		if c.entropy != nil {
			kp, err = ecdsa.GenerateKeyPairWithReader(c.entropy)
		} else {
			kp, err = ecdsa.GenerateKeyPair()
		}
		if err != nil {
			return err
		}
		c.keyPair = kp
	}

	c.serverAddr = serverAddr
	c.cancelAttempt()
	c.retryWaitInterval = 0
	c.txFailureRetryCount = 0

	c.setState(StateUpdated)
	c.resume()

	return nil
}

// Stop stops the SRP client. All in-flight operations are cancelled.
// Items in Adding/Refreshing states revert to ToRefresh; items in
// Removing revert to ToRemove.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateStopped {
		return
	}

	c.cancelAttempt()
	c.changeHostAndServiceStates(&newStateOnStop, false)
	c.setState(StateStopped)
}

// Pause pauses the SRP client. Similar to Stop but preserves
// Registered state for items that were already registered.
func (c *Client) Pause() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateStopped {
		return
	}

	c.cancelAttempt()
	c.changeHostAndServiceStates(&newStateOnPause, false)
	c.setState(StatePaused)
}

// Resume resumes a paused client.
func (c *Client) Resume() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state != StatePaused {
		return
	}

	c.resume()
}

// IsRunning reports whether the client is in a running state
// (not stopped and not paused).
func (c *Client) IsRunning() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state != StateStopped && c.state != StatePaused
}

// GetState returns the current client state.
func (c *Client) GetState() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// GetHostInfo returns a copy of the current host info.
func (c *Client) GetHostInfo() HostInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	info := c.hostInfo
	// Copy the addresses slice to prevent mutation.
	if len(info.Addresses) > 0 {
		addrs := make([]ip6.Address, len(info.Addresses))
		copy(addrs, info.Addresses)
		info.Addresses = addrs
	}
	return info
}

// GetServices returns the current list of services. The returned
// slice is a copy; mutating it won't affect the client.
func (c *Client) GetServices() []*Service {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*Service, len(c.services))
	copy(out, c.services)
	return out
}

// ServiceUpdateSize measures a fresh registration using the actual encoder,
// current host configuration and public KEY. It has no side effects on the
// running client, signing entropy, timers, sender, or service argument. The
// fixed-size SIG(0) placeholder has exactly the final signature's wire size.
//
//nolint:gocritic // The detached value is intentionally independent of live service ownership.
func (c *Client) ServiceUpdateSize(service Service) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.keyPair == nil {
		return 0, errors.ErrInvalidState
	}
	service.State = ItemStateToAdd
	host := c.hostInfo
	host.Addresses = append([]ip6.Address(nil), host.Addresses...)
	host.State = ItemStateToAdd
	snapshot := &Client{
		keyPair: c.keyPair, domainName: c.domainName,
		hostInfo: host, services: []*Service{&service},
		defaultLease: c.defaultLease, defaultKeyLease: c.defaultKeyLease,
		ttl: c.ttl, singleServiceUpdates: true,
	}
	info := &msgInfo{}
	if err := snapshot.encodeUpdateMessage(info, false); err != nil {
		return 0, err
	}
	return len(info.buf), nil
}

// GetServerAddress returns the server address.
func (c *Client) GetServerAddress() ip6.SockAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverAddr
}

// SetServerAddress updates the server address while running.
func (c *Client) SetServerAddress(addr ip6.SockAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverAddr == addr {
		return
	}
	c.serverAddr = addr
	c.changeHostAndServiceStates(&newStateOnStop, false)
	c.restartPending()
}

// -------------------------------------------------------
// Public — configuration
// -------------------------------------------------------

// SetCallback sets the callback function invoked on update completion.
func (c *Client) SetCallback(cb Callback) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callback = cb
}

// SetHostName sets the host name for registration. The name should be
// a single label (without the domain suffix). Returns ErrInvalidArgs
// if the name is empty, or ErrInvalidState if currently updating.
func (c *Client) SetHostName(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if name == "" {
		return errors.ErrInvalidArgs
	}

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	if c.hostInfo.Name == name {
		return errors.ErrAlready
	}

	c.hostInfo.Name = name

	if c.hostInfo.State != ItemStateRemoved {
		c.hostInfo.State = ItemStateToRefresh
	}

	c.handleHostInfoOrServiceChange()
	return nil
}

// SetHostAddresses sets the IPv6 addresses to register for the host.
func (c *Client) SetHostAddresses(addrs []ip6.Address) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	c.hostInfo.AutoAddress = false

	copied := make([]ip6.Address, len(addrs))
	copy(copied, addrs)
	c.hostInfo.Addresses = copied

	if c.hostInfo.State == ItemStateRemoved {
		c.hostInfo.State = ItemStateToAdd
	} else {
		c.hostInfo.State = ItemStateToRefresh
	}

	c.handleHostInfoOrServiceChange()
	return nil
}

// EnableAutoHostAddress enables auto host address mode.
func (c *Client) EnableAutoHostAddress() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	if c.hostInfo.AutoAddress {
		return errors.ErrAlready
	}

	c.hostInfo.AutoAddress = true

	if c.hostInfo.State == ItemStateRemoved {
		c.hostInfo.State = ItemStateToAdd
	} else {
		c.hostInfo.State = ItemStateToRefresh
	}

	c.handleHostInfoOrServiceChange()
	return nil
}

// AddService adds a service for registration. The service will be
// included in the next SRP update. Returns ErrAlready if the service
// is already tracked, or ErrInvalidState if the client is updating.
func (c *Client) AddService(svc *Service) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateUpdating || c.hostInfo.State == ItemStateToRemove || c.hostInfo.State == ItemStateRemoving {
		return errors.ErrInvalidState
	}

	for _, s := range c.services {
		if s == svc {
			return errors.ErrAlready
		}
	}

	svc.State = ItemStateToAdd
	c.services = append(c.services, svc)
	c.handleHostInfoOrServiceChange()
	return nil
}

// RemoveService marks a service for removal. It will be unregistered
// in the next SRP update.
func (c *Client) RemoveService(svc *Service) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	found := false
	for _, s := range c.services {
		if s == svc {
			found = true
			break
		}
	}
	if !found {
		return errors.ErrNotFound
	}

	if svc.State == ItemStateRemoved || svc.State == ItemStateToRemove || svc.State == ItemStateRemoving {
		return errors.ErrAlready
	}

	svc.State = ItemStateToRemove
	c.handleHostInfoOrServiceChange()
	return nil
}

// ClearService removes a service from the client's list without
// sending an unregister to the server.
func (c *Client) ClearService(svc *Service) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	idx := -1
	for i, s := range c.services {
		if s == svc {
			idx = i
			break
		}
	}
	if idx < 0 {
		return errors.ErrNotFound
	}

	c.services = append(c.services[:idx], c.services[idx+1:]...)
	c.restartPending()
	return nil
}

// RemoveHostAndServices marks the host and all services for removal.
// If sendUnregToServer is true, an unregister update is sent to the
// server. If removeKeyLease is true, the key lease is also removed.
func (c *Client) RemoveHostAndServices(removeKeyLease, sendUnregToServer bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	if c.hostInfo.State == ItemStateRemoved {
		return errors.ErrAlready
	}

	c.shouldRemoveKeyLease = removeKeyLease

	if sendUnregToServer {
		c.hostInfo.State = ItemStateToRemove
		for _, svc := range c.services {
			if svc.State != ItemStateRemoved {
				svc.State = ItemStateToRemove
			}
		}
		c.handleHostInfoOrServiceChange()
	} else {
		c.cancelAttempt()
		c.hostInfo.State = ItemStateRemoved
		for _, svc := range c.services {
			svc.State = ItemStateRemoved
		}
		c.leaseRenewTime = time.Time{}
		if c.state != StateStopped && c.state != StatePaused {
			c.setState(StateUpdated)
		}
	}

	return nil
}

// ClearHostAndServices clears all host info and services without
// sending any updates.
func (c *Client) ClearHostAndServices() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cancelAttempt()
	c.hostInfo = HostInfo{State: ItemStateRemoved}
	c.services = nil
	c.shouldRemoveKeyLease = false
	c.lease, c.keyLease = 0, 0
	c.leaseRenewTime = time.Time{}
	c.txFailureRetryCount, c.retryWaitInterval = 0, 0
	if c.state != StateStopped && c.state != StatePaused {
		c.setState(StateUpdated)
	}
}

// SetLeaseInterval sets the requested lease interval in seconds.
// Use 0 to revert to the default.
func (c *Client) SetLeaseInterval(interval uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultLease = interval
}

// SetKeyLeaseInterval sets the requested key lease interval in seconds.
// Use 0 to revert to the default.
func (c *Client) SetKeyLeaseInterval(interval uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.defaultKeyLease = interval
}

// SetTtl sets the TTL for all records. Use 0 for automatic TTL
// (derived from the lease interval).
func (c *Client) SetTtl(ttl uint32) { //nolint:revive // Preserve the exported API spelling for existing callers.
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ttl = ttl
}

// SetDomainName sets the domain name for registrations.
func (c *Client) SetDomainName(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if name == "" {
		return errors.ErrInvalidArgs
	}

	if c.state == StateUpdating {
		return errors.ErrInvalidState
	}

	c.domainName = name
	c.handleHostInfoOrServiceChange()
	return nil
}

// GetDomainName returns the current domain name.
func (c *Client) GetDomainName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.domainName
}

// -------------------------------------------------------
// Internal — state management
// -------------------------------------------------------

// setState sets the client state and manages timer lifecycle.
// Must be called with c.mu held.
func (c *Client) setState(s State) {
	c.state = s
}

// resume moves the client from Paused/Stopped to Updated and
// triggers updateState. Must be called with c.mu held.
func (c *Client) resume() {
	c.txFailureRetryCount, c.retryWaitInterval = 0, 0
	c.setState(StateUpdated)
	c.updateState()
}

// stopTimer stops the current timer if one is running.
// Must be called with c.mu held.
func (c *Client) stopTimer() {
	c.timerEpoch++
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
}

// changeHostAndServiceStates applies a state transition table to the
// host info and all services. If forAppendedOnly is true, only items
// whose appendedInMessage flag is set are transitioned. Returns true
// if any item was transitioned.
func (c *Client) changeHostAndServiceStates(newStates *[8]ItemState, forAppendedOnly bool) bool {
	changed := false

	if !forAppendedOnly || c.hostInfo.State != ItemStateRegistered {
		newState := newStates[c.hostInfo.State]
		if newState != c.hostInfo.State {
			c.hostInfo.State = newState
			changed = true
		}
	}

	for _, svc := range c.services {
		if forAppendedOnly && !svc.appendedInMessage {
			continue
		}
		newState := newStates[svc.State]
		if newState != svc.State {
			svc.State = newState
			changed = true
		}
	}

	return changed
}

// invokeCallback calls the user callback if one is set.
// Must be called with c.mu held.
func (c *Client) invokeCallback(err error) {
	// Only acknowledged removal can prune or publish removed services. This
	// cleanup is independent of whether an application installed a callback.
	var removed []*Service
	remaining := c.services[:0]
	for _, svc := range c.services {
		if err == nil && svc.State == ItemStateRemoved {
			removed = append(removed, svc)
		} else {
			remaining = append(remaining, svc)
		}
	}
	clear(c.services[len(remaining):])
	c.services = remaining
	if c.callback == nil {
		return
	}

	info := c.hostInfo
	info.Addresses = append([]ip6.Address(nil), c.hostInfo.Addresses...)
	cb := c.callback
	svcs := make([]*Service, len(c.services))
	copy(svcs, c.services)

	// Invoke callback without lock to prevent deadlocks.
	c.mu.Unlock()
	cb(err, &info, svcs, removed)
	c.mu.Lock()
}

// handleHostInfoOrServiceChange is called whenever host info or
// services change. It triggers an update if appropriate.
func (c *Client) handleHostInfoOrServiceChange() {
	c.restartPending()
}

// updateState evaluates whether an update needs to be sent and
// schedules the timer accordingly.
func (c *Client) updateState() {
	if c.state == StateStopped || c.state == StatePaused {
		return
	}

	// Check if there is anything to update.
	needsUpdate := false

	if c.hostInfo.Name != "" {
		switch c.hostInfo.State {
		case ItemStateToAdd, ItemStateToRefresh, ItemStateToRemove:
			needsUpdate = true
		}
	}

	if !needsUpdate {
		for _, svc := range c.services {
			switch svc.State {
			case ItemStateToAdd, ItemStateToRefresh, ItemStateToRemove:
				needsUpdate = true
			}
			if needsUpdate {
				break
			}
		}
	}

	if !needsUpdate {
		// Check for lease renewal.
		if c.state == StateUpdated {
			c.scheduleLeaseRenewal()
		}
		return
	}

	if c.state == StateUpdated || c.state == StateToRetry {
		c.setState(StateToUpdate)
		c.scheduleUpdate(0) // immediate with jitter
	}
}

// scheduleUpdate schedules the update timer with the given delay
// plus random jitter. Must be called with c.mu held.
func (c *Client) scheduleUpdate(baseDelayMs uint32) {
	jitter := c.randUint32(MaxTxJitterDefault)
	if jitter < MinTxJitter {
		jitter = MinTxJitter
	}

	delayMs := baseDelayMs + jitter
	c.armTimer(time.Duration(delayMs)*time.Millisecond, c.handleTimer)
}

// scheduleLeaseRenewal schedules a timer to renew the lease before
// it expires. Must be called with c.mu held.
func (c *Client) scheduleLeaseRenewal() {
	if c.lease == 0 {
		return
	}

	now := c.now()
	if c.leaseRenewTime.IsZero() {
		return
	}

	delay := c.leaseRenewTime.Sub(now)
	if delay <= 0 {
		// Already past renewal time; trigger immediately.
		c.hostInfo.State = ItemStateToRefresh
		for _, svc := range c.services {
			if svc.State == ItemStateRegistered {
				svc.State = ItemStateToRefresh
			}
		}
		c.setState(StateToUpdate)
		c.scheduleUpdate(0)
		return
	}

	c.armTimer(delay, c.handleLeaseRenewalTimer)
}

// handleLeaseRenewalTimer fires when the lease needs renewal.
func (c *Client) handleLeaseRenewalTimer() {
	if c.state != StateUpdated {
		return
	}

	c.hostInfo.State = ItemStateToRefresh
	for _, svc := range c.services {
		if svc.State == ItemStateRegistered {
			svc.State = ItemStateToRefresh
		}
	}

	c.setState(StateToUpdate)
	c.scheduleUpdate(0)
}

// handleTimer fires when the update timer expires.
func (c *Client) handleTimer() {
	switch c.state {
	case StateToUpdate:
		c.sendUpdate()
	case StateUpdating:
		c.responseTimedOut()
	case StateToRetry:
		c.setState(StateToUpdate)
		c.sendUpdate()
	default:
		// Unexpected state; ignore.
	}
}

// -------------------------------------------------------
// Internal — DNS Update message building
// -------------------------------------------------------

// sendUpdate builds and sends a DNS Update message.
// Must be called with c.mu held.
func (c *Client) sendUpdate() {
	if c.hostInfo.Name == "" {
		// No host name set yet; nothing to do.
		return
	}

	c.selectNewMessageID()

	info := &msgInfo{
		buf: make([]byte, 0, 512),
	}

	err := c.prepareUpdateMessage(info)
	if err != nil {
		c.handleSendFailure()
		return
	}

	// Transition states for items included in this message.
	c.changeHostAndServiceStates(&newStateOnMessageTx, info.singleServiceMode)
	c.setState(StateUpdating)
	c.attemptEpoch++
	attempt := c.attemptEpoch

	// A sender may synchronously deliver a response or call lifecycle APIs.
	// Snapshot ownership before releasing the lock, not when it returns.
	sender, destination := c.sender, c.serverAddr
	c.mu.Unlock()
	var sendErr error = errors.ErrInvalidState
	if sender != nil {
		sendErr = sender.Send(info.buf, destination)
	}
	c.mu.Lock()
	if c.attemptEpoch != attempt || c.state != StateUpdating {
		return // Response/Stop/Pause/clear superseded this send.
	}
	if sendErr != nil {
		c.handleSendFailure()
		return
	}

	c.txFailureRetryCount = 0
	c.scheduleResponseDeadline()
}

// handleSendFailure handles a failed message send or build.
func (c *Client) handleSendFailure() {
	// Preserve the baseline terminal callback for local build/send failures.
	c.failAttempt(errors.ErrFailed, false)
}

// prepareUpdateMessage builds the DNS Update message in info.buf.
func (c *Client) prepareUpdateMessage(info *msgInfo) error {
	return c.encodeUpdateMessage(info, true)
}

func (c *Client) encodeUpdateMessage(info *msgInfo, sign bool) error {
	// --- Header ---
	header := dns.NewUpdateHeader()
	header.MessageID = c.curMessageID
	header.SetZoneCount(1)
	// SIG(0) covers the header before adding SIG itself: the OPT already
	// counts as one additional record (RFC2931 section 3.1).
	header.ARCount = 1
	headerBytes := header.MarshalBinary()
	info.buf = append(info.buf, headerBytes[:]...)

	// --- Zone section ---
	// Zone name: domain name
	var err error
	info.buf, err = dns.AppendName(info.buf, c.domainName)
	if err != nil {
		return err
	}
	info.domainNameOffset = uint16(dns.HeaderSize) // right after the header
	zone := dns.NewZone()
	zoneBytes := zone.MarshalBinary()
	info.buf = append(info.buf, zoneBytes[:]...)

	// --- Prerequisites section (empty for SRP) ---
	// No prerequisites.

	// --- Update section ---
	info.recordCount = 0

	// Append service instructions.
	err = c.appendServiceInstructions(info)
	if err != nil {
		return err
	}

	// Append host description instruction.
	err = c.appendHostDescriptionInstruction(info)
	if err != nil {
		return err
	}

	// Update the header's update (NS) count.
	binary.BigEndian.PutUint16(info.buf[8:10], info.recordCount)

	// --- Additional section ---
	// OPT record (EDNS) with lease option.
	err = c.appendUpdateLeaseOptRecord(info)
	if err != nil {
		return err
	}

	// SIG(0) record — first pass: empty signature.
	err = c.appendSignature(info, false)
	if err != nil {
		return err
	}

	// SIG(0) record — second pass: compute and overwrite signature.
	if sign {
		err = c.appendSignature(info, true)
		if err != nil {
			return err
		}
	}

	// Set AR count to 2 (OPT + SIG).
	binary.BigEndian.PutUint16(info.buf[10:12], 2)

	return nil
}

// appendServiceInstructions appends PTR, SRV, and TXT records for
// all services that need updating.
func (c *Client) appendServiceInstructions(info *msgInfo) error {
	info.singleServiceMode = c.singleServiceUpdates
	for _, svc := range c.services {
		svc.appendedInMessage = false
	}
	if c.hostInfo.State == ItemStateToRemove || c.hostInfo.State == ItemStateRemoving {
		// Host lease zero withdraws all its services. The ACK covers every
		// owned service even though no individual service record is needed.
		for _, svc := range c.services {
			svc.appendedInMessage = true
		}
		return nil
	}

	for _, svc := range c.services {
		if !c.canAppendService(svc) {
			continue
		}
		if c.singleServiceUpdates {
			c.lease = c.determineLeaseInterval(svc.Lease, c.defaultLease)
			c.keyLease = c.determineLeaseInterval(svc.KeyLease, c.defaultKeyLease)
		}

		// Try to append the service. If the message gets too large,
		// revert and switch to single-service mode.
		savedLen := len(info.buf)
		savedCount := info.recordCount

		err := c.appendServiceInstruction(svc, info)
		if err != nil {
			// Message too large or other error.
			info.buf = info.buf[:savedLen]
			info.recordCount = savedCount

			if !info.singleServiceMode {
				// Switch to single-service mode: revert all services
				// except this one.
				info.singleServiceMode = true
				c.changeHostAndServiceStates(&newStateOnSingleServiceMode, false)
				svc.appendedInMessage = false

				// Retry with just this service.
				err = c.appendServiceInstruction(svc, info)
				if err != nil {
					return err
				}
			} else {
				return err
			}
		}

		svc.appendedInMessage = true
		if c.singleServiceUpdates {
			break
		}
	}

	return nil
}

// canAppendService returns true if the service should be included in
// the current update message.
func (c *Client) canAppendService(svc *Service) bool {
	switch svc.State {
	case ItemStateToAdd, ItemStateAdding,
		ItemStateToRefresh, ItemStateRefreshing,
		ItemStateToRemove, ItemStateRemoving:
		return true
	default:
		return false
	}
}

// appendServiceInstruction appends the DNS Update records for a
// single service: PTR, SRV, TXT, and optional sub-type PTRs.
func (c *Client) appendServiceInstruction(svc *Service, info *msgInfo) error {
	isRemove := svc.State == ItemStateToRemove || svc.State == ItemStateRemoving

	// Service instance full name: "InstanceName.ServiceName.DomainName"
	// Service name full name: "ServiceName.DomainName"

	// --- Append PTR record: ServiceName -> InstanceName.ServiceName ---
	// Owner name: service name (e.g., "_chip._udp.default.service.arpa.")
	serviceNameOffset := uint16(len(info.buf))
	info.buf = appendServiceName(info.buf, svc.Name, info.domainNameOffset)

	// PTR owner is followed immediately by the RR header, then its RDATA.
	var ptr dns.ResourceRecord
	ptr.Init(dns.RRTypePtr, dns.ClassInternet)
	ptr.TTL = c.determineTTL()
	if isRemove {
		ptr.Class = dns.ClassNone
		ptr.TTL = 0
	}
	ptrOffset := len(info.buf)
	ptrBytes := ptr.MarshalBinary()
	info.buf = append(info.buf, ptrBytes[:]...)

	// Instance name full: "InstanceName.ServiceName", in the PTR RDATA.
	instanceNameOffset := uint16(len(info.buf))
	var err error
	info.buf, err = dns.AppendLabel(info.buf, svc.InstanceName)
	if err != nil {
		return err
	}
	info.buf, err = dns.AppendPointerLabel(info.buf, serviceNameOffset)
	if err != nil {
		return err
	}

	binary.BigEndian.PutUint16(info.buf[ptrOffset+8:], uint16(len(info.buf)-int(instanceNameOffset)))
	info.recordCount++

	if !isRemove {
		// --- Sub-type PTR records ---
		for _, subType := range svc.SubTypeLabels {
			// Owner name: SubType._sub.ServiceName.DomainName.
			info.buf, err = dns.AppendLabel(info.buf, subType)
			if err != nil {
				return err
			}
			info.buf, err = dns.AppendLabel(info.buf, "_sub")
			if err != nil {
				return err
			}
			info.buf, err = dns.AppendPointerLabel(info.buf, serviceNameOffset)
			if err != nil {
				return err
			}

			var rr dns.ResourceRecord
			rr.Init(dns.RRTypePtr, dns.ClassInternet)
			rr.TTL = c.determineTTL()
			rrOffset := len(info.buf)
			rrBytes := rr.MarshalBinary()
			info.buf = append(info.buf, rrBytes[:]...)

			// RDATA: pointer to instance name.
			info.buf, err = dns.AppendPointerLabel(info.buf, instanceNameOffset)
			if err != nil {
				return err
			}

			rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
			binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)
			info.recordCount++
		}
	}

	if !isRemove {
		// RFC9665 service adds clear existing RRsets before SRV/TXT adds.
		info.buf, err = dns.AppendPointerLabel(info.buf, instanceNameOffset)
		if err != nil {
			return err
		}
		var clearRecord dns.ResourceRecord
		clearRecord.Init(dns.RRTypeAny, dns.ClassAny)
		clearBytes := clearRecord.MarshalBinary()
		info.buf = append(info.buf, clearBytes[:]...)
		info.recordCount++
	}

	// --- SRV record ---
	// Owner name: instance name (compressed).
	info.buf, err = dns.AppendPointerLabel(info.buf, instanceNameOffset)
	if err != nil {
		return err
	}

	if isRemove {
		// Delete all RRsets for this name: Type=ANY, Class=ANY.
		var rr dns.ResourceRecord
		rr.Init(dns.RRTypeAny, dns.ClassAny)
		rr.TTL = 0
		rr.RDLength = 0
		rrBytes := rr.MarshalBinary()
		info.buf = append(info.buf, rrBytes[:]...)
		info.recordCount++
	} else {
		var srv dns.SrvRecord
		srv.Init(dns.ClassInternet)
		srv.TTL = c.determineTTL()
		srv.Priority = svc.Priority
		srv.Weight = svc.Weight
		srv.Port = svc.Port

		rrOffset := len(info.buf)
		srvBytes := srv.MarshalBinary()
		info.buf = append(info.buf, srvBytes...)

		// Target: host name (compressed or full).
		err = c.appendHostName(info, false)
		if err != nil {
			return err
		}

		rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
		binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)
		info.recordCount++
	}

	// --- TXT record (only for add/refresh) ---
	if !isRemove {
		// Owner name: instance name (compressed).
		info.buf, err = dns.AppendPointerLabel(info.buf, instanceNameOffset)
		if err != nil {
			return err
		}

		var rr dns.ResourceRecord
		rr.Init(dns.RRTypeTxt, dns.ClassInternet)
		rr.TTL = c.determineTTL()

		rrOffset := len(info.buf)
		rrBytes := rr.MarshalBinary()
		info.buf = append(info.buf, rrBytes[:]...)

		// RDATA: TXT entries.
		if len(svc.TxtEntries) > 0 {
			info.buf, err = dns.AppendTxtEntries(info.buf, svc.TxtEntries)
			if err != nil {
				return err
			}
		} else {
			// Empty TXT record: single zero-length string.
			info.buf = append(info.buf, 0)
		}

		rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
		binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)
		info.recordCount++
	}

	return nil
}

// appendHostDescriptionInstruction appends the host description
// records: delete-all-rrsets (if needed), AAAA records, and KEY record.
func (c *Client) appendHostDescriptionInstruction(info *msgInfo) error {
	isRemove := c.hostInfo.State == ItemStateToRemove || c.hostInfo.State == ItemStateRemoving
	var err error

	// --- Delete all existing RRsets for the host name ---
	err = c.appendDeleteAllRrsets(info)
	if err != nil {
		return err
	}

	if !isRemove {
		// --- AAAA records for each address ---
		for _, addr := range c.hostInfo.Addresses {
			err = c.appendAaaaRecord(addr, info)
			if err != nil {
				return err
			}
		}
	}

	// --- KEY record ---
	err = c.appendKeyRecord(info)
	if err != nil {
		return err
	}

	return nil
}

// appendDeleteAllRrsets appends a "delete all RRsets" prerequisite
// for the host name. This tells the server to remove all existing
// records for this host before applying the update.
func (c *Client) appendDeleteAllRrsets(info *msgInfo) error {
	var err = c.appendHostName(info, false)
	if err != nil {
		return err
	}

	var rr dns.ResourceRecord
	rr.Init(dns.RRTypeAny, dns.ClassAny)
	rr.TTL = 0
	rr.RDLength = 0
	rrBytes := rr.MarshalBinary()
	info.buf = append(info.buf, rrBytes[:]...)
	info.recordCount++

	return nil
}

// appendAaaaRecord appends a single AAAA record for the given address.
func (c *Client) appendAaaaRecord(addr ip6.Address, info *msgInfo) error {
	var err = c.appendHostName(info, false)
	if err != nil {
		return err
	}

	var rr dns.ResourceRecord
	rr.Init(dns.RRTypeAaaa, dns.ClassInternet)
	rr.TTL = c.determineTTL()
	rr.RDLength = 16

	rrBytes := rr.MarshalBinary()
	info.buf = append(info.buf, rrBytes[:]...)

	// RDATA: 16-byte IPv6 address.
	info.buf = append(info.buf, addr[:]...)
	info.recordCount++

	return nil
}

// appendKeyRecord appends the KEY record with the client's public key.
func (c *Client) appendKeyRecord(info *msgInfo) error {
	var err = c.appendHostName(info, false)
	if err != nil {
		return err
	}

	var key dns.KeyRecord
	key.Init(dns.ClassInternet)
	key.TTL = c.determineTTL()
	key.SetFlags(dns.KeyUseAuthConfidPermitted, dns.KeyOwnerNonZone, 0)
	key.Protocol = dns.KeyProtocolDnsSec
	key.Algorithm = dns.KeyAlgorithmEcdsaP256Sha256

	rrOffset := len(info.buf)
	keyBytes := key.MarshalBinary()
	info.buf = append(info.buf, keyBytes...)

	// RDATA (continued): 64-byte ECDSA P-256 public key.
	pubKey := c.keyPair.GetPublicKey()
	info.buf = append(info.buf, pubKey[:]...)

	rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
	binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)
	info.recordCount++

	return nil
}

// appendHostName appends the host name (hostname.domainname) to the
// buffer, using DNS name compression when possible and doNotCompress
// is false.
func (c *Client) appendHostName(info *msgInfo, doNotCompress bool) error {
	var err error

	if !doNotCompress && info.hostNameOffset != 0 {
		// Compress: pointer to previously written host name.
		info.buf, err = dns.AppendPointerLabel(info.buf, info.hostNameOffset)
		return err
	}

	// Record the offset for future compression.
	if info.hostNameOffset == 0 {
		info.hostNameOffset = uint16(len(info.buf))
	}

	// Host name label.
	info.buf, err = dns.AppendLabel(info.buf, c.hostInfo.Name)
	if err != nil {
		return err
	}

	if !doNotCompress && info.domainNameOffset != 0 {
		// Compress domain part.
		info.buf, err = dns.AppendPointerLabel(info.buf, info.domainNameOffset)
		return err
	}

	// Full domain name (uncompressed).
	info.buf, err = dns.AppendName(info.buf, c.domainName)
	return err
}

// appendUpdateLeaseOptRecord appends the EDNS OPT record with the
// Update Lease option.
func (c *Client) appendUpdateLeaseOptRecord(info *msgInfo) error {
	// OPT record: root name (0x00), then OPT RR.
	info.buf = append(info.buf, 0x00) // root name

	var opt dns.OptRecord
	opt.Init()
	opt.SetUDPPayloadSize(UDPPayloadSize)

	rrOffset := len(info.buf)
	optBytes := opt.MarshalBinary()
	info.buf = append(info.buf, optBytes[:]...)

	// Lease option.
	leaseInterval := c.determineLeaseInterval(c.lease, c.defaultLease)
	keyLeaseInterval := c.determineLeaseInterval(c.keyLease, c.defaultKeyLease)
	if c.hostInfo.State == ItemStateToRemove || c.hostInfo.State == ItemStateRemoving {
		leaseInterval = 0
	}

	if c.shouldRemoveKeyLease {
		keyLeaseInterval = 0
	}

	var leaseOpt dns.LeaseOption
	if leaseInterval == keyLeaseInterval {
		leaseOpt.InitShort(leaseInterval)
	} else {
		leaseOpt.InitLong(leaseInterval, keyLeaseInterval)
	}

	leaseBytes := leaseOpt.MarshalBinary()
	info.buf = append(info.buf, leaseBytes...)

	// Update RDLength for OPT record.
	rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
	binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)

	return nil
}

// appendSignature appends the SIG(0) record to the message.
//
// When overwrite is false (first pass): appends a placeholder SIG
// record with 64 zero bytes for the signature, records sigRecordOffset.
//
// When overwrite is true (second pass): truncates back to
// sigRecordOffset, computes the signature over:
//  1. SIG RR RDATA (with uncompressed/canonical signer name)
//  2. The DNS message from offset 0 to sigRecordOffset
//
// Then writes the final SIG record with the actual signature.
func (c *Client) appendSignature(info *msgInfo, overwrite bool) error {
	if !overwrite {
		// --- First pass: placeholder ---
		info.sigRecordOffset = len(info.buf)

		// Root name as owner.
		info.buf = append(info.buf, 0x00)

		var sig dns.SigRecord
		sig.Init(dns.ClassAny)
		sig.TypeCovered = 0 // SIG(0)
		sig.Algorithm = dns.KeyAlgorithmEcdsaP256Sha256
		sig.Labels = 0
		sig.OriginalTTL = 0
		sig.Expiration = 0
		sig.Inception = 0
		sig.KeyTag = 0

		rrOffset := len(info.buf)
		sigBytes := sig.MarshalBinary()
		info.buf = append(info.buf, sigBytes...)

		// Signer name: host name (compressed).
		err := c.appendHostName(info, false)
		if err != nil {
			return err
		}

		// Placeholder signature: 64 zero bytes.
		info.buf = append(info.buf, make([]byte, ecdsa.SignatureSize)...)

		// Update RDLength.
		rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
		binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)

		return nil
	}

	// --- Second pass: compute signature ---
	// Build the SIG RDATA with UNCOMPRESSED (canonical) signer name
	// for hash computation.

	var sig dns.SigRecord
	sig.Init(dns.ClassAny)
	sig.TypeCovered = 0
	sig.Algorithm = dns.KeyAlgorithmEcdsaP256Sha256
	sig.Labels = 0
	sig.OriginalTTL = 0
	sig.Expiration = 0
	sig.Inception = 0
	sig.KeyTag = 0

	sigBytes := sig.MarshalBinary()

	// SIG RDATA for hashing: skip the ResourceRecord header (10 bytes),
	// use only the SIG-specific fields + canonical signer name.
	sigRData := make([]byte, 0, 128)
	sigRData = append(sigRData, sigBytes[dns.ResourceRecordSize:]...) // SIG fields (18 bytes)

	// Canonical (uncompressed) signer name: hostname.domainname
	var err error
	sigRData, err = dns.AppendLabel(sigRData, c.hostInfo.Name)
	if err != nil {
		return err
	}
	sigRData, err = dns.AppendName(sigRData, c.domainName)
	if err != nil {
		return err
	}
	canonical, err := canonicalSignerName(sigRData, dns.SigRecordFixedSize)
	if err != nil {
		return err
	}
	sigRData = append(sigRData[:dns.SigRecordFixedSize], canonical...)

	// Hash: SHA-256(SIG RDATA || message[0:sigRecordOffset])
	var h sha256.Sha256
	h.Start()
	h.Update(sigRData)
	h.Update(info.buf[:info.sigRecordOffset])
	var hash sha256.Hash
	h.Finish(&hash)

	// Sign the hash.
	var signature ecdsa.Signature
	if c.entropy != nil {
		signature, err = c.keyPair.SignWithReader(hash, c.entropy)
	} else {
		signature, err = c.keyPair.Sign(hash)
	}
	if err != nil {
		return err
	}

	// --- Rewrite from sigRecordOffset ---
	info.buf = info.buf[:info.sigRecordOffset]

	// Root name as owner.
	info.buf = append(info.buf, 0x00)

	rrOffset := len(info.buf)
	info.buf = append(info.buf, sigBytes...)

	// Signer name: compressed host name.
	err = c.appendHostName(info, false)
	if err != nil {
		return err
	}

	// Actual signature.
	info.buf = append(info.buf, signature[:]...)

	// Update RDLength.
	rdataLen := uint16(len(info.buf) - rrOffset - int(dns.ResourceRecordSize))
	binary.BigEndian.PutUint16(info.buf[rrOffset+8:], rdataLen)

	return nil
}

// appendServiceName appends "serviceName.domainName" using a pointer
// for the domain part if domainOffset is known.
func appendServiceName(buf []byte, serviceName string, domainOffset uint16) []byte {
	// Service name is like "_chip._udp" — may have multiple labels.
	var err error
	buf, err = dns.AppendMultipleLabels(buf, serviceName)
	if err != nil {
		// If the labels can't be appended, this is a programming error.
		// In production this shouldn't happen with valid service names.
		return buf
	}

	if domainOffset != 0 {
		buf, _ = dns.AppendPointerLabel(buf, domainOffset)
	} else {
		buf = dns.AppendTerminator(buf)
	}

	return buf
}

// -------------------------------------------------------
// Internal — response processing
// -------------------------------------------------------

// HandleResponse processes a DNS response from the SRP server.
// This is the externally-callable entry point (e.g., from UDP receive).
func (c *Client) HandleResponse(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processResponse(data)
}

// processResponse processes a DNS response message.
func (c *Client) processResponse(data []byte) {
	if c.state != StateUpdating {
		return
	}

	if len(data) < dns.HeaderSize {
		return
	}

	var header dns.Header
	if err := header.UnmarshalBinary(data); err != nil {
		return
	}

	// Verify this is a response to our message.
	if header.MessageID != c.curMessageID {
		return
	}

	if header.GetType() != dns.TypeResponse || header.GetOpCode() != dns.OpcodeUpdate ||
		header.IsTruncated() || header.QDCount > 1 {
		return
	}

	rc := header.GetResponseCode()

	if rc == dns.RcodeSuccess {
		// Process OPT record to extract granted lease.
		if err := c.processResponseRecords(data, &header); err != nil {
			return // Malformed input cannot cancel the actual response deadline.
		}
		c.handleUpdateDone()
		return
	}

	// Server rejected the update.
	c.failAttempt(dns.ResponseCodeToError(rc), true)
}

// processResponseRecords scans the additional section for an OPT
// record containing lease information.
func (c *Client) processResponseRecords(data []byte, header *dns.Header) error {
	// Skip past question/zone, answer/prerequisite, and authority/update
	// sections to reach the additional section.
	offset := dns.HeaderSize

	// Skip zone (QD) section.
	for i := uint16(0); i < header.QDCount; i++ {
		newOff, err := dns.SkipName(data, offset)
		if err != nil {
			return errors.ErrParse
		}
		offset = newOff + int(dns.QuestionSize)
		if offset > len(data) {
			return errors.ErrParse
		}
	}

	// Skip answer (AN) section.
	for i := uint16(0); i < header.ANCount; i++ {
		offset = c.skipRecord(data, offset)
		if offset < 0 {
			return errors.ErrParse
		}
	}

	// Skip authority (NS) section.
	for i := uint16(0); i < header.NSCount; i++ {
		offset = c.skipRecord(data, offset)
		if offset < 0 {
			return errors.ErrParse
		}
	}

	// Validate the full response before committing any granted lease state.
	var leaseOption *dns.LeaseOption
	for i := uint16(0); i < header.ARCount; i++ {
		savedOffset := offset

		// Skip name.
		newOff, err := dns.SkipName(data, offset)
		if err != nil {
			return errors.ErrParse
		}
		offset = newOff

		if offset+int(dns.ResourceRecordSize) > len(data) {
			return errors.ErrParse
		}

		var rr dns.ResourceRecord
		if err := rr.UnmarshalBinary(data[offset:]); err != nil {
			return errors.ErrParse
		}

		if rr.Type == dns.RRTypeOpt {
			// Found OPT record; look for lease option in RDATA.
			rdataStart := offset + int(dns.ResourceRecordSize)
			rdataEnd := rdataStart + int(rr.RDLength)
			if rdataEnd > len(data) {
				return errors.ErrParse
			}
			// Check option framing even when no lease option is present.
			for optionOffset := rdataStart; optionOffset < rdataEnd; {
				if rdataEnd-optionOffset < dns.OptionSize {
					return errors.ErrParse
				}
				var option dns.Option
				if err := option.UnmarshalBinary(data[optionOffset:rdataEnd]); err != nil {
					return errors.ErrParse
				}
				if option.GetSize() > rdataEnd-optionOffset {
					return errors.ErrParse
				}
				if option.Code == dns.OptionCodeUpdateLease {
					if leaseOption != nil {
						return errors.ErrParse
					}
					leaseOption = &dns.LeaseOption{}
					if err := leaseOption.UnmarshalBinary(data[optionOffset:rdataEnd]); err != nil ||
						!leaseOption.IsValid() {
						return errors.ErrParse
					}
				}
				optionOffset += option.GetSize()
			}
		}

		offset = savedOffset
		offset = c.skipRecord(data, offset)
		if offset < 0 {
			return errors.ErrParse
		}
	}
	if offset != len(data) {
		return errors.ErrParse
	}
	if leaseOption == nil {
		// A successful bare response accepts the requested/default lease.
		c.setGrantedLease(c.determineLeaseInterval(c.lease, c.defaultLease),
			c.determineLeaseInterval(c.keyLease, c.defaultKeyLease))
	} else {
		c.setGrantedLease(leaseOption.LeaseInterval, leaseOption.KeyLeaseInterval)
	}
	return nil
}

func (c *Client) setGrantedLease(lease, keyLease uint32) {
	c.lease = lease
	c.keyLease = keyLease
	c.leaseRenewTime = time.Time{}

	// Cap lease values.
	if c.lease > MaxLease {
		c.lease = MaxLease
	}
	if c.keyLease > MaxLease {
		c.keyLease = MaxLease
	}

	// Calculate lease renewal time.
	if c.lease > 0 {
		renewSecs := c.lease
		if renewSecs > LeaseRenewGuardInterval {
			renewSecs -= LeaseRenewGuardInterval
		}
		// Apply early renewal fraction.
		renewSecs = renewSecs * EarlyLeaseRenewNumerator / EarlyLeaseRenewDenominator

		jitterMs := c.randUint32(LeaseRenewJitter)
		renewDuration := time.Duration(renewSecs)*time.Second + time.Duration(jitterMs)*time.Millisecond
		c.leaseRenewTime = c.now().Add(renewDuration)
	}
}

// skipRecord skips over a single DNS resource record (name + RR header + RDATA).
// Returns the new offset, or -1 on error.
func (c *Client) skipRecord(data []byte, offset int) int {
	newOff, err := dns.SkipName(data, offset)
	if err != nil {
		return -1
	}
	offset = newOff

	if offset+int(dns.ResourceRecordSize) > len(data) {
		return -1
	}

	var rr dns.ResourceRecord
	if err := rr.UnmarshalBinary(data[offset:]); err != nil {
		return -1
	}
	offset += int(dns.ResourceRecordSize)
	offset += int(rr.RDLength)
	if offset > len(data) {
		return -1
	}
	return offset
}

// -------------------------------------------------------
// Internal — update completion and retry
// -------------------------------------------------------

// handleUpdateDone applies ONLY an accepted, matching, valid update response.
func (c *Client) handleUpdateDone() {
	c.cancelAttempt()

	// Apply state transitions for successful update.
	c.changeHostAndServiceStates(&newStateOnUpdateDone, false)

	c.retryWaitInterval = 0
	c.txFailureRetryCount = 0
	c.setState(StateUpdated)
	if c.hostInfo.State == ItemStateRemoved {
		c.leaseRenewTime = time.Time{}
	}

	// Check if there are more items to update.
	if c.hostInfo.State != ItemStateRemoved {
		c.updateState()
	}

	// Invoke callback with success.
	c.invokeCallback(nil)
}

// growRetryWaitInterval grows the retry wait interval using
// exponential backoff.
func (c *Client) growRetryWaitInterval() {
	if c.retryWaitInterval == 0 {
		c.retryWaitInterval = MinRetryWaitInterval
	} else {
		c.retryWaitInterval = c.retryWaitInterval * RetryGrowthNumerator / RetryGrowthDenominator
		if c.retryWaitInterval > MaxRetryWaitInterval {
			c.retryWaitInterval = MaxRetryWaitInterval
		}
	}
}

// -------------------------------------------------------
// Internal — helpers
// -------------------------------------------------------

// selectNewMessageID preserves random nonzero IDs and excludes only the previous
// ID, as in OpenThread. A deterministic RNG collision uses one bounded fallback
// rather than spinning. Local epochs protect callbacks, not indefinite stale
// wire replies after a 16-bit ID is eventually reused.
func (c *Client) selectNewMessageID() {
	previous := c.curMessageID
	c.curMessageID = uint16(c.randUint32(0xffff)) + 1
	if c.curMessageID == previous {
		c.curMessageID++
		if c.curMessageID == 0 {
			c.curMessageID = 1
		}
	}
}

// determineLeaseInterval returns the lease interval to use, taking
// into account per-service overrides and client defaults.
func (c *Client) determineLeaseInterval(interval, defaultInterval uint32) uint32 {
	if interval != UnspecifiedInterval {
		return interval
	}
	if defaultInterval != UnspecifiedInterval {
		return defaultInterval
	}
	return DefaultLease
}

// determineTTL returns the TTL to use for records.
func (c *Client) determineTTL() uint32 {
	if c.ttl != 0 {
		return c.ttl
	}
	// Default: use the lease interval.
	lease := c.determineLeaseInterval(c.lease, c.defaultLease)
	return lease
}
