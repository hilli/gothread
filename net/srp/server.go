// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the conditions in the
// LICENSE file are met.

package srp

import (
	"encoding/binary"
	"strings"
	"sync"
	"time"

	"github.com/hilli/gothread/crypto/ecdsa"
	"github.com/hilli/gothread/crypto/sha256"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
)

// -------------------------------------------------------
// Server constants
// -------------------------------------------------------

const (
	// DefaultMinLease is the default minimum lease in seconds (30s).
	DefaultMinLease uint32 = 30

	// DefaultMaxLease is the default maximum lease in seconds (27 hours).
	DefaultMaxLease uint32 = 97200

	// DefaultMinKeyLease is the default minimum key-lease in seconds (30s).
	DefaultMinKeyLease uint32 = 30

	// DefaultMaxKeyLease is the default maximum key-lease in seconds (~7.9 days).
	DefaultMaxKeyLease uint32 = 680400

	// DefaultMinTTL is the default minimum TTL in seconds (30s).
	DefaultMinTTL uint32 = 30

	// DefaultMaxTTL is the default maximum TTL in seconds (27 hours).
	DefaultMaxTTL uint32 = 97200

	// DefaultHandlerTimeout is the default service update handler timeout (ms).
	DefaultHandlerTimeout = 1250 * time.Millisecond

	// ServerDefaultDomain is the default SRP server domain.
	ServerDefaultDomain = "default.service.arpa."

	// serviceSubTypeLabel is the sub-type separator.
	serviceSubTypeLabel = "._sub."

	// serverUDPPortMin is the minimum UDP port in the range.
	serverUDPPortMin uint16 = 53535

	// serverUDPPortMax is the maximum UDP port in the range.
	serverUDPPortMax uint16 = 53554
)

// -------------------------------------------------------
// Server enums
// -------------------------------------------------------

// ServerState represents the server state.
type ServerState uint8

const (
	// ServerStateDisabled means the server is disabled.
	ServerStateDisabled ServerState = iota
	// ServerStateStopped means the server is enabled but not running.
	ServerStateStopped
	// ServerStateRunning means the server is running and accepting updates.
	ServerStateRunning
)

// String returns the string representation of a ServerState.
func (s ServerState) String() string {
	switch s {
	case ServerStateDisabled:
		return "Disabled"
	case ServerStateStopped:
		return "Stopped"
	case ServerStateRunning:
		return "Running"
	default:
		return "Unknown"
	}
}

// AddressMode represents how the SRP server address is published.
type AddressMode uint8

const (
	// AddressModeUnicast publishes the server's unicast address.
	AddressModeUnicast AddressMode = iota
	// AddressModeAnycast publishes an anycast address.
	AddressModeAnycast
)

// -------------------------------------------------------
// TTL and Lease configuration
// -------------------------------------------------------

// TTLConfig holds the min/max TTL values for the server.
type TTLConfig struct {
	MinTTL uint32 // Minimum TTL in seconds.
	MaxTTL uint32 // Maximum TTL in seconds.
}

// DefaultTTLConfig returns a TTLConfig with default values.
func DefaultTTLConfig() TTLConfig {
	return TTLConfig{MinTTL: DefaultMinTTL, MaxTTL: DefaultMaxTTL}
}

// IsValid returns true if the config is valid (min <= max).
func (c *TTLConfig) IsValid() bool {
	return c.MinTTL <= c.MaxTTL
}

// GrantTTL clamps a requested TTL to the configured range,
// also capping at the granted lease value.
func (c *TTLConfig) GrantTTL(lease, ttl uint32) uint32 {
	if ttl > lease {
		ttl = lease
	}
	return clampU32(ttl, c.MinTTL, c.MaxTTL)
}

// LeaseConfig holds the min/max lease and key-lease values.
type LeaseConfig struct {
	MinLease    uint32 // Minimum lease in seconds.
	MaxLease    uint32 // Maximum lease in seconds.
	MinKeyLease uint32 // Minimum key-lease in seconds.
	MaxKeyLease uint32 // Maximum key-lease in seconds.
}

// DefaultLeaseConfig returns a LeaseConfig with default values.
func DefaultLeaseConfig() LeaseConfig {
	return LeaseConfig{
		MinLease:    DefaultMinLease,
		MaxLease:    DefaultMaxLease,
		MinKeyLease: DefaultMinKeyLease,
		MaxKeyLease: DefaultMaxKeyLease,
	}
}

// IsValid returns true if the config is valid.
func (c *LeaseConfig) IsValid() bool {
	return c.MinLease <= c.MaxLease &&
		c.MinKeyLease <= c.MaxKeyLease &&
		c.MinLease <= c.MinKeyLease &&
		c.MaxLease <= c.MaxKeyLease
}

// GrantLease clamps a requested lease to the configured range.
// If lease is 0 (deletion), returns 0.
func (c *LeaseConfig) GrantLease(lease uint32) uint32 {
	if lease == 0 {
		return 0
	}
	return clampU32(lease, c.MinLease, c.MaxLease)
}

// GrantKeyLease clamps a requested key-lease to the configured range.
// If keyLease is 0 (full removal), returns 0.
func (c *LeaseConfig) GrantKeyLease(keyLease uint32) uint32 {
	if keyLease == 0 {
		return 0
	}
	return clampU32(keyLease, c.MinKeyLease, c.MaxKeyLease)
}

// -------------------------------------------------------
// Registered Service
// -------------------------------------------------------

// RegService represents a registered service instance on the SRP server.
type RegService struct {
	InstanceName  string    // Full instance name (e.g., "My Printer._ipp._tcp.default.service.arpa.").
	InstanceLabel string    // Instance label only (e.g., "My Printer").
	ServiceName   string    // Service type name (e.g., "_ipp._tcp.default.service.arpa.").
	SubTypes      []string  // Sub-type full names.
	TxtData       []byte    // Raw TXT record data.
	Priority      uint16    // SRV priority.
	Weight        uint16    // SRV weight.
	Port          uint16    // SRV port.
	TTL           uint32    // TTL in seconds.
	Lease         uint32    // Lease in seconds (0 = deleted).
	KeyLease      uint32    // Key-lease in seconds.
	UpdateTime    time.Time // When the service was last updated.
	IsDeleted     bool      // True if service is deleted but name retained.

	// Parsing state (used during update processing).
	parsedDeleteAllRRset bool
	parsedSrv            bool
	parsedTxt            bool
}

// GetExpireTime returns the time at which the lease expires.
func (s *RegService) GetExpireTime() time.Time {
	return s.UpdateTime.Add(time.Duration(s.Lease) * time.Second)
}

// GetKeyExpireTime returns the time at which the key-lease expires.
func (s *RegService) GetKeyExpireTime() time.Time {
	return s.UpdateTime.Add(time.Duration(s.KeyLease) * time.Second)
}

// MatchesInstanceName returns true if the instance name matches (case-insensitive).
func (s *RegService) MatchesInstanceName(name string) bool {
	return strings.EqualFold(s.InstanceName, name)
}

// MatchesServiceName returns true if the service name matches (case-insensitive).
func (s *RegService) MatchesServiceName(name string) bool {
	return strings.EqualFold(s.ServiceName, name)
}

// -------------------------------------------------------
// Registered Host
// -------------------------------------------------------

// RegHost represents a registered host on the SRP server.
type RegHost struct {
	FullName   string          // FQDN (e.g., "myhost.default.service.arpa.").
	Addresses  []ip6.Address   // IPv6 addresses.
	Key        ecdsa.PublicKey // ECDSA P-256 public key for SIG(0) verification.
	TTL        uint32          // TTL in seconds.
	Lease      uint32          // Lease in seconds (0 = deleted, name retained).
	KeyLease   uint32          // Key-lease in seconds (0 = fully removed).
	UpdateTime time.Time       // When the host was last updated.
	Services   []*RegService   // Services owned by this host.

	// Parsing state (used during update processing).
	parsedKey           bool
	useShortLeaseOption bool
}

// IsDeleted returns true if the host lease is 0 (deleted but name retained).
func (h *RegHost) IsDeleted() bool {
	return h.Lease == 0
}

// GetExpireTime returns the time at which the lease expires.
func (h *RegHost) GetExpireTime() time.Time {
	return h.UpdateTime.Add(time.Duration(h.Lease) * time.Second)
}

// GetKeyExpireTime returns the time at which the key-lease expires.
func (h *RegHost) GetKeyExpireTime() time.Time {
	return h.UpdateTime.Add(time.Duration(h.KeyLease) * time.Second)
}

// Matches returns true if the host full name matches (case-insensitive).
func (h *RegHost) Matches(name string) bool {
	return strings.EqualFold(h.FullName, name)
}

// FindService finds a service by instance name (case-insensitive).
func (h *RegHost) FindService(instanceName string) *RegService {
	for _, svc := range h.Services {
		if svc.MatchesInstanceName(instanceName) {
			return svc
		}
	}
	return nil
}

// LeaseInfo provides lease information in duration form.
type LeaseInfo struct {
	Lease             time.Duration
	KeyLease          time.Duration
	RemainingLease    time.Duration
	RemainingKeyLease time.Duration
}

// GetLeaseInfo computes lease information for a host.
func (h *RegHost) GetLeaseInfo(now time.Time) LeaseInfo {
	lease := time.Duration(h.Lease) * time.Second
	keyLease := time.Duration(h.KeyLease) * time.Second
	remaining := h.GetExpireTime().Sub(now)
	if remaining < 0 {
		remaining = 0
	}
	keyRemaining := h.GetKeyExpireTime().Sub(now)
	if keyRemaining < 0 {
		keyRemaining = 0
	}
	return LeaseInfo{
		Lease:             lease,
		KeyLease:          keyLease,
		RemainingLease:    remaining,
		RemainingKeyLease: keyRemaining,
	}
}

// -------------------------------------------------------
// Response counters
// -------------------------------------------------------

// ResponseCounters tracks SRP server response statistics.
type ResponseCounters struct {
	Success       uint32
	ServerFailure uint32
	FormatError   uint32
	NameExists    uint32
	Refused       uint32
	Other         uint32
}

// -------------------------------------------------------
// Service Update Handler interface
// -------------------------------------------------------

// ServiceUpdateHandler is called when the server has a new update to process.
// The handler receives the update ID, the host being updated, and a timeout.
// The handler must call Server.HandleServiceUpdateResult with the update ID
// and an error when processing is complete.
type ServiceUpdateHandler func(id uint32, host *RegHost, timeout time.Duration)

// -------------------------------------------------------
// UDPReceiver / UDPResponder interfaces
// -------------------------------------------------------

// UDPResponder sends a DNS response to a client.
type UDPResponder func(data []byte, peer ip6.SockAddr)

// -------------------------------------------------------
// Update metadata (tracks in-flight updates)
// -------------------------------------------------------

// updateMetadata tracks an in-flight update that has been passed to
// the service update handler.
type updateMetadata struct {
	id                 uint32
	dnsHeader          dns.UpdateHeader
	ttlConfig          TTLConfig
	leaseConfig        LeaseConfig
	host               *RegHost
	peer               ip6.SockAddr
	expireTime         time.Time
	err                error
	isDirectFromClient bool
	completed          bool
}

// -------------------------------------------------------
// messageMetadata (parsing context for a received message)
// -------------------------------------------------------

// messageMetadata holds context during DNS Update message parsing.
type messageMetadata struct {
	dnsHeader   dns.UpdateHeader
	zone        dns.Zone
	offset      int
	rxTime      time.Time
	ttlConfig   TTLConfig
	leaseConfig LeaseConfig
	peer        *ip6.SockAddr // nil when from SRPL partner.
}

// isDirectRxFromClient returns true if the message was received directly.
func (m *messageMetadata) isDirectRxFromClient() bool {
	return m.peer != nil
}

// -------------------------------------------------------
// Server
// -------------------------------------------------------

// Server is an SRP server that receives DNS Update messages,
// validates SIG(0) signatures, manages host/service registrations,
// and grants leases.
type Server struct {
	mu sync.Mutex

	state       ServerState
	domain      string
	port        uint16
	addressMode AddressMode

	ttlConfig   TTLConfig
	leaseConfig LeaseConfig

	hosts []*RegHost

	updateHandler      ServiceUpdateHandler
	outstandingUpdates []*updateMetadata
	completedUpdates   []*updateMetadata
	nextUpdateID       uint32

	leaseTimer  Timer
	updateTimer Timer
	responder   UDPResponder

	responseCounters ResponseCounters

	// Dependency injection for testing.
	now       func() time.Time
	afterFunc func(time.Duration, func()) Timer
}

// ServerOption is a functional option for configuring a Server.
type ServerOption func(*Server)

// WithServerNow injects a clock function for testing.
func WithServerNow(fn func() time.Time) ServerOption {
	return func(s *Server) { s.now = fn }
}

// WithServerAfterFunc injects a timer factory for testing.
func WithServerAfterFunc(fn func(time.Duration, func()) Timer) ServerOption {
	return func(s *Server) { s.afterFunc = fn }
}

// WithServerResponder sets the UDP responder for sending responses.
func WithServerResponder(fn UDPResponder) ServerOption {
	return func(s *Server) { s.responder = fn }
}

// NewServer creates a new SRP server with the given options.
func NewServer(opts ...ServerOption) *Server {
	s := &Server{
		state:       ServerStateDisabled,
		domain:      ServerDefaultDomain,
		ttlConfig:   DefaultTTLConfig(),
		leaseConfig: DefaultLeaseConfig(),
		now:         time.Now,
		afterFunc: func(d time.Duration, f func()) Timer {
			return &stdTimer{timer: time.AfterFunc(d, f)}
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// stdTimer wraps a standard library timer.
type stdTimer struct {
	timer *time.Timer
}

func (t *stdTimer) Stop() bool {
	return t.timer.Stop()
}

// -------------------------------------------------------
// Server public API
// -------------------------------------------------------

// GetState returns the current server state.
func (s *Server) GetState() ServerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// GetDomain returns the authorized domain.
func (s *Server) GetDomain() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.domain
}

// SetDomain sets the authorized domain. Can only be called when disabled.
func (s *Server) SetDomain(domain string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != ServerStateDisabled {
		return errors.ErrInvalidState
	}
	if domain == "" {
		return errors.ErrInvalidArgs
	}
	// Ensure trailing dot.
	if !strings.HasSuffix(domain, ".") {
		domain += "."
	}
	s.domain = domain
	return nil
}

// GetPort returns the current listening port (0 if not running).
func (s *Server) GetPort() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != ServerStateRunning {
		return 0
	}
	return s.port
}

// SetTTLConfig sets the TTL configuration.
func (s *Server) SetTTLConfig(config TTLConfig) error {
	if !config.IsValid() {
		return errors.ErrInvalidArgs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttlConfig = config
	return nil
}

// GetTTLConfig returns the current TTL configuration.
func (s *Server) GetTTLConfig() TTLConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ttlConfig
}

// SetLeaseConfig sets the lease configuration.
func (s *Server) SetLeaseConfig(config LeaseConfig) error {
	if !config.IsValid() {
		return errors.ErrInvalidArgs
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.leaseConfig = config
	return nil
}

// GetLeaseConfig returns the current lease configuration.
func (s *Server) GetLeaseConfig() LeaseConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leaseConfig
}

// SetServiceUpdateHandler sets the external service update handler.
func (s *Server) SetServiceUpdateHandler(handler ServiceUpdateHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updateHandler = handler
}

// GetHosts returns a snapshot of all registered hosts.
func (s *Server) GetHosts() []*RegHost {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*RegHost, len(s.hosts))
	copy(result, s.hosts)
	return result
}

// GetResponseCounters returns the response counters.
func (s *Server) GetResponseCounters() ResponseCounters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseCounters
}

// Enable enables or disables the server.
func (s *Server) Enable(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if enabled {
		s.enable()
	} else {
		s.disable()
	}
}

func (s *Server) enable() {
	if s.state != ServerStateDisabled {
		return
	}
	s.state = ServerStateStopped
}

func (s *Server) disable() {
	if s.state == ServerStateDisabled {
		return
	}
	if s.state == ServerStateRunning {
		s.stop()
	}
	s.state = ServerStateDisabled
}

// Start starts the server (transitions from Stopped to Running).
// port is the UDP port to listen on.
func (s *Server) Start(port uint16) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.start(port)
}

func (s *Server) start(port uint16) error {
	if s.state != ServerStateStopped {
		return errors.ErrInvalidState
	}
	s.port = port
	s.state = ServerStateRunning
	return nil
}

// Stop stops the server (transitions from Running to Stopped).
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
}

func (s *Server) stop() {
	if s.state != ServerStateRunning {
		return
	}

	// Cancel outstanding updates.
	for _, um := range s.outstandingUpdates {
		um.err = errors.ErrFailed
		um.completed = true
	}
	s.outstandingUpdates = nil
	s.completedUpdates = nil

	// Stop timers.
	if s.leaseTimer != nil {
		s.leaseTimer.Stop()
		s.leaseTimer = nil
	}
	if s.updateTimer != nil {
		s.updateTimer.Stop()
		s.updateTimer = nil
	}

	// Remove all hosts.
	s.hosts = nil

	s.state = ServerStateStopped
}

// -------------------------------------------------------
// HandleServiceUpdateResult - callback from handler
// -------------------------------------------------------

// HandleServiceUpdateResult is called by the service update handler
// when processing is complete for the given update ID.
func (s *Server) HandleServiceUpdateResult(id uint32, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.handleServiceUpdateResult(id, err)
}

func (s *Server) handleServiceUpdateResult(id uint32, err error) {
	// Find the update in the outstanding list.
	for i, um := range s.outstandingUpdates {
		if um.id == id {
			um.err = err
			um.completed = true
			// Move to completed list.
			s.outstandingUpdates = append(s.outstandingUpdates[:i], s.outstandingUpdates[i+1:]...)
			s.completedUpdates = append(s.completedUpdates, um)
			// Process completed updates asynchronously.
			s.processCompletedUpdatesAsync()
			return
		}
	}
	// Update not found (late callback), silently ignore.
}

func (s *Server) processCompletedUpdatesAsync() {
	// Process all completed updates immediately.
	for len(s.completedUpdates) > 0 {
		um := s.completedUpdates[0]
		s.completedUpdates = s.completedUpdates[1:]
		s.commitSrpUpdate(um.host, um.err, um.dnsHeader, um.ttlConfig, um.leaseConfig,
			um.isDirectFromClient, um.peer)
	}
}

// -------------------------------------------------------
// ProcessMessage - entry point for received DNS messages
// -------------------------------------------------------

// ProcessMessage processes a received DNS Update message.
// data is the raw UDP payload, peer is the source address.
func (s *Server) ProcessMessage(data []byte, peer ip6.SockAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != ServerStateRunning {
		return
	}

	s.processMessage(data, &peer)
}

func (s *Server) processMessage(data []byte, peer *ip6.SockAddr) {
	var meta messageMetadata
	meta.rxTime = s.now()
	meta.ttlConfig = s.ttlConfig
	meta.leaseConfig = s.leaseConfig
	meta.peer = peer

	// Parse the DNS header.
	if len(data) < dns.HeaderSize {
		return
	}
	if err := meta.dnsHeader.UnmarshalBinary(data); err != nil {
		return
	}

	// Must be a query with OpCode = Update.
	if meta.dnsHeader.GetType() != dns.TypeQuery {
		return
	}
	if meta.dnsHeader.GetOpCode() != dns.OpcodeUpdate {
		return
	}

	meta.offset = dns.HeaderSize
	s.processDnsUpdate(data, &meta)
}

// -------------------------------------------------------
// DNS Update processing
// -------------------------------------------------------

func (s *Server) processDnsUpdate(data []byte, meta *messageMetadata) {
	// Step 1: Process zone section.
	if err := s.processZoneSection(data, meta); err != nil {
		s.sendErrorResponse(meta.dnsHeader, errorToDnsResponseCode(err), meta.peer)
		return
	}

	// Step 2: Check for duplicate outstanding update.
	if s.findOutstandingUpdate(meta.dnsHeader.MessageID, meta.peer) != nil {
		return // Duplicate; silently drop.
	}

	// Step 3: Verify no prerequisites (per SRP draft section 2.3.2).
	if meta.dnsHeader.PrerequisiteCount() != 0 {
		s.sendErrorResponse(meta.dnsHeader, dns.RcodeFormatError, meta.peer)
		return
	}

	// Step 4: Allocate host and process update section.
	host := &RegHost{
		UpdateTime: meta.rxTime,
	}

	// Process update records (3 passes).
	if err := s.processUpdateSection(data, meta, host); err != nil {
		s.sendErrorResponse(meta.dnsHeader, errorToDnsResponseCode(err), meta.peer)
		return
	}

	// Step 5: Check for name conflicts.
	if err := s.hasNameConflictsWith(host); err != nil {
		s.sendErrorResponse(meta.dnsHeader, errorToDnsResponseCode(err), meta.peer)
		return
	}

	// Step 6: Process additional section (OPT + SIG(0)).
	if err := s.processAdditionalSection(data, meta, host); err != nil {
		s.sendErrorResponse(meta.dnsHeader, errorToDnsResponseCode(err), meta.peer)
		return
	}

	// Step 7: Handle the update.
	s.handleUpdate(data, meta, host)
}

// processZoneSection validates the zone section (exactly 1 zone, matching domain, SOA type).
func (s *Server) processZoneSection(data []byte, meta *messageMetadata) error {
	if meta.dnsHeader.ZoneCount() != 1 {
		return errors.ErrParse
	}

	// Read the zone name.
	zoneName, newOffset, err := dns.ReadName(data, meta.offset)
	if err != nil {
		return errors.ErrParse
	}

	// Read the zone record (Question format: type + class).
	if newOffset+dns.QuestionSize > len(data) {
		return errors.ErrParse
	}
	if err := meta.zone.UnmarshalBinary(data[newOffset:]); err != nil {
		return errors.ErrParse
	}
	meta.offset = newOffset + dns.QuestionSize

	// Verify zone matches server domain (case-insensitive).
	if !strings.EqualFold(zoneName, s.domain) {
		return errors.ErrSecurity
	}

	// Must be SOA type.
	if meta.zone.Type != dns.RRTypeSoa {
		return errors.ErrParse
	}

	return nil
}

// findOutstandingUpdate checks if a matching update is already in flight.
func (s *Server) findOutstandingUpdate(msgID uint16, peer *ip6.SockAddr) *updateMetadata {
	if peer == nil {
		return nil
	}
	for _, um := range s.outstandingUpdates {
		if um.dnsHeader.MessageID == msgID && um.peer == *peer {
			return um
		}
	}
	return nil
}

// processUpdateSection processes the update section in 3 passes.
func (s *Server) processUpdateSection(data []byte, meta *messageMetadata, host *RegHost) error {
	updateCount := int(meta.dnsHeader.UpdateCount())
	if updateCount == 0 {
		return errors.ErrParse
	}

	// Save offset at start of update section.
	startOffset := meta.offset

	// Pass 0: Process service discovery instructions (PTR records).
	meta.offset = startOffset
	if err := s.processServiceDiscoveryInstructions(data, meta, host, updateCount); err != nil {
		return err
	}

	// Pass 1: Process host description instruction (AAAA, KEY, delete-all).
	meta.offset = startOffset
	if err := s.processHostDescriptionInstruction(data, meta, host, updateCount); err != nil {
		return err
	}

	// Pass 2: Process service description instructions (SRV, TXT, delete-all for services).
	meta.offset = startOffset
	if err := s.processServiceDescriptionInstructions(data, meta, host, updateCount); err != nil {
		return err
	}

	return nil
}

// -------------------------------------------------------
// Pass 0: Service discovery instructions (PTR records)
// -------------------------------------------------------

func (s *Server) processServiceDiscoveryInstructions(data []byte, meta *messageMetadata, host *RegHost, count int) error {
	for i := 0; i < count; i++ {
		// Read record name.
		name, newOffset, err := dns.ReadName(data, meta.offset)
		if err != nil {
			return errors.ErrParse
		}

		// Read resource record header.
		if newOffset+dns.ResourceRecordSize > len(data) {
			return errors.ErrParse
		}
		var rr dns.ResourceRecord
		if err := rr.UnmarshalBinary(data[newOffset:]); err != nil {
			return errors.ErrParse
		}
		rdataOffset := newOffset + dns.ResourceRecordSize
		endOffset := rdataOffset + int(rr.RDLength)
		if endOffset > len(data) {
			return errors.ErrParse
		}

		if rr.Type == dns.RRTypePtr {
			// Read the PTR target name (the service instance name).
			instanceName, _, err := dns.ReadName(data, rdataOffset)
			if err != nil {
				return errors.ErrParse
			}

			// Parse instance label from the instance name.
			instanceLabel, err := extractInstanceLabel(instanceName)
			if err != nil {
				return errors.ErrParse
			}

			// Check if this is a sub-type PTR.
			subTypeLabel := ""
			if isSubType, stl := parseSubType(name); isSubType {
				subTypeLabel = stl
				_ = subTypeLabel
			}

			// Find or create the service.
			svc := host.FindService(instanceName)
			if svc == nil {
				svc = &RegService{
					InstanceName:  instanceName,
					InstanceLabel: instanceLabel,
					UpdateTime:    meta.rxTime,
				}

				// Derive service name from instance name by stripping instance label.
				svc.ServiceName = deriveServiceName(instanceName)
				host.Services = append(host.Services, svc)
			}

			// Record sub-types.
			if isSubType, _ := parseSubType(name); isSubType {
				svc.SubTypes = append(svc.SubTypes, name)
			}

			// Check if this is a removal (Class None).
			if rr.Class == dns.ClassNone {
				svc.IsDeleted = true
			}
		}

		meta.offset = endOffset
	}
	return nil
}

// -------------------------------------------------------
// Pass 1: Host description instruction (AAAA, KEY, delete-all)
// -------------------------------------------------------

func (s *Server) processHostDescriptionInstruction(data []byte, meta *messageMetadata, host *RegHost, count int) error {
	for i := 0; i < count; i++ {
		name, newOffset, err := dns.ReadName(data, meta.offset)
		if err != nil {
			return errors.ErrParse
		}

		if newOffset+dns.ResourceRecordSize > len(data) {
			return errors.ErrParse
		}
		var rr dns.ResourceRecord
		if err := rr.UnmarshalBinary(data[newOffset:]); err != nil {
			return errors.ErrParse
		}
		rdataOffset := newOffset + dns.ResourceRecordSize
		endOffset := rdataOffset + int(rr.RDLength)
		if endOffset > len(data) {
			return errors.ErrParse
		}

		// Only process records for the host (not service instance names).
		isHostRecord := false
		if host.FullName == "" {
			// First host record sets the name; verify it's under the domain.
			if isNameUnderDomain(name, s.domain) && !isServiceRelatedName(name, s.domain) {
				host.FullName = name
				isHostRecord = true
			}
		} else {
			isHostRecord = strings.EqualFold(name, host.FullName)
		}

		if isHostRecord {
			switch rr.Type {
			case dns.RRTypeAaaa:
				// Parse AAAA record.
				if rr.Class != dns.ClassInternet && rr.Class != dns.ClassAny {
					break
				}
				if rr.RDLength == dns.AaaaRecordRDataSize {
					var addr ip6.Address
					copy(addr[:], data[rdataOffset:rdataOffset+16])
					host.Addresses = append(host.Addresses, addr)
					host.TTL = rr.TTL
				}

			case dns.RRTypeKey:
				// Parse KEY record.
				if rr.RDLength < dns.KeyRecordFixedSize+ecdsa.PublicKeySize {
					return errors.ErrParse
				}
				var keyRec dns.KeyRecord
				if err := keyRec.UnmarshalBinary(data[newOffset:]); err != nil {
					return errors.ErrParse
				}
				if keyRec.Algorithm != dns.KeyAlgorithmEcdsaP256Sha256 {
					return errors.ErrSecurity
				}
				// Extract the public key bytes.
				keyStart := rdataOffset + dns.KeyRecordFixedSize
				keyEnd := keyStart + ecdsa.PublicKeySize
				if keyEnd > len(data) {
					return errors.ErrParse
				}
				var key ecdsa.PublicKey
				copy(key[:], data[keyStart:keyEnd])

				// If host already has a key (from a prior registration), verify it matches.
				if host.parsedKey && host.Key != key {
					return errors.ErrSecurity
				}
				host.Key = key
				host.parsedKey = true

			default:
				// "Delete all RRsets" for the host: Class=Any, Type=Any, RDLength=0.
				if rr.Class == dns.ClassAny && rr.Type == dns.RRTypeAny && rr.RDLength == 0 {
					// Host is being deleted (name retained). No action needed here;
					// lease=0 handling happens in processAdditionalSection.
				}
			}
		}

		meta.offset = endOffset
	}

	// Validate: host name and key must be set.
	if host.FullName == "" {
		return errors.ErrParse
	}
	if !host.parsedKey {
		return errors.ErrParse
	}

	return nil
}

// -------------------------------------------------------
// Pass 2: Service description instructions (SRV, TXT, delete-all for services)
// -------------------------------------------------------

func (s *Server) processServiceDescriptionInstructions(data []byte, meta *messageMetadata, host *RegHost, count int) error {
	for i := 0; i < count; i++ {
		name, newOffset, err := dns.ReadName(data, meta.offset)
		if err != nil {
			return errors.ErrParse
		}

		if newOffset+dns.ResourceRecordSize > len(data) {
			return errors.ErrParse
		}
		var rr dns.ResourceRecord
		if err := rr.UnmarshalBinary(data[newOffset:]); err != nil {
			return errors.ErrParse
		}
		rdataOffset := newOffset + dns.ResourceRecordSize
		endOffset := rdataOffset + int(rr.RDLength)
		if endOffset > len(data) {
			return errors.ErrParse
		}

		// Find matching service.
		svc := host.FindService(name)
		if svc != nil {
			switch rr.Type {
			case dns.RRTypeSrv:
				if rr.Class != dns.ClassInternet && rr.Class != dns.ClassNone {
					break
				}
				var srvRec dns.SrvRecord
				if err := srvRec.UnmarshalBinary(data[newOffset:]); err != nil {
					return errors.ErrParse
				}
				svc.Priority = srvRec.Priority
				svc.Weight = srvRec.Weight
				svc.Port = srvRec.Port
				svc.TTL = rr.TTL
				svc.parsedSrv = true

				// Read target host name and verify it matches the host.
				if rr.RDLength > dns.SrvRecordFixedSize {
					targetName, err := srvRec.ReadTargetHostName(data, rdataOffset)
					if err != nil {
						return errors.ErrParse
					}
					if !strings.EqualFold(targetName, host.FullName) {
						return errors.ErrParse
					}
				}

			case dns.RRTypeTxt:
				if rr.Class != dns.ClassInternet && rr.Class != dns.ClassNone {
					break
				}
				txtData := make([]byte, rr.RDLength)
				copy(txtData, data[rdataOffset:endOffset])
				svc.TxtData = txtData
				svc.parsedTxt = true

			default:
				// "Delete all RRsets" for service: Class=Any, Type=Any, RDLength=0.
				if rr.Class == dns.ClassAny && rr.Type == dns.RRTypeAny && rr.RDLength == 0 {
					svc.parsedDeleteAllRRset = true
				}
			}
		}

		meta.offset = endOffset
	}

	// Validate services.
	for _, svc := range host.Services {
		if svc.IsDeleted {
			// Deleted services must have parsedDeleteAllRRset.
			if !svc.parsedDeleteAllRRset {
				return errors.ErrParse
			}
			continue
		}
		// Non-deleted services must have both SRV and TXT parsed.
		if !svc.parsedSrv || !svc.parsedTxt {
			return errors.ErrParse
		}
		// Must also have parsedDeleteAllRRset (the initial clear).
		if !svc.parsedDeleteAllRRset {
			return errors.ErrParse
		}
	}

	return nil
}

// -------------------------------------------------------
// Name conflict detection
// -------------------------------------------------------

func (s *Server) hasNameConflictsWith(newHost *RegHost) error {
	for _, existingHost := range s.hosts {
		// Same host name but different key -> conflict.
		if existingHost.Matches(newHost.FullName) {
			if existingHost.Key != newHost.Key {
				return errors.ErrDuplicated
			}
			continue
		}
		// Check service instance names under different keys.
		for _, newSvc := range newHost.Services {
			for _, existingSvc := range existingHost.Services {
				if existingSvc.MatchesInstanceName(newSvc.InstanceName) {
					if existingHost.Key != newHost.Key {
						return errors.ErrDuplicated
					}
				}
			}
		}
	}
	return nil
}

// -------------------------------------------------------
// Additional section (OPT + SIG(0))
// -------------------------------------------------------

func (s *Server) processAdditionalSection(data []byte, meta *messageMetadata, host *RegHost) error {
	additionalCount := meta.dnsHeader.ARCount
	if additionalCount != 2 {
		return errors.ErrParse
	}

	// Record 1: OPT with Lease Option.
	if err := s.processLeaseOption(data, meta, host); err != nil {
		return err
	}

	// Record 2: SIG(0).
	if err := s.processSig0(data, meta, host); err != nil {
		return err
	}

	return nil
}

func (s *Server) processLeaseOption(data []byte, meta *messageMetadata, host *RegHost) error {
	// Skip the name (root name "." = single 0x00 byte typically).
	_, newOffset, err := dns.ReadName(data, meta.offset)
	if err != nil {
		return errors.ErrParse
	}

	// Read OPT record header.
	if newOffset+dns.ResourceRecordSize > len(data) {
		return errors.ErrParse
	}
	var optRec dns.OptRecord
	if err := optRec.UnmarshalBinary(data[newOffset:]); err != nil {
		return errors.ErrParse
	}
	if optRec.Type != dns.RRTypeOpt {
		return errors.ErrParse
	}

	rdataOffset := newOffset + dns.ResourceRecordSize
	rdataEnd := rdataOffset + int(optRec.RDLength)
	if rdataEnd > len(data) {
		return errors.ErrParse
	}

	// Find the lease option within OPT RDATA.
	leaseOpt, err := dns.FindLeaseOption(data[rdataOffset:rdataEnd])
	if err != nil {
		return errors.ErrParse
	}

	host.useShortLeaseOption = leaseOpt.IsShortVariant()

	// Set lease and key-lease on host and all services.
	host.Lease = leaseOpt.LeaseInterval
	host.KeyLease = leaseOpt.KeyLeaseInterval

	for _, svc := range host.Services {
		if !svc.IsDeleted {
			svc.Lease = leaseOpt.LeaseInterval
			svc.KeyLease = leaseOpt.KeyLeaseInterval
		} else {
			svc.Lease = 0
			svc.KeyLease = leaseOpt.KeyLeaseInterval
		}
	}

	// Validate: if registering (lease > 0), must have at least 1 address.
	if host.Lease > 0 && len(host.Addresses) == 0 {
		return errors.ErrParse
	}

	meta.offset = rdataEnd
	return nil
}

func (s *Server) processSig0(data []byte, meta *messageMetadata, host *RegHost) error {
	sigRecordOffset := meta.offset

	// Read the SIG record name (root ".").
	_, newOffset, err := dns.ReadName(data, meta.offset)
	if err != nil {
		return errors.ErrParse
	}

	// Read the SIG record header.
	if newOffset+dns.ResourceRecordSize > len(data) {
		return errors.ErrParse
	}
	var sigRec dns.SigRecord
	if err := sigRec.UnmarshalBinary(data[newOffset:]); err != nil {
		return errors.ErrParse
	}
	if !sigRec.IsValid() {
		return errors.ErrParse
	}
	if sigRec.Algorithm != dns.KeyAlgorithmEcdsaP256Sha256 {
		return errors.ErrSecurity
	}
	if sigRec.TypeCovered != 0 {
		return errors.ErrParse // SIG(0) must have type covered = 0.
	}

	rdataOffset := newOffset + dns.ResourceRecordSize
	rdataEnd := rdataOffset + int(sigRec.RDLength)
	if rdataEnd > len(data) {
		return errors.ErrParse
	}

	// Read signer name.
	_, sigDataOffset, err := sigRec.ReadSignerName(data, rdataOffset)
	if err != nil {
		return errors.ErrParse
	}

	// Extract signature bytes.
	sigLen := rdataEnd - sigDataOffset
	if sigLen != ecdsa.SignatureSize {
		return errors.ErrParse
	}
	var sig ecdsa.Signature
	copy(sig[:], data[sigDataOffset:rdataEnd])

	// Verify the signature.
	if err := s.verifySignature(data, &sigRec, host, sig, rdataOffset, sigRecordOffset, sigDataOffset); err != nil {
		return err
	}

	meta.offset = rdataEnd
	return nil
}

// verifySignature verifies the SIG(0) signature per RFC 2931.
func (s *Server) verifySignature(data []byte, sigRec *dns.SigRecord, host *RegHost,
	sig ecdsa.Signature, rdataOffset, sigRecordOffset, sigDataOffset int) error {

	var hash sha256.Hash
	var hasher sha256.Sha256

	hasher.Start()

	// 1. Hash the SIG RDATA (from rdata start to signer name end = sigDataOffset),
	//    which is: fixed fields (18 bytes) + signer name (uncompressed).
	//    We hash from rdataOffset to sigDataOffset (excludes the signature itself).
	hasher.Update(data[rdataOffset:sigDataOffset])

	// 2. Hash the modified DNS header: decrement ARCount by 1.
	modifiedHeader := make([]byte, dns.HeaderSize)
	copy(modifiedHeader, data[:dns.HeaderSize])
	arCount := binary.BigEndian.Uint16(modifiedHeader[10:12])
	binary.BigEndian.PutUint16(modifiedHeader[10:12], arCount-1)
	hasher.Update(modifiedHeader)

	// 3. Hash all message bytes from after the DNS header up to the SIG record.
	hasher.Update(data[dns.HeaderSize:sigRecordOffset])

	hasher.Finish(&hash)

	// Verify using the host's public key.
	if err := host.Key.Verify(hash, sig); err != nil {
		return errors.ErrSecurity
	}

	return nil
}

// -------------------------------------------------------
// Handle update (pre-commit logic)
// -------------------------------------------------------

func (s *Server) handleUpdate(data []byte, meta *messageMetadata, host *RegHost) {
	// If the host is being removed (lease == 0), copy any missing services
	// from the existing committed host as deleted.
	if host.Lease == 0 {
		existingHost := s.findHost(host.FullName)
		if existingHost != nil {
			for _, existingSvc := range existingHost.Services {
				if host.FindService(existingSvc.InstanceName) == nil {
					deletedSvc := &RegService{
						InstanceName:  existingSvc.InstanceName,
						InstanceLabel: existingSvc.InstanceLabel,
						ServiceName:   existingSvc.ServiceName,
						SubTypes:      existingSvc.SubTypes,
						IsDeleted:     true,
						Lease:         0,
						KeyLease:      host.KeyLease,
						UpdateTime:    meta.rxTime,
					}
					host.Services = append(host.Services, deletedSvc)
				}
			}
		}
	}

	s.informUpdateHandlerOrCommit(meta, host)
}

func (s *Server) informUpdateHandlerOrCommit(meta *messageMetadata, host *RegHost) {
	if s.updateHandler != nil {
		// Create update metadata and hand off to handler.
		s.nextUpdateID++
		um := &updateMetadata{
			id:                 s.nextUpdateID,
			dnsHeader:          meta.dnsHeader,
			ttlConfig:          meta.ttlConfig,
			leaseConfig:        meta.leaseConfig,
			host:               host,
			isDirectFromClient: meta.isDirectRxFromClient(),
		}
		if meta.peer != nil {
			um.peer = *meta.peer
		}
		um.expireTime = s.now().Add(DefaultHandlerTimeout)
		s.outstandingUpdates = append(s.outstandingUpdates, um)

		// Schedule timeout.
		s.scheduleUpdateTimeout(um)

		// Invoke handler.
		s.updateHandler(um.id, host, DefaultHandlerTimeout)
	} else {
		// No handler; commit immediately.
		var peer ip6.SockAddr
		isDirectFromClient := meta.isDirectRxFromClient()
		if isDirectFromClient {
			peer = *meta.peer
		}
		s.commitSrpUpdate(host, nil, meta.dnsHeader, meta.ttlConfig, meta.leaseConfig,
			isDirectFromClient, peer)
	}
}

func (s *Server) scheduleUpdateTimeout(um *updateMetadata) {
	id := um.id
	timeout := um.expireTime.Sub(s.now())
	if timeout < 0 {
		timeout = 0
	}
	s.updateTimer = s.afterFunc(timeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.handleUpdateTimeout(id)
	})
}

func (s *Server) handleUpdateTimeout(id uint32) {
	for i, um := range s.outstandingUpdates {
		if um.id == id {
			um.err = errors.ErrResponseTimeout
			um.completed = true
			s.outstandingUpdates = append(s.outstandingUpdates[:i], s.outstandingUpdates[i+1:]...)
			s.commitSrpUpdate(um.host, um.err, um.dnsHeader, um.ttlConfig, um.leaseConfig,
				um.isDirectFromClient, um.peer)
			return
		}
	}
}

// -------------------------------------------------------
// Commit SRP update
// -------------------------------------------------------

func (s *Server) commitSrpUpdate(host *RegHost, err error, header dns.UpdateHeader,
	ttlConfig TTLConfig, leaseConfig LeaseConfig, isDirectFromClient bool, peer ip6.SockAddr) {

	if s.state != ServerStateRunning {
		return
	}

	if err != nil {
		s.sendErrorResponse(header, errorToDnsResponseCode(err), peerPtr(isDirectFromClient, peer))
		return
	}

	// Grant lease values.
	requestedLease := host.Lease
	requestedKeyLease := host.KeyLease
	grantedLease := leaseConfig.GrantLease(requestedLease)
	grantedKeyLease := leaseConfig.GrantKeyLease(requestedKeyLease)
	if host.useShortLeaseOption {
		grantedKeyLease = grantedLease
	}
	grantedTTL := ttlConfig.GrantTTL(grantedLease, host.TTL)

	// Set granted values on host.
	host.Lease = grantedLease
	host.KeyLease = grantedKeyLease
	host.TTL = grantedTTL

	// Set granted values on services.
	for _, svc := range host.Services {
		if !svc.IsDeleted {
			svc.Lease = grantedLease
			svc.KeyLease = grantedKeyLease
			svc.TTL = ttlConfig.GrantTTL(grantedLease, svc.TTL)
		} else {
			svc.Lease = 0
			svc.KeyLease = grantedKeyLease
		}
		svc.UpdateTime = host.UpdateTime
	}

	// If key-lease == 0, fully remove and done.
	if grantedKeyLease == 0 {
		s.removeHost(host.FullName)
		if isDirectFromClient {
			s.incrementResponseCounter(dns.RcodeSuccess)
			s.sendResponse(header, dns.RcodeSuccess, peerPtr(isDirectFromClient, peer))
		}
		return
	}

	// Remove any existing host with the same name.
	existingHost := s.removeHostFromList(host.FullName)

	// Merge services from existing host that are not in the new update.
	if existingHost != nil {
		for _, existingSvc := range existingHost.Services {
			if host.FindService(existingSvc.InstanceName) == nil {
				// If host is deleted, mark the moved service as deleted too.
				if host.IsDeleted() {
					existingSvc.IsDeleted = true
					existingSvc.Lease = 0
				}
				host.Services = append(host.Services, existingSvc)
			}
		}
	}

	// Add the new host.
	s.hosts = append(s.hosts, host)

	// Schedule lease timer.
	s.scheduleLeaseTimer()

	// Send response.
	if isDirectFromClient {
		if grantedLease != requestedLease || grantedKeyLease != requestedKeyLease {
			s.sendLeaseResponse(header, grantedLease, grantedKeyLease,
				host.useShortLeaseOption, peerPtr(isDirectFromClient, peer))
		} else {
			s.incrementResponseCounter(dns.RcodeSuccess)
			s.sendResponse(header, dns.RcodeSuccess, peerPtr(isDirectFromClient, peer))
		}
	}
}

// -------------------------------------------------------
// Host management
// -------------------------------------------------------

func (s *Server) findHost(name string) *RegHost {
	for _, h := range s.hosts {
		if h.Matches(name) {
			return h
		}
	}
	return nil
}

func (s *Server) removeHostFromList(name string) *RegHost {
	for i, h := range s.hosts {
		if h.Matches(name) {
			s.hosts = append(s.hosts[:i], s.hosts[i+1:]...)
			return h
		}
	}
	return nil
}

func (s *Server) removeHost(name string) {
	s.removeHostFromList(name)
}

// -------------------------------------------------------
// Lease timer
// -------------------------------------------------------

func (s *Server) scheduleLeaseTimer() {
	if s.leaseTimer != nil {
		s.leaseTimer.Stop()
		s.leaseTimer = nil
	}

	if len(s.hosts) == 0 {
		return
	}

	now := s.now()
	var earliest time.Time
	first := true

	for _, h := range s.hosts {
		expiry := h.GetExpireTime()
		keyExpiry := h.GetKeyExpireTime()

		// Use the earlier of lease/key-lease expiry.
		t := expiry
		if keyExpiry.Before(t) {
			t = keyExpiry
		}

		if first || t.Before(earliest) {
			earliest = t
			first = false
		}

		for _, svc := range h.Services {
			svcExpiry := svc.GetExpireTime()
			svcKeyExpiry := svc.GetKeyExpireTime()
			st := svcExpiry
			if svcKeyExpiry.Before(st) {
				st = svcKeyExpiry
			}
			if st.Before(earliest) {
				earliest = st
			}
		}
	}

	if first {
		return
	}

	delay := earliest.Sub(now)
	if delay < 0 {
		delay = 0
	}

	s.leaseTimer = s.afterFunc(delay, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.handleLeaseTimer()
	})
}

func (s *Server) handleLeaseTimer() {
	if s.state != ServerStateRunning {
		return
	}

	now := s.now()
	var remaining []*RegHost

	for _, h := range s.hosts {
		// Check key-lease expiry first (full removal).
		if !h.GetKeyExpireTime().After(now) {
			// Key-lease expired -> fully remove.
			continue
		}

		// Check if host is already deleted.
		if h.IsDeleted() {
			// Check individual service key-lease expirations.
			var remainingServices []*RegService
			for _, svc := range h.Services {
				if !svc.GetKeyExpireTime().After(now) {
					continue // Remove service entirely.
				}
				remainingServices = append(remainingServices, svc)
			}
			h.Services = remainingServices
			remaining = append(remaining, h)
			continue
		}

		// Check lease expiry (mark as deleted, retain name).
		if !h.GetExpireTime().After(now) {
			h.Lease = 0
			h.Addresses = nil
			for _, svc := range h.Services {
				svc.IsDeleted = true
				svc.Lease = 0
			}
			remaining = append(remaining, h)
			continue
		}

		// Host still alive; check individual services.
		var remainingServices []*RegService
		for _, svc := range h.Services {
			if !svc.GetKeyExpireTime().After(now) {
				continue // Full service removal.
			}
			if !svc.IsDeleted && !svc.GetExpireTime().After(now) {
				svc.IsDeleted = true
				svc.Lease = 0
			}
			remainingServices = append(remainingServices, svc)
		}
		h.Services = remainingServices
		remaining = append(remaining, h)
	}

	s.hosts = remaining

	// Reschedule.
	s.scheduleLeaseTimer()
}

// -------------------------------------------------------
// Response sending
// -------------------------------------------------------

func (s *Server) sendErrorResponse(header dns.UpdateHeader, rcode dns.ResponseCode, peer *ip6.SockAddr) {
	s.incrementResponseCounter(rcode)
	s.sendResponse(header, rcode, peer)
}

func (s *Server) sendResponse(header dns.UpdateHeader, rcode dns.ResponseCode, peer *ip6.SockAddr) {
	if peer == nil || s.responder == nil {
		return
	}

	var resp dns.UpdateHeader
	resp.MessageID = header.MessageID
	resp.SetType(dns.TypeResponse)
	resp.SetOpCode(dns.OpcodeUpdate)
	resp.SetResponseCode(rcode)

	buf := resp.MarshalBinary()
	s.responder(buf[:], *peer)
}

func (s *Server) sendLeaseResponse(header dns.UpdateHeader, lease, keyLease uint32,
	useShort bool, peer *ip6.SockAddr) {

	if peer == nil || s.responder == nil {
		return
	}

	s.incrementResponseCounter(dns.RcodeSuccess)

	var resp dns.UpdateHeader
	resp.MessageID = header.MessageID
	resp.SetType(dns.TypeResponse)
	resp.SetOpCode(dns.OpcodeUpdate)
	resp.SetResponseCode(dns.RcodeSuccess)
	resp.ARCount = 1

	data := make([]byte, 0, 64)
	hdrBuf := resp.MarshalBinary()
	data = append(data, hdrBuf[:]...)

	// Append root name.
	data = append(data, 0x00)

	// Append OPT record.
	var optRec dns.OptRecord
	optRec.Init()
	optRec.SetUDPPayloadSize(UDPPayloadSize)

	// Build lease option.
	var leaseOpt dns.LeaseOption
	if useShort {
		leaseOpt.InitShort(lease)
	} else {
		leaseOpt.InitLong(lease, keyLease)
	}
	leaseOptBuf := leaseOpt.MarshalBinary()
	optRec.RDLength = uint16(len(leaseOptBuf))

	optBuf := optRec.MarshalBinary()
	data = append(data, optBuf[:]...)
	data = append(data, leaseOptBuf...)

	s.responder(data, *peer)
}

func (s *Server) incrementResponseCounter(rcode dns.ResponseCode) {
	switch rcode {
	case dns.RcodeSuccess:
		s.responseCounters.Success++
	case dns.RcodeServerFailure:
		s.responseCounters.ServerFailure++
	case dns.RcodeFormatError:
		s.responseCounters.FormatError++
	case dns.RcodeNameExists:
		s.responseCounters.NameExists++
	case dns.RcodeRefused:
		s.responseCounters.Refused++
	default:
		s.responseCounters.Other++
	}
}

// -------------------------------------------------------
// Error to DNS response code mapping
// -------------------------------------------------------

func errorToDnsResponseCode(err error) dns.ResponseCode {
	if err == nil {
		return dns.RcodeSuccess
	}
	switch err {
	case errors.ErrNoBufs:
		return dns.RcodeServerFailure
	case errors.ErrParse:
		return dns.RcodeFormatError
	case errors.ErrDuplicated:
		return dns.RcodeNameExists
	default:
		return dns.RcodeRefused
	}
}

// -------------------------------------------------------
// Helper functions
// -------------------------------------------------------

func clampU32(v, min, max uint32) uint32 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

func peerPtr(isDirectFromClient bool, peer ip6.SockAddr) *ip6.SockAddr {
	if isDirectFromClient {
		return &peer
	}
	return nil
}

// extractInstanceLabel extracts the first label from a DNS name.
// For "My Printer._ipp._tcp.default.service.arpa.", returns "My Printer".
func extractInstanceLabel(instanceName string) (string, error) {
	if instanceName == "" {
		return "", errors.ErrParse
	}
	// Find the first dot after the instance label.
	// Instance labels can contain dots if escaped, but in SRP they typically
	// are separated by the service type which starts with "_".
	idx := strings.Index(instanceName, "._")
	if idx < 0 {
		return "", errors.ErrParse
	}
	return instanceName[:idx], nil
}

// deriveServiceName derives the service name from an instance name.
// "My Printer._ipp._tcp.default.service.arpa." -> "_ipp._tcp.default.service.arpa."
func deriveServiceName(instanceName string) string {
	idx := strings.Index(instanceName, "._")
	if idx < 0 {
		return instanceName
	}
	return instanceName[idx+1:]
}

// isNameUnderDomain checks if name is under the given domain (case-insensitive).
func isNameUnderDomain(name, domain string) bool {
	return strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(domain)) ||
		strings.EqualFold(name, domain)
}

// isServiceRelatedName checks if a name is service-related (service type, service instance, or sub-type).
// A service-related name has labels starting with "_" before the domain suffix.
// Examples: "_ipp._tcp.domain.", "MyPrinter._ipp._tcp.domain.", "_print._sub._ipp._tcp.domain."
// Host names (e.g., "myhost.domain.") do not have underscore-prefixed labels and return false.
func isServiceRelatedName(name, domain string) bool {
	lower := strings.ToLower(name)
	domLower := strings.ToLower(domain)
	if !strings.HasSuffix(lower, "."+domLower) {
		return false
	}
	prefix := lower[:len(lower)-len(domLower)-1]
	// Check if any label in the prefix starts with "_".
	parts := strings.Split(prefix, ".")
	for _, p := range parts {
		if strings.HasPrefix(p, "_") {
			return true
		}
	}
	return false
}

// isServiceInstanceName checks if a name is a service instance name
// (has at least one label before a service type label like _xxx._tcp or _xxx._udp).
func isServiceInstanceName(name, domain string) bool {
	lower := strings.ToLower(name)
	domLower := strings.ToLower(domain)
	if !strings.HasSuffix(lower, "."+domLower) {
		return false
	}
	// Strip domain suffix.
	prefix := lower[:len(lower)-len(domLower)-1]
	// Service instance names have the form: instancelabel._type._proto
	// Check for at least 3 labels (instance._type._proto).
	parts := strings.Split(prefix, ".")
	if len(parts) < 3 {
		return false
	}
	// Service type labels start with "_".
	return strings.HasPrefix(parts[len(parts)-2], "_") && strings.HasPrefix(parts[len(parts)-1], "_")
}

// parseSubType checks if a name is a sub-type PTR and returns the sub-type label.
// "_print._sub._ipp._tcp.default.service.arpa." -> true, "_print"
func parseSubType(name string) (bool, string) {
	idx := strings.Index(strings.ToLower(name), serviceSubTypeLabel)
	if idx < 0 {
		return false, ""
	}
	subLabel := name[:idx]
	// Get the last label (after any dots).
	if lastDot := strings.LastIndex(subLabel, "."); lastDot >= 0 {
		subLabel = subLabel[lastDot+1:]
	}
	return true, subLabel
}
