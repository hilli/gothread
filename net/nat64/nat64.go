// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package nat64 implements a NAT64 translator for Thread border routers.
//
// This is a clean-room Go port of the NAT64 translator in OpenThread's
// src/core/net/nat64_translator.hpp and src/core/net/nat64_translator.cpp.
// It translates between IPv6 and IPv4 packets per RFC 6145/6146.
package nat64

import (
	"sync"
	"time"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip4"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

// State represents the operational state of the NAT64 translator.
type State uint8

const (
	// StateDisabled means the translator is disabled.
	StateDisabled State = iota
	// StateNotRunning means the translator is enabled but lacks valid
	// configuration (no prefix or CIDR).
	StateNotRunning
	// StateIdle means the translator is enabled but this border router is
	// not the active NAT64 translator.
	StateIdle
	// StateActive means the translator is actively translating packets.
	StateActive
)

// String returns a human-readable name for the state.
func (s State) String() string {
	switch s {
	case StateDisabled:
		return "Disabled"
	case StateNotRunning:
		return "NotRunning"
	case StateIdle:
		return "Idle"
	case StateActive:
		return "Active"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// DropReason
// ---------------------------------------------------------------------------

// DropReason indicates why a packet was dropped.
type DropReason uint8

// NAT64 packet drop reasons used to index error counters.
const (
	DropReasonUnknown          DropReason = iota
	DropReasonIllegalPacket               // Malformed packet
	DropReasonUnsupportedProto            // Protocol not TCP/UDP/ICMP
	DropReasonNoMapping                   // No address mapping found/available
)

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// DirectionCounters holds packet and byte counts for one direction.
type DirectionCounters struct {
	Packets uint64
	Bytes   uint64
}

// ProtocolCounters holds per-protocol translation counters.
type ProtocolCounters struct {
	TCP   DirectionCounters
	UDP   DirectionCounters
	ICMP  DirectionCounters
	Total DirectionCounters
}

// ErrorCounters holds per-reason drop counters for each direction.
type ErrorCounters struct {
	Count6To4 [4]uint64 // indexed by DropReason
	Count4To6 [4]uint64 // indexed by DropReason
}

// ---------------------------------------------------------------------------
// AddressMapping (exported snapshot)
// ---------------------------------------------------------------------------

// AddressMapping is a snapshot of an active address mapping entry.
type AddressMapping struct {
	ID         uint64
	IPv6Addr   ip6.Address
	IPv4Addr   ip4.Address
	LastUsed   time.Time
	Expiration time.Time
}

// ---------------------------------------------------------------------------
// Internal mapping
// ---------------------------------------------------------------------------

// mapping is the internal representation of an address mapping entry.
type mapping struct {
	id         uint64
	ip6Addr    ip6.Address
	ip4Addr    ip4.Address
	lastUsed   time.Time
	expiration time.Time
	counters   mappingCounters
}

// mappingCounters tracks per-mapping protocol counters for both directions.
type mappingCounters struct {
	tcp6to4  DirectionCounters
	udp6to4  DirectionCounters
	icmp6to4 DirectionCounters
	tcp4to6  DirectionCounters
	udp4to6  DirectionCounters
	icmp4to6 DirectionCounters
}

// protoCategory classifies the mapping by its highest-priority protocol.
type protoCategory uint8

const (
	protoCatICMPOnly protoCategory = iota
	protoCatUDP
	protoCatTCP
)

func (m *mapping) category() protoCategory {
	if m.counters.tcp6to4.Packets > 0 || m.counters.tcp4to6.Packets > 0 {
		return protoCatTCP
	}
	if m.counters.udp6to4.Packets > 0 || m.counters.udp4to6.Packets > 0 {
		return protoCatUDP
	}
	return protoCatICMPOnly
}

func (m *mapping) touch(proto uint8, now time.Time, idleTimeout, icmpTimeout time.Duration) {
	timeout := idleTimeout
	if proto == ip6.ProtoICMPv6 || proto == ip4.ProtocolICMP {
		timeout = icmpTimeout
	}
	m.lastUsed = now
	m.expiration = now.Add(timeout)
}

func (m *mapping) isExpired(now time.Time) bool {
	return now.After(m.expiration)
}

func (m *mapping) count6To4(proto uint8, size uint16) {
	switch proto {
	case ip6.ProtoTCP:
		m.counters.tcp6to4.Packets++
		m.counters.tcp6to4.Bytes += uint64(size)
	case ip6.ProtoUDP:
		m.counters.udp6to4.Packets++
		m.counters.udp6to4.Bytes += uint64(size)
	case ip6.ProtoICMPv6:
		m.counters.icmp6to4.Packets++
		m.counters.icmp6to4.Bytes += uint64(size)
	}
}

func (m *mapping) count4To6(proto uint8, size uint16) {
	switch proto {
	case ip4.ProtocolTCP:
		m.counters.tcp4to6.Packets++
		m.counters.tcp4to6.Bytes += uint64(size)
	case ip4.ProtocolUDP:
		m.counters.udp4to6.Packets++
		m.counters.udp4to6.Bytes += uint64(size)
	case ip4.ProtocolICMP:
		m.counters.icmp4to6.Packets++
		m.counters.icmp4to6.Bytes += uint64(size)
	}
}

// ---------------------------------------------------------------------------
// ICMPv6 ↔ ICMPv4 type constants (RFC 6145 Section 4)
// ---------------------------------------------------------------------------

const (
	icmp4EchoReply   uint8 = 0
	icmp4EchoRequest uint8 = 8

	icmp6EchoRequest uint8 = 128
	icmp6EchoReply   uint8 = 129

	// ICMP header: type(1) + code(1) + checksum(2) + id(2) + seq(2) = 8
	icmpHeaderSize = 8
)

// ---------------------------------------------------------------------------
// Translator
// ---------------------------------------------------------------------------

// DefaultMaxMappings is the default mapping pool size.
const DefaultMaxMappings = 64

// DefaultIdleTimeout is the default timeout for TCP/UDP mappings.
const DefaultIdleTimeout = 5 * time.Minute

// DefaultICMPTimeout is the default timeout for ICMP mappings.
const DefaultICMPTimeout = 30 * time.Second

// MinEvictTimeout is the minimum time a mapping must be idle before eviction.
const MinEvictTimeout = 2 * time.Minute

// Translator implements the NAT64 translation engine.
type Translator struct {
	mu sync.Mutex

	state State

	nat64Prefix ip6.Prefix
	ip4CIDR     ip4.CIDR

	minHostID  uint32
	maxHostID  uint32
	nextHostID uint32

	mappings    []*mapping
	maxMappings int
	nextID      uint64

	idleTimeout time.Duration
	icmpTimeout time.Duration

	counters      ProtocolCounters
	errorCounters ErrorCounters

	now func() time.Time
}

// NewTranslator creates a new NAT64 translator in the Disabled state.
func NewTranslator(opts ...Option) *Translator {
	t := &Translator{
		state:       StateDisabled,
		maxMappings: DefaultMaxMappings,
		idleTimeout: DefaultIdleTimeout,
		icmpTimeout: DefaultICMPTimeout,
		now:         time.Now,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// Option is a functional option for configuring a Translator.
type Option func(*Translator)

// WithMaxMappings sets the maximum number of concurrent address mappings.
func WithMaxMappings(n int) Option {
	return func(t *Translator) {
		if n > 0 {
			t.maxMappings = n
		}
	}
}

// WithIdleTimeout sets the idle timeout for TCP/UDP mappings.
func WithIdleTimeout(d time.Duration) Option {
	return func(t *Translator) { t.idleTimeout = d }
}

// WithICMPTimeout sets the idle timeout for ICMP mappings.
func WithICMPTimeout(d time.Duration) Option {
	return func(t *Translator) { t.icmpTimeout = d }
}

// WithClock overrides the clock function (for testing).
func WithClock(fn func() time.Time) Option {
	return func(t *Translator) { t.now = fn }
}

// ---------------------------------------------------------------------------
// State management
// ---------------------------------------------------------------------------

// GetState returns the current state of the translator.
func (t *Translator) GetState() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.state
}

// SetEnabled enables or disables the translator.
func (t *Translator) SetEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if enabled {
		t.setState(t.activeOrNotRunning())
	} else {
		t.setState(StateDisabled)
	}
}

func (t *Translator) setState(s State) {
	if t.state == s {
		return
	}
	t.state = s
	switch s {
	case StateDisabled, StateNotRunning, StateIdle:
		t.mappings = nil
	}
}

func (t *Translator) activeOrNotRunning() State {
	if t.hasValidPrefixAndCIDR() {
		return StateActive
	}
	return StateNotRunning
}

func (t *Translator) hasValidPrefixAndCIDR() bool {
	return t.ip4CIDR.PrefixLength > 0 && t.nat64Prefix.IsValidNat64()
}

func (t *Translator) updateState() {
	if t.state != StateDisabled {
		t.setState(t.activeOrNotRunning())
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// SetNat64Prefix sets the NAT64 prefix used to synthesize IPv6 addresses.
func (t *Translator) SetNat64Prefix(prefix ip6.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nat64Prefix = prefix
	t.updateState()
}

// GetNat64Prefix returns the configured NAT64 prefix, or ErrNotFound.
func (t *Translator) GetNat64Prefix() (ip6.Prefix, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nat64Prefix.GetLength() == 0 {
		return ip6.Prefix{}, errors.ErrNotFound
	}
	return t.nat64Prefix, nil
}

// ClearNat64Prefix removes the NAT64 prefix.
func (t *Translator) ClearNat64Prefix() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.nat64Prefix = ip6.Prefix{}
	t.updateState()
}

// SetIPv4CIDR sets the IPv4 CIDR used for translated source addresses.
// Setting a new CIDR clears all existing mappings.
func (t *Translator) SetIPv4CIDR(cidr ip4.CIDR) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if cidr.PrefixLength == 0 || cidr.PrefixLength > 32 {
		return errors.ErrInvalidArgs
	}

	if cidr.Equal(t.ip4CIDR) {
		return nil
	}

	t.minHostID = 0
	bits := 32 - uint32(cidr.PrefixLength)
	if bits >= 32 {
		t.maxHostID = 0xFFFFFFFF
	} else {
		t.maxHostID = (1 << bits) - 1
	}

	if cidr.PrefixLength < 31 {
		t.minHostID++
		t.maxHostID--
	}

	t.nextHostID = t.minHostID
	t.mappings = nil
	t.ip4CIDR = cidr
	t.updateState()

	return nil
}

// GetIPv4CIDR returns the configured IPv4 CIDR, or ErrNotFound.
func (t *Translator) GetIPv4CIDR() (ip4.CIDR, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ip4CIDR.PrefixLength == 0 {
		return ip4.CIDR{}, errors.ErrNotFound
	}
	return t.ip4CIDR, nil
}

// ClearIPv4CIDR removes the IPv4 CIDR and clears all mappings.
func (t *Translator) ClearIPv4CIDR() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ip4CIDR.PrefixLength == 0 {
		return
	}
	t.ip4CIDR = ip4.CIDR{}
	t.mappings = nil
	t.updateState()
}

// ---------------------------------------------------------------------------
// Address allocation
// ---------------------------------------------------------------------------

func (t *Translator) getNextIPv4Address() ip4.Address {
	addr := ip4.SynthesizeFromCIDRAndHost(t.ip4CIDR, t.nextHostID)
	t.nextHostID++
	if t.nextHostID > t.maxHostID {
		t.nextHostID = t.minHostID
	}
	return addr
}

func (t *Translator) isIPv4AddressInUse(addr ip4.Address) bool {
	for _, m := range t.mappings {
		if m.ip4Addr == addr {
			return true
		}
	}
	return false
}

func (t *Translator) allocateIPv4Address() (ip4.Address, error) {
	numHosts := t.maxHostID - t.minHostID + 1
	if uint32(len(t.mappings)) >= numHosts {
		t.evictStaleMapping()
		if uint32(len(t.mappings)) >= numHosts {
			return ip4.Address{}, errors.ErrFailed
		}
	}
	addr := t.getNextIPv4Address()
	for t.isIPv4AddressInUse(addr) {
		addr = t.getNextIPv4Address()
	}
	return addr, nil
}

// ---------------------------------------------------------------------------
// Mapping management
// ---------------------------------------------------------------------------

func (t *Translator) findMappingByIPv6(src ip6.Address) *mapping {
	for _, m := range t.mappings {
		if m.ip6Addr == src {
			return m
		}
	}
	return nil
}

func (t *Translator) findMappingByIPv4(dst ip4.Address) *mapping {
	for _, m := range t.mappings {
		if m.ip4Addr == dst {
			return m
		}
	}
	return nil
}

func (t *Translator) allocateMapping(ip6Src ip6.Address) (*mapping, error) {
	ip4Addr, err := t.allocateIPv4Address()
	if err != nil {
		return nil, err
	}

	if len(t.mappings) >= t.maxMappings {
		t.evictStaleMapping()
		if len(t.mappings) >= t.maxMappings {
			return nil, errors.ErrNoBufs
		}
	}

	now := t.now()
	m := &mapping{
		id:         t.nextID,
		ip6Addr:    ip6Src,
		ip4Addr:    ip4Addr,
		lastUsed:   now,
		expiration: now.Add(t.idleTimeout),
	}
	t.nextID++
	t.mappings = append(t.mappings, m)
	return m, nil
}

func (t *Translator) evictStaleMapping() {
	now := t.now()

	// First remove all expired mappings.
	n := 0
	removed := false
	for _, m := range t.mappings {
		if m.isExpired(now) {
			removed = true
		} else {
			t.mappings[n] = m
			n++
		}
	}
	// Clear dangling pointers.
	for i := n; i < len(t.mappings); i++ {
		t.mappings[i] = nil
	}
	t.mappings = t.mappings[:n]

	if removed {
		return
	}

	// No expired mappings; evict best candidate.
	best := -1
	for i, m := range t.mappings {
		sinceUse := now.Sub(m.lastUsed)
		if sinceUse < MinEvictTimeout {
			continue
		}
		if best < 0 || isBetterEvictionCandidate(m, t.mappings[best], now) {
			best = i
		}
	}

	if best >= 0 {
		last := len(t.mappings) - 1
		t.mappings[best] = t.mappings[last]
		t.mappings[last] = nil
		t.mappings = t.mappings[:last]
	}
}

func isBetterEvictionCandidate(a, b *mapping, now time.Time) bool {
	catA := a.category()
	catB := b.category()
	if catA < catB {
		return true
	}
	if catA > catB {
		return false
	}
	return now.Sub(a.lastUsed) > now.Sub(b.lastUsed)
}

// RemoveExpiredMappings removes all expired mappings from the table.
func (t *Translator) RemoveExpiredMappings() {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	n := 0
	for _, m := range t.mappings {
		if !m.isExpired(now) {
			t.mappings[n] = m
			n++
		}
	}
	for i := n; i < len(t.mappings); i++ {
		t.mappings[i] = nil
	}
	t.mappings = t.mappings[:n]
}

// GetMappings returns a snapshot of all active address mappings.
func (t *Translator) GetMappings() []AddressMapping {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := make([]AddressMapping, 0, len(t.mappings))
	for _, m := range t.mappings {
		result = append(result, AddressMapping{
			ID:         m.id,
			IPv6Addr:   m.ip6Addr,
			IPv4Addr:   m.ip4Addr,
			LastUsed:   m.lastUsed,
			Expiration: m.expiration,
		})
	}
	return result
}

// MappingCount returns the number of active mappings.
func (t *Translator) MappingCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.mappings)
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

// GetCounters returns the global protocol counters.
func (t *Translator) GetCounters() ProtocolCounters {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.counters
}

// GetErrorCounters returns the global error counters.
func (t *Translator) GetErrorCounters() ErrorCounters {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.errorCounters
}

func (t *Translator) count6To4(proto uint8, size uint16) {
	switch proto {
	case ip6.ProtoTCP:
		t.counters.TCP.Packets++
		t.counters.TCP.Bytes += uint64(size)
	case ip6.ProtoUDP:
		t.counters.UDP.Packets++
		t.counters.UDP.Bytes += uint64(size)
	case ip6.ProtoICMPv6:
		t.counters.ICMP.Packets++
		t.counters.ICMP.Bytes += uint64(size)
	}
	t.counters.Total.Packets++
	t.counters.Total.Bytes += uint64(size)
}

func (t *Translator) count4To6(proto uint8, size uint16) {
	switch proto {
	case ip4.ProtocolTCP:
		t.counters.TCP.Packets++
		t.counters.TCP.Bytes += uint64(size)
	case ip4.ProtocolUDP:
		t.counters.UDP.Packets++
		t.counters.UDP.Bytes += uint64(size)
	case ip4.ProtocolICMP:
		t.counters.ICMP.Packets++
		t.counters.ICMP.Bytes += uint64(size)
	}
	t.counters.Total.Packets++
	t.counters.Total.Bytes += uint64(size)
}

// ---------------------------------------------------------------------------
// Translation: IPv6 → IPv4
// ---------------------------------------------------------------------------

// TranslateIPv6ToIPv4 translates an IPv6 packet to an IPv4 packet.
//
// Returns:
//   - The translated IPv4 packet on success.
//   - ErrDrop if the packet should be dropped (malformed, unsupported, no mapping).
//   - ErrInvalidState if the translator is not Active or the destination
//     does not match the NAT64 prefix.
func (t *Translator) TranslateIPv6ToIPv4(pkt []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != StateActive {
		return nil, errors.ErrInvalidState
	}

	var dropReason DropReason

	// Parse IPv6 header.
	if len(pkt) < ip6.HeaderSize {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count6To4[dropReason]++
		return nil, errors.ErrDrop
	}

	if pkt[0]>>4 != 6 {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count6To4[dropReason]++
		return nil, errors.ErrDrop
	}

	payloadLen := encoding.BigEndianReadUint16(pkt[4:6])
	nextHeader := pkt[6]
	hopLimit := pkt[7]

	var src6, dst6 ip6.Address
	copy(src6[:], pkt[8:24])
	copy(dst6[:], pkt[24:40])

	totalLen := ip6.HeaderSize + int(payloadLen)
	if len(pkt) < totalLen {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count6To4[dropReason]++
		return nil, errors.ErrDrop
	}

	// Read DSCP/ECN from traffic class.
	tc := (pkt[0]&0x0f)<<4 | pkt[1]>>4
	dscp := tc >> 2
	ecn := ip6.Ecn(tc & 0x03)

	// Check destination matches NAT64 prefix.
	if !dst6.MatchesPrefix(t.nat64Prefix) {
		return nil, errors.ErrInvalidState
	}

	// Find or create mapping.
	m := t.findMappingByIPv6(src6)
	if m == nil {
		var err error
		m, err = t.allocateMapping(src6)
		if err != nil {
			dropReason = DropReasonNoMapping
			t.errorCounters.Count6To4[dropReason]++
			return nil, errors.ErrDrop
		}
	}

	m.touch(nextHeader, t.now(), t.idleTimeout, t.icmpTimeout)

	dst4, err := ip4.ExtractFromV6(dst6, t.nat64Prefix)
	if err != nil {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count6To4[dropReason]++
		return nil, errors.ErrDrop
	}

	payload := pkt[ip6.HeaderSize:totalLen]

	// Translate protocol.
	var ip4Proto uint8
	switch nextHeader {
	case ip6.ProtoTCP:
		ip4Proto = ip4.ProtocolTCP
		if len(payload) < ip6.TCPHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count6To4[dropReason]++
			return nil, errors.ErrDrop
		}
	case ip6.ProtoUDP:
		ip4Proto = ip4.ProtocolUDP
		if len(payload) < ip6.UDPHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count6To4[dropReason]++
			return nil, errors.ErrDrop
		}
	case ip6.ProtoICMPv6:
		ip4Proto = ip4.ProtocolICMP
		if len(payload) < icmpHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count6To4[dropReason]++
			return nil, errors.ErrDrop
		}
	default:
		dropReason = DropReasonUnsupportedProto
		t.errorCounters.Count6To4[dropReason]++
		return nil, errors.ErrDrop
	}

	// Build IPv4 header.
	var ip4Hdr ip4.Header
	ip4Hdr.Init()
	ip4Hdr.SetTTL(hopLimit)
	ip4Hdr.SetProtocol(ip4Proto)
	ip4Hdr.SetSource(m.ip4Addr)
	ip4Hdr.SetDestination(dst4)
	ip4Hdr.SetTotalLength(uint16(ip4.HeaderMinSize + len(payload)))
	ip4Hdr.SetIdentification(0)
	ip4Hdr.SetDscp(dscp)
	ip4Hdr.SetEcn(ecn)

	// Copy payload and translate.
	translatedPayload := make([]byte, len(payload))
	copy(translatedPayload, payload)

	if ip4Proto == ip4.ProtocolICMP {
		if err := translateICMPv6ToICMPv4(translatedPayload); err != nil {
			dropReason = DropReasonUnsupportedProto
			t.errorCounters.Count6To4[dropReason]++
			return nil, errors.ErrDrop
		}
		// ICMPv4 checksum: recompute from scratch (no pseudo-header).
		translatedPayload[2] = 0
		translatedPayload[3] = 0
		csum := ip4.InternetChecksum(translatedPayload)
		encoding.BigEndianWriteUint16(csum, translatedPayload[2:4])
	} else {
		// TCP/UDP: update checksum for pseudo-header change.
		updateChecksumV6ToV4(translatedPayload, ip4Proto, src6, dst6,
			nextHeader, m.ip4Addr, dst4, uint16(len(payload)))
	}

	// Assemble output packet.
	hdrBytes := ip4Hdr.Marshal()
	result := make([]byte, 0, ip4.HeaderMinSize+len(translatedPayload))
	result = append(result, hdrBytes[:]...)
	result = append(result, translatedPayload...)

	// Compute IPv4 header checksum.
	result[10] = 0
	result[11] = 0
	headerCsum := ip4.InternetChecksum(result[:ip4.HeaderMinSize])
	encoding.BigEndianWriteUint16(headerCsum, result[10:12])

	t.count6To4(nextHeader, payloadLen)
	m.count6To4(nextHeader, payloadLen)

	return result, nil
}

// ---------------------------------------------------------------------------
// Translation: IPv4 → IPv6
// ---------------------------------------------------------------------------

// TranslateIPv4ToIPv6 translates an IPv4 packet to an IPv6 packet.
//
// Returns:
//   - The translated IPv6 packet on success.
//   - ErrDrop if the packet should be dropped.
//   - ErrInvalidState if the translator is not Active.
func (t *Translator) TranslateIPv4ToIPv6(pkt []byte) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.state != StateActive {
		return nil, errors.ErrInvalidState
	}

	var dropReason DropReason

	if len(pkt) < ip4.HeaderMinSize {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	var ip4Hdr ip4.Header
	if err := ip4Hdr.Unmarshal(pkt); err != nil {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	totalLen := ip4Hdr.GetTotalLength()
	if int(totalLen) > len(pkt) || totalLen < ip4.HeaderMinSize {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	hdrLen := int(ip4Hdr.GetHeaderLength())
	if hdrLen < ip4.HeaderMinSize || hdrLen > int(totalLen) {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	dst4 := ip4Hdr.GetDestination()
	src4 := ip4Hdr.GetSource()
	ip4Proto := ip4Hdr.GetProtocol()

	m := t.findMappingByIPv4(dst4)
	if m == nil {
		dropReason = DropReasonNoMapping
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	m.touch(ip4Proto, t.now(), t.idleTimeout, t.icmpTimeout)

	src6, err := ip4.MappedToV6(src4, t.nat64Prefix)
	if err != nil {
		dropReason = DropReasonIllegalPacket
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	payload := pkt[hdrLen:totalLen]

	var nextHeader uint8
	switch ip4Proto {
	case ip4.ProtocolTCP:
		nextHeader = ip6.ProtoTCP
		if len(payload) < ip6.TCPHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count4To6[dropReason]++
			return nil, errors.ErrDrop
		}
	case ip4.ProtocolUDP:
		nextHeader = ip6.ProtoUDP
		if len(payload) < ip6.UDPHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count4To6[dropReason]++
			return nil, errors.ErrDrop
		}
	case ip4.ProtocolICMP:
		nextHeader = ip6.ProtoICMPv6
		if len(payload) < icmpHeaderSize {
			dropReason = DropReasonIllegalPacket
			t.errorCounters.Count4To6[dropReason]++
			return nil, errors.ErrDrop
		}
	default:
		dropReason = DropReasonUnsupportedProto
		t.errorCounters.Count4To6[dropReason]++
		return nil, errors.ErrDrop
	}

	translatedPayload := make([]byte, len(payload))
	copy(translatedPayload, payload)

	if ip4Proto == ip4.ProtocolICMP {
		if err := translateICMPv4ToICMPv6(translatedPayload); err != nil {
			dropReason = DropReasonUnsupportedProto
			t.errorCounters.Count4To6[dropReason]++
			return nil, errors.ErrDrop
		}
		// ICMPv6 uses a pseudo-header checksum.
		translatedPayload[2] = 0
		translatedPayload[3] = 0
		pseudo := ipv6PseudoHeaderChecksum(src6, m.ip6Addr, ip6.ProtoICMPv6,
			uint16(len(translatedPayload)))
		dataCsum := ip4.InternetChecksum(translatedPayload)
		combined := ip4.CombineChecksums(pseudo, dataCsum)
		encoding.BigEndianWriteUint16(combined, translatedPayload[2:4])
	} else {
		updateChecksumV4ToV6(translatedPayload, ip4Proto, src4, dst4,
			src6, m.ip6Addr, nextHeader, uint16(len(payload)))
	}

	// Build IPv6 header.
	result := make([]byte, ip6.HeaderSize+len(translatedPayload))

	// Byte 0-3: version(4) | TC(8) | flow(20).
	dscpEcn := (ip4Hdr.GetDscp() << 2) | uint8(ip4Hdr.GetEcn())
	result[0] = 0x60 | (dscpEcn >> 4)
	result[1] = dscpEcn << 4 // flow label = 0
	// bytes 2,3 = 0 (flow label)

	encoding.BigEndianWriteUint16(uint16(len(translatedPayload)), result[4:6])
	result[6] = nextHeader
	result[7] = ip4Hdr.GetTTL()

	copy(result[8:24], src6[:])
	copy(result[24:40], m.ip6Addr[:])
	copy(result[ip6.HeaderSize:], translatedPayload)

	payloadSize := totalLen - uint16(hdrLen)
	t.count4To6(ip4Proto, payloadSize)
	m.count4To6(ip4Proto, payloadSize)

	return result, nil
}

// ---------------------------------------------------------------------------
// ICMP translation (RFC 6145 Section 4)
// ---------------------------------------------------------------------------

func translateICMPv6ToICMPv4(payload []byte) error {
	if len(payload) < icmpHeaderSize {
		return errors.ErrParse
	}
	switch payload[0] {
	case icmp6EchoRequest:
		payload[0] = icmp4EchoRequest
	case icmp6EchoReply:
		payload[0] = icmp4EchoReply
	default:
		return errors.ErrInvalidArgs
	}
	return nil
}

func translateICMPv4ToICMPv6(payload []byte) error {
	if len(payload) < icmpHeaderSize {
		return errors.ErrParse
	}
	switch payload[0] {
	case icmp4EchoReply:
		payload[0] = icmp6EchoReply
	case icmp4EchoRequest:
		payload[0] = icmp6EchoRequest
	default:
		return errors.ErrInvalidArgs
	}
	return nil
}

// ---------------------------------------------------------------------------
// Checksum helpers
// ---------------------------------------------------------------------------

// ipv6PseudoHeaderChecksum computes the IPv6 pseudo-header contribution
// for upper-layer checksum calculation.
func ipv6PseudoHeaderChecksum(src, dst ip6.Address, nextHeader uint8, upperLayerLen uint16) uint16 {
	var pseudo [40]byte
	copy(pseudo[0:16], src[:])
	copy(pseudo[16:32], dst[:])
	encoding.BigEndianWriteUint32(uint32(upperLayerLen), pseudo[32:36])
	pseudo[39] = nextHeader
	return ip4.InternetChecksum(pseudo[:])
}

// updateChecksumV6ToV4 recalculates the TCP/UDP checksum when translating
// from IPv6 to IPv4 (pseudo-header changes from IPv6 to IPv4).
func updateChecksumV6ToV4(payload []byte, ip4Proto uint8,
	src6, dst6 ip6.Address, ip6NextHeader uint8,
	src4, dst4 ip4.Address, upperLen uint16) {

	csumOff := checksumOffset(ip4Proto)
	if csumOff < 0 || len(payload) < csumOff+2 {
		return
	}

	// Recompute from scratch with IPv4 pseudo-header.
	payload[csumOff] = 0
	payload[csumOff+1] = 0

	pCsum := ip4.PseudoHeaderChecksum(src4, dst4, ip4Proto, upperLen)
	dCsum := ip4.InternetChecksum(payload)
	combined := ip4.CombineChecksums(pCsum, dCsum)

	// UDP checksum of 0 means "no checksum" in IPv4; use 0xffff.
	if combined == 0 && ip4Proto == ip4.ProtocolUDP {
		combined = 0xffff
	}

	encoding.BigEndianWriteUint16(combined, payload[csumOff:csumOff+2])
}

// updateChecksumV4ToV6 recalculates the TCP/UDP checksum when translating
// from IPv4 to IPv6 (pseudo-header changes from IPv4 to IPv6).
func updateChecksumV4ToV6(payload []byte, ip4Proto uint8,
	src4, dst4 ip4.Address,
	src6, dst6 ip6.Address, ip6NextHeader uint8, upperLen uint16) {

	csumOff := checksumOffset(ip4Proto)
	if csumOff < 0 || len(payload) < csumOff+2 {
		return
	}

	payload[csumOff] = 0
	payload[csumOff+1] = 0

	pCsum := ipv6PseudoHeaderChecksum(src6, dst6, ip6NextHeader, upperLen)
	dCsum := ip4.InternetChecksum(payload)
	combined := ip4.CombineChecksums(pCsum, dCsum)

	encoding.BigEndianWriteUint16(combined, payload[csumOff:csumOff+2])
}

// checksumOffset returns the offset of the checksum field in TCP or UDP.
func checksumOffset(proto uint8) int {
	switch proto {
	case ip4.ProtocolTCP: // ip6.ProtoTCP is the same value (6)
		return 16
	case ip4.ProtocolUDP: // ip6.ProtoUDP is the same value (17)
		return 6
	default:
		return -1
	}
}
