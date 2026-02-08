// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package mle

import (
	"fmt"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
)

// Message represents an MLE message being constructed or parsed.
//
// Wire format:
//
//	SecuritySuite(1) + SecurityHeader(10) + Command(1) + TLVs... + MIC(4)
//
// For unsecured messages (Discovery):
//
//	SecuritySuite(1) + Command(1) + TLVs...
type Message struct {
	buf []byte
}

// headerOverhead is the size of the security suite byte + security header.
const headerOverhead = 1 + SecurityHeaderSize // 11

// NewMessage creates a new secured MLE message with the given command type.
// The returned message has the security suite and command byte set, with
// space reserved for the security header to be filled in during Finalize.
func NewMessage(command Command) *Message {
	// Allocate: SecuritySuite(1) + SecurityHeader(10) + Command(1)
	buf := make([]byte, 0, 128)
	buf = append(buf, SecuritySuiteEncMic32)
	// Reserve 10 bytes for the security header (filled during Finalize).
	buf = append(buf, make([]byte, SecurityHeaderSize)...)
	buf = append(buf, byte(command))

	return &Message{buf: buf}
}

// NewUnsecuredMessage creates a new unsecured MLE message (for Discovery).
func NewUnsecuredMessage(command Command) *Message {
	buf := make([]byte, 0, 64)
	buf = append(buf, SecuritySuiteNone)
	buf = append(buf, byte(command))
	return &Message{buf: buf}
}

// Command returns the command byte from the message.
func (m *Message) Command() Command {
	if m.IsSecured() {
		return Command(m.buf[headerOverhead])
	}
	return Command(m.buf[1])
}

// IsSecured returns true if the message uses security (SecuritySuiteEncMic32).
func (m *Message) IsSecured() bool {
	return len(m.buf) > 0 && m.buf[0] == SecuritySuiteEncMic32
}

// Bytes returns the raw message buffer.
func (m *Message) Bytes() []byte {
	return m.buf
}

// Payload returns the command byte + TLVs portion (the part that gets encrypted).
func (m *Message) Payload() []byte {
	if m.IsSecured() {
		return m.buf[headerOverhead:]
	}
	return m.buf[1:]
}

// --- TLV append methods ---

// appendTLV appends a type-length-value triple to the message.
func (m *Message) appendTLV(tlvType uint8, value []byte) {
	m.buf = append(m.buf, tlvType, byte(len(value)))
	m.buf = append(m.buf, value...)
}

// AppendSourceAddressTLV appends a Source Address TLV (2-byte RLOC16).
func (m *Message) AppendSourceAddressTLV(rloc16 uint16) {
	var val [2]byte
	encoding.BigEndianWriteUint16(rloc16, val[:])
	m.appendTLV(TLVSourceAddress, val[:])
}

// AppendModeTLV appends a Mode TLV (1-byte device mode flags).
func (m *Message) AppendModeTLV(mode DeviceMode) {
	m.appendTLV(TLVMode, []byte{mode.Get()})
}

// AppendTimeoutTLV appends a Timeout TLV (4-byte seconds, big-endian).
func (m *Message) AppendTimeoutTLV(timeout uint32) {
	var val [4]byte
	encoding.BigEndianWriteUint32(timeout, val[:])
	m.appendTLV(TLVTimeout, val[:])
}

// AppendChallengeTLV appends a Challenge TLV (8-byte random value).
func (m *Message) AppendChallengeTLV(challenge Challenge) {
	m.appendTLV(TLVChallenge, challenge[:])
}

// AppendResponseTLV appends a Response TLV (echo of a received challenge).
func (m *Message) AppendResponseTLV(response []byte) {
	m.appendTLV(TLVResponse, response)
}

// AppendLinkFrameCounterTLV appends a Link Frame Counter TLV (4-byte big-endian).
func (m *Message) AppendLinkFrameCounterTLV(counter uint32) {
	var val [4]byte
	encoding.BigEndianWriteUint32(counter, val[:])
	m.appendTLV(TLVLinkFrameCounter, val[:])
}

// AppendMleFrameCounterTLV appends an MLE Frame Counter TLV (4-byte big-endian).
func (m *Message) AppendMleFrameCounterTLV(counter uint32) {
	var val [4]byte
	encoding.BigEndianWriteUint32(counter, val[:])
	m.appendTLV(TLVMleFrameCounter, val[:])
}

// AppendAddress16TLV appends an Address16 TLV (2-byte RLOC16, big-endian).
func (m *Message) AppendAddress16TLV(rloc16 uint16) {
	var val [2]byte
	encoding.BigEndianWriteUint16(rloc16, val[:])
	m.appendTLV(TLVAddress16, val[:])
}

// AppendLeaderDataTLV appends a Leader Data TLV (8 bytes).
func (m *Message) AppendLeaderDataTLV(ld LeaderData) {
	var val [LeaderDataTLVSize]byte
	encoding.BigEndianWriteUint32(ld.PartitionID, val[0:4])
	val[4] = ld.Weighting
	val[5] = ld.DataVersion
	val[6] = ld.StableDataVersion
	val[7] = ld.LeaderRouterID
	m.appendTLV(TLVLeaderData, val[:])
}

// AppendNetworkDataTLV appends a Network Data TLV (variable-length raw bytes).
func (m *Message) AppendNetworkDataTLV(data []byte) {
	m.appendTLV(TLVNetworkData, data)
}

// AppendTLVRequestTLV appends a TLV Request TLV (list of requested TLV types).
func (m *Message) AppendTLVRequestTLV(types []uint8) {
	m.appendTLV(TLVTLVRequest, types)
}

// AppendScanMaskTLV appends a Scan Mask TLV (1 byte).
func (m *Message) AppendScanMaskTLV(mask uint8) {
	m.appendTLV(TLVScanMask, []byte{mask})
}

// AppendLinkMarginTLV appends a Link Margin TLV (1 byte).
func (m *Message) AppendLinkMarginTLV(margin uint8) {
	m.appendTLV(TLVLinkMargin, []byte{margin})
}

// AppendStatusTLV appends a Status TLV (1 byte).
func (m *Message) AppendStatusTLV(status uint8) {
	m.appendTLV(TLVStatus, []byte{status})
}

// AppendVersionTLV appends a Version TLV (2-byte protocol version, big-endian).
func (m *Message) AppendVersionTLV(version uint16) {
	var val [2]byte
	encoding.BigEndianWriteUint16(version, val[:])
	m.appendTLV(TLVVersion, val[:])
}

// AppendChannelTLV appends a Channel TLV (3 bytes: page + channel).
func (m *Message) AppendChannelTLV(channelPage uint8, channel uint16) {
	var val [3]byte
	val[0] = channelPage
	encoding.BigEndianWriteUint16(channel, val[1:3])
	m.appendTLV(TLVChannel, val[:])
}

// AppendPanIDTLV appends a PAN ID TLV (2-byte big-endian).
func (m *Message) AppendPanIDTLV(panID uint16) {
	var val [2]byte
	encoding.BigEndianWriteUint16(panID, val[:])
	m.appendTLV(TLVPanID, val[:])
}

// AppendActiveTimestampTLV appends an Active Timestamp TLV (8 bytes).
func (m *Message) AppendActiveTimestampTLV(ts *meshcop.Timestamp) error {
	data, err := ts.MarshalBinary()
	if err != nil {
		return fmt.Errorf("mle: marshal active timestamp: %w", err)
	}
	m.appendTLV(TLVActiveTimestamp, data)
	return nil
}

// AppendPendingTimestampTLV appends a Pending Timestamp TLV (8 bytes).
func (m *Message) AppendPendingTimestampTLV(ts *meshcop.Timestamp) error {
	data, err := ts.MarshalBinary()
	if err != nil {
		return fmt.Errorf("mle: marshal pending timestamp: %w", err)
	}
	m.appendTLV(TLVPendingTimestamp, data)
	return nil
}

// AppendSupervisionIntervalTLV appends a Supervision Interval TLV (2-byte big-endian).
func (m *Message) AppendSupervisionIntervalTLV(interval uint16) {
	var val [2]byte
	encoding.BigEndianWriteUint16(interval, val[:])
	m.appendTLV(TLVSupervisionInterval, val[:])
}

// Route64Entry represents a single router entry in the Route64 TLV.
type Route64Entry struct {
	// LinkQualityOut is the outgoing link quality (0-3).
	LinkQualityOut uint8

	// LinkQualityIn is the incoming link quality (0-3).
	LinkQualityIn uint8

	// Cost is the route cost (0-15).
	Cost uint8
}

// AppendRoute64TLV appends a Route64 TLV.
// routerIDSequence is the sequence number, routerIDMask is the 64-bit set,
// and entries provides cost/quality per allocated router in mask order.
func (m *Message) AppendRoute64TLV(routerIDSequence uint8, routerIDMask RouterIDSet, entries []Route64Entry) {
	// 1 byte sequence + 8 bytes mask + 1 byte per entry.
	val := make([]byte, 0, 1+8+len(entries))
	val = append(val, routerIDSequence)
	val = append(val, routerIDMask[:]...)
	for _, e := range entries {
		b := (e.LinkQualityOut & 0x03) << Route64EntryLinkQualityOutShift
		b |= (e.LinkQualityIn & 0x03) << Route64EntryLinkQualityInShift
		b |= e.Cost & Route64EntryCostMask
		val = append(val, b)
	}
	m.appendTLV(TLVRoute64, val)
}

// ConnectivityTLV holds the data for an MLE Connectivity TLV.
type ConnectivityTLV struct {
	// Flags contains the parent priority bits.
	Flags uint8

	// LinkQuality3 is the count of neighbors with link quality 3.
	LinkQuality3 uint8

	// LinkQuality2 is the count of neighbors with link quality 2.
	LinkQuality2 uint8

	// LinkQuality1 is the count of neighbors with link quality 1.
	LinkQuality1 uint8

	// LeaderCost is the cost to reach the leader.
	LeaderCost uint8

	// IDSequence is the router ID sequence number.
	IDSequence uint8

	// ActiveRouters is the number of active routers.
	ActiveRouters uint8

	// SEDBufferSize is the optional SED buffer size (0 if not present).
	SEDBufferSize uint16

	// SEDDatagramCount is the optional SED datagram count (0 if not present).
	SEDDatagramCount uint8
}

// AppendConnectivityTLV appends a Connectivity TLV.
// If sedBufferSize > 0 or sedDatagramCount > 0, the optional SED fields are included.
func (m *Message) AppendConnectivityTLV(c ConnectivityTLV) {
	includeSED := c.SEDBufferSize > 0 || c.SEDDatagramCount > 0
	size := ConnectivityTLVMinSize
	if includeSED {
		size = ConnectivityTLVMaxSize
	}

	val := make([]byte, size)
	val[0] = c.Flags
	val[1] = c.LinkQuality3
	val[2] = c.LinkQuality2
	val[3] = c.LinkQuality1
	val[4] = c.LeaderCost
	val[5] = c.IDSequence
	val[6] = c.ActiveRouters

	if includeSED {
		encoding.BigEndianWriteUint16(c.SEDBufferSize, val[7:9])
		val[9] = c.SEDDatagramCount
	}

	m.appendTLV(TLVConnectivity, val)
}

// AddressRegistrationEntry represents one entry in the Address Registration TLV.
type AddressRegistrationEntry struct {
	// Compressed indicates whether this is a compressed (context + IID) or full entry.
	Compressed bool

	// ContextID is the 6LoWPAN context ID (only used when Compressed is true).
	ContextID uint8

	// IID is the interface identifier (only used when Compressed is true).
	IID [8]byte

	// Address is the full IPv6 address (only used when Compressed is false).
	Address ip6.Address
}

// AppendAddressRegistrationTLV appends an Address Registration TLV with the given entries.
func (m *Message) AppendAddressRegistrationTLV(entries []AddressRegistrationEntry) {
	var val []byte
	for _, e := range entries {
		if e.Compressed {
			val = append(val, AddressRegistrationCompressed|e.ContextID)
			val = append(val, e.IID[:]...)
		} else {
			val = append(val, AddressRegistrationFull)
			val = append(val, e.Address[:]...)
		}
	}
	m.appendTLV(TLVAddressRegistration, val)
}

// --- TLV parsing ---

// TLV represents a single parsed MLE TLV.
type TLV struct {
	// Type is the TLV type code.
	Type uint8

	// Value is the TLV value bytes (without type and length bytes).
	Value []byte
}

// ParseTLVs parses a sequence of TLVs from the given buffer.
// The buffer should contain only TLV data (no security suite, header, or command).
func ParseTLVs(data []byte) ([]TLV, error) {
	var tlvs []TLV
	offset := 0
	for offset < len(data) {
		if offset+2 > len(data) {
			return nil, fmt.Errorf("mle: truncated TLV at offset %d", offset)
		}
		t := data[offset]
		l := int(data[offset+1])
		offset += 2
		if offset+l > len(data) {
			return nil, fmt.Errorf("mle: TLV type %d length %d exceeds buffer at offset %d",
				t, l, offset-2)
		}
		tlvs = append(tlvs, TLV{Type: t, Value: data[offset : offset+l]})
		offset += l
	}
	return tlvs, nil
}

// FindTLV searches for a TLV with the given type in a parsed TLV list.
// Returns the TLV value and true if found, nil and false otherwise.
func FindTLV(tlvs []TLV, tlvType uint8) ([]byte, bool) {
	for _, t := range tlvs {
		if t.Type == tlvType {
			return t.Value, true
		}
	}
	return nil, false
}

// --- TLV read helpers ---

// ReadSourceAddressTLV reads an RLOC16 from a Source Address TLV value.
func ReadSourceAddressTLV(value []byte) (uint16, error) {
	if len(value) < 2 {
		return 0, fmt.Errorf("mle: SourceAddress TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint16(value), nil
}

// ReadModeTLV reads a DeviceMode from a Mode TLV value.
func ReadModeTLV(value []byte) (DeviceMode, error) {
	if len(value) < 1 {
		return DeviceMode{}, fmt.Errorf("mle: Mode TLV too short: %d", len(value))
	}
	return NewDeviceMode(value[0]), nil
}

// ReadTimeoutTLV reads a timeout in seconds from a Timeout TLV value.
func ReadTimeoutTLV(value []byte) (uint32, error) {
	if len(value) < 4 {
		return 0, fmt.Errorf("mle: Timeout TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint32(value), nil
}

// ReadChallengeTLV reads a Challenge from a Challenge TLV value.
func ReadChallengeTLV(value []byte) (Challenge, error) {
	var c Challenge
	if len(value) < len(c) {
		return c, fmt.Errorf("mle: Challenge TLV too short: %d", len(value))
	}
	copy(c[:], value)
	return c, nil
}

// ReadLinkFrameCounterTLV reads a frame counter from a LinkFrameCounter TLV value.
func ReadLinkFrameCounterTLV(value []byte) (uint32, error) {
	if len(value) < 4 {
		return 0, fmt.Errorf("mle: LinkFrameCounter TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint32(value), nil
}

// ReadMleFrameCounterTLV reads a frame counter from an MleFrameCounter TLV value.
func ReadMleFrameCounterTLV(value []byte) (uint32, error) {
	if len(value) < 4 {
		return 0, fmt.Errorf("mle: MleFrameCounter TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint32(value), nil
}

// ReadAddress16TLV reads an RLOC16 from an Address16 TLV value.
func ReadAddress16TLV(value []byte) (uint16, error) {
	if len(value) < 2 {
		return 0, fmt.Errorf("mle: Address16 TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint16(value), nil
}

// ReadLeaderDataTLV reads a LeaderData from a LeaderData TLV value.
func ReadLeaderDataTLV(value []byte) (LeaderData, error) {
	if len(value) < LeaderDataTLVSize {
		return LeaderData{}, fmt.Errorf("mle: LeaderData TLV too short: %d", len(value))
	}
	return LeaderData{
		PartitionID:       encoding.BigEndianReadUint32(value[0:4]),
		Weighting:         value[4],
		DataVersion:       value[5],
		StableDataVersion: value[6],
		LeaderRouterID:    value[7],
	}, nil
}

// ReadVersionTLV reads a protocol version from a Version TLV value.
func ReadVersionTLV(value []byte) (uint16, error) {
	if len(value) < 2 {
		return 0, fmt.Errorf("mle: Version TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint16(value), nil
}

// ReadLinkMarginTLV reads a link margin from a LinkMargin TLV value.
func ReadLinkMarginTLV(value []byte) (uint8, error) {
	if len(value) < 1 {
		return 0, fmt.Errorf("mle: LinkMargin TLV too short: %d", len(value))
	}
	return value[0], nil
}

// ReadStatusTLV reads a status code from a Status TLV value.
func ReadStatusTLV(value []byte) (uint8, error) {
	if len(value) < 1 {
		return 0, fmt.Errorf("mle: Status TLV too short: %d", len(value))
	}
	return value[0], nil
}

// ReadScanMaskTLV reads a scan mask from a ScanMask TLV value.
func ReadScanMaskTLV(value []byte) (uint8, error) {
	if len(value) < 1 {
		return 0, fmt.Errorf("mle: ScanMask TLV too short: %d", len(value))
	}
	return value[0], nil
}

// ReadChannelTLV reads channel page and channel from a Channel TLV value.
func ReadChannelTLV(value []byte) (channelPage uint8, channel uint16, err error) {
	if len(value) < 3 {
		return 0, 0, fmt.Errorf("mle: Channel TLV too short: %d", len(value))
	}
	return value[0], encoding.BigEndianReadUint16(value[1:3]), nil
}

// ReadPanIDTLV reads a PAN ID from a PanID TLV value.
func ReadPanIDTLV(value []byte) (uint16, error) {
	if len(value) < 2 {
		return 0, fmt.Errorf("mle: PanID TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint16(value), nil
}

// ReadActiveTimestampTLV reads a Timestamp from an ActiveTimestamp TLV value.
func ReadActiveTimestampTLV(value []byte) (*meshcop.Timestamp, error) {
	ts := &meshcop.Timestamp{}
	if err := ts.UnmarshalBinary(value); err != nil {
		return nil, fmt.Errorf("mle: read active timestamp: %w", err)
	}
	return ts, nil
}

// ReadPendingTimestampTLV reads a Timestamp from a PendingTimestamp TLV value.
func ReadPendingTimestampTLV(value []byte) (*meshcop.Timestamp, error) {
	ts := &meshcop.Timestamp{}
	if err := ts.UnmarshalBinary(value); err != nil {
		return nil, fmt.Errorf("mle: read pending timestamp: %w", err)
	}
	return ts, nil
}

// ReadSupervisionIntervalTLV reads an interval from a SupervisionInterval TLV value.
func ReadSupervisionIntervalTLV(value []byte) (uint16, error) {
	if len(value) < 2 {
		return 0, fmt.Errorf("mle: SupervisionInterval TLV too short: %d", len(value))
	}
	return encoding.BigEndianReadUint16(value), nil
}

// ReadRoute64TLV parses a Route64 TLV value into its components.
func ReadRoute64TLV(value []byte) (routerIDSequence uint8, routerIDMask RouterIDSet, entries []Route64Entry, err error) {
	if len(value) < 9 {
		return 0, RouterIDSet{}, nil, fmt.Errorf("mle: Route64 TLV too short: %d", len(value))
	}

	routerIDSequence = value[0]
	copy(routerIDMask[:], value[1:9])

	entryData := value[9:]
	entries = make([]Route64Entry, len(entryData))
	for i, b := range entryData {
		entries[i] = Route64Entry{
			LinkQualityOut: (b >> Route64EntryLinkQualityOutShift) & 0x03,
			LinkQualityIn:  (b >> Route64EntryLinkQualityInShift) & 0x03,
			Cost:           b & Route64EntryCostMask,
		}
	}
	return routerIDSequence, routerIDMask, entries, nil
}

// ReadConnectivityTLV parses a Connectivity TLV value.
func ReadConnectivityTLV(value []byte) (ConnectivityTLV, error) {
	if len(value) < ConnectivityTLVMinSize {
		return ConnectivityTLV{}, fmt.Errorf("mle: Connectivity TLV too short: %d", len(value))
	}

	c := ConnectivityTLV{
		Flags:         value[0],
		LinkQuality3:  value[1],
		LinkQuality2:  value[2],
		LinkQuality1:  value[3],
		LeaderCost:    value[4],
		IDSequence:    value[5],
		ActiveRouters: value[6],
	}

	if len(value) >= ConnectivityTLVMaxSize {
		c.SEDBufferSize = encoding.BigEndianReadUint16(value[7:9])
		c.SEDDatagramCount = value[9]
	}

	return c, nil
}

// ReadAddressRegistrationTLV parses an Address Registration TLV value.
func ReadAddressRegistrationTLV(value []byte) ([]AddressRegistrationEntry, error) {
	var entries []AddressRegistrationEntry
	offset := 0

	for offset < len(value) {
		if offset >= len(value) {
			break
		}
		control := value[offset]
		offset++

		if control&AddressRegistrationCompressed != 0 {
			// Compressed: contextID + 8-byte IID
			if offset+8 > len(value) {
				return nil, fmt.Errorf("mle: AddressRegistration compressed entry truncated at offset %d", offset-1)
			}
			e := AddressRegistrationEntry{
				Compressed: true,
				ContextID:  control & 0x0F,
			}
			copy(e.IID[:], value[offset:offset+8])
			offset += 8
			entries = append(entries, e)
		} else {
			// Full: 16-byte IPv6 address
			if offset+16 > len(value) {
				return nil, fmt.Errorf("mle: AddressRegistration full entry truncated at offset %d", offset-1)
			}
			e := AddressRegistrationEntry{
				Compressed: false,
			}
			copy(e.Address[:], value[offset:offset+16])
			offset += 16
			entries = append(entries, e)
		}
	}

	return entries, nil
}

// --- Finalize: fill security header and encrypt ---

// Finalize fills in the security header with the given parameters and
// encrypts the message payload (command + TLVs) in place, appending
// the 4-byte MIC.
//
// After Finalize, Bytes() returns the complete wire-format message ready
// to be sent over UDP.
func (m *Message) Finalize(secHdr SecurityHeader, mleKey [16]byte, srcAddr [8]byte, srcIP, dstIP ip6.Address) error {
	if !m.IsSecured() {
		return fmt.Errorf("mle: cannot finalize unsecured message")
	}

	// 1. Write security header into reserved space.
	hdr := secHdr.Marshal()
	copy(m.buf[1:1+SecurityHeaderSize], hdr[:])

	// 2. Build nonce and AAD.
	nonce := BuildNonce(srcAddr, secHdr.FrameCounter)
	aad := BuildAAD(srcIP, dstIP, hdr)

	// 3. Encrypt the payload (command byte + TLVs).
	payload := m.buf[headerOverhead:]

	ciphertext, tag, err := Encrypt(mleKey, nonce, aad[:], payload)
	if err != nil {
		return err
	}

	// 4. Replace plaintext with ciphertext and append MIC.
	copy(m.buf[headerOverhead:], ciphertext)
	m.buf = append(m.buf, tag[:]...)

	return nil
}

// ParsedMessage holds the fields extracted from a received MLE message.
//
// For secured messages, it contains the security header and the
// encrypted payload with MIC for later decryption.
// For unsecured messages, it contains the plaintext payload directly.
type ParsedMessage struct {
	// SecuritySuite is the security suite byte (0x00 or 0xFF).
	SecuritySuite uint8

	// SecHeader is the parsed security header (only valid if SecuritySuite == 0x00).
	SecHeader SecurityHeader

	// Payload is the (possibly encrypted) command + TLVs.
	// For secured messages, this is the ciphertext.
	// For unsecured messages, this is the plaintext.
	Payload []byte

	// Tag is the 4-byte authentication tag (only valid if SecuritySuite == 0x00).
	Tag [SecurityTagSize]byte
}

// ParseMessage parses a raw MLE message from wire bytes.
func ParseMessage(data []byte) (*ParsedMessage, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("mle: message too short")
	}

	pm := &ParsedMessage{
		SecuritySuite: data[0],
	}

	switch data[0] {
	case SecuritySuiteEncMic32:
		// Minimum: suite(1) + secHeader(10) + command(1) + mic(4) = 16
		minLen := 1 + SecurityHeaderSize + 1 + SecurityTagSize
		if len(data) < minLen {
			return nil, fmt.Errorf("mle: secured message too short: %d < %d", len(data), minLen)
		}

		if err := pm.SecHeader.Unmarshal(data[1 : 1+SecurityHeaderSize]); err != nil {
			return nil, err
		}

		// Payload is everything between the security header and the MIC.
		payloadEnd := len(data) - SecurityTagSize
		pm.Payload = data[headerOverhead:payloadEnd]
		copy(pm.Tag[:], data[payloadEnd:])

	case SecuritySuiteNone:
		if len(data) < 2 {
			return nil, fmt.Errorf("mle: unsecured message too short: %d", len(data))
		}
		pm.Payload = data[1:]

	default:
		return nil, fmt.Errorf("mle: unknown security suite 0x%02X", data[0])
	}

	return pm, nil
}

// DecryptPayload decrypts a parsed secured message's payload.
// Returns the plaintext (command byte + TLVs).
func (pm *ParsedMessage) DecryptPayload(mleKey [16]byte, srcAddr [8]byte, srcIP, dstIP ip6.Address, secHdrBytes [SecurityHeaderSize]byte) ([]byte, error) {
	if pm.SecuritySuite != SecuritySuiteEncMic32 {
		return nil, fmt.Errorf("mle: cannot decrypt unsecured message")
	}

	nonce := BuildNonce(srcAddr, pm.SecHeader.FrameCounter)
	aad := BuildAAD(srcIP, dstIP, secHdrBytes)

	return Decrypt(mleKey, nonce, aad[:], pm.Payload, pm.Tag)
}
