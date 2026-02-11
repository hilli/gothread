// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the name of the copyright holder nor the
//    names of its contributors may be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package mdns

import (
	"encoding/binary"
	"strings"
)

// ---------------------------------------------------------------------------
// DNS wire-format constants
// ---------------------------------------------------------------------------

const (
	headerSize       = 12  // DNS header is 12 bytes.
	maxLabelLen      = 63  // Maximum label length per RFC 1035.
	maxNameWireLen   = 255 // Maximum wire-encoded name length.
	maxUDPSize       = 9000
	pointerMask      = 0xC0
	pointerOffsetMax = 0x3FFF
)

// Flag bit positions within the header.
const (
	qrBit = 0x80 // Flags[0]: query/response flag.
	aaBit = 0x04 // Flags[0]: authoritative answer.
	tcBit = 0x02 // Flags[0]: truncated.
)

// ---------------------------------------------------------------------------
// msgHeader — 12-byte DNS message header (RFC 1035 4.1.1)
// ---------------------------------------------------------------------------

// msgHeader represents the fixed 12-byte DNS message header.
type msgHeader struct {
	ID      uint16
	Flags   [2]byte
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

func (h *msgHeader) isResponse() bool { return h.Flags[0]&qrBit != 0 }
func (h *msgHeader) isQuery() bool    { return !h.isResponse() }

func (h *msgHeader) setResponse() { h.Flags[0] |= qrBit }

func (h *msgHeader) setAA() { h.Flags[0] |= aaBit }

func (h *msgHeader) isTruncated() bool { return h.Flags[0]&tcBit != 0 }
func (h *msgHeader) setTruncated()     { h.Flags[0] |= tcBit }

func (h *msgHeader) marshal() []byte {
	b := make([]byte, headerSize)
	binary.BigEndian.PutUint16(b[0:2], h.ID)
	b[2] = h.Flags[0]
	b[3] = h.Flags[1]
	binary.BigEndian.PutUint16(b[4:6], h.QDCount)
	binary.BigEndian.PutUint16(b[6:8], h.ANCount)
	binary.BigEndian.PutUint16(b[8:10], h.NSCount)
	binary.BigEndian.PutUint16(b[10:12], h.ARCount)
	return b
}

func unmarshalHeader(b []byte) (msgHeader, bool) {
	if len(b) < headerSize {
		return msgHeader{}, false
	}
	var h msgHeader
	h.ID = binary.BigEndian.Uint16(b[0:2])
	h.Flags[0] = b[2]
	h.Flags[1] = b[3]
	h.QDCount = binary.BigEndian.Uint16(b[4:6])
	h.ANCount = binary.BigEndian.Uint16(b[6:8])
	h.NSCount = binary.BigEndian.Uint16(b[8:10])
	h.ARCount = binary.BigEndian.Uint16(b[10:12])
	return h, true
}

// ---------------------------------------------------------------------------
// question — a DNS question entry
// ---------------------------------------------------------------------------

type question struct {
	Name  string
	Type  uint16
	Class uint16
}

// ---------------------------------------------------------------------------
// resourceRecord — a parsed DNS resource record
// ---------------------------------------------------------------------------

type resourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// ---------------------------------------------------------------------------
// parsedMessage — a fully parsed DNS message
// ---------------------------------------------------------------------------

type parsedMessage struct {
	Header      msgHeader
	Questions   []question
	Answers     []resourceRecord
	Authorities []resourceRecord
	Additionals []resourceRecord
}

// ---------------------------------------------------------------------------
// Name encoding (RFC 1035 Section 4.1.4)
// ---------------------------------------------------------------------------

// encodeName converts a dotted name (e.g. "myhost.local") to DNS wire
// format without compression. The result includes a trailing zero-length
// label.
func encodeName(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	// Strip trailing dot for processing.
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")
	var buf []byte
	for _, label := range labels {
		n := len(label)
		if n == 0 || n > maxLabelLen {
			return nil, errInvalidName
		}
		buf = append(buf, byte(n))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // root label
	return buf, nil
}

// encodeNameLabel encodes a single label (which may contain dots, for
// service instance names) into wire format as a single DNS label.
func encodeNameLabel(label string) ([]byte, error) {
	n := len(label)
	if n == 0 || n > maxLabelLen {
		return nil, errInvalidName
	}
	buf := make([]byte, 0, n+1)
	buf = append(buf, byte(n))
	buf = append(buf, label...)
	return buf, nil
}

// ---------------------------------------------------------------------------
// Name compression (RFC 1035 Section 4.1.4)
// ---------------------------------------------------------------------------

// compressor tracks label offsets for DNS name compression.
type compressor struct {
	offsets map[string]uint16 // lowercased suffix -> offset
}

func newCompressor() *compressor {
	return &compressor{offsets: make(map[string]uint16)}
}

// appendName encodes a DNS name with compression, appending to buf.
// It records label offsets for later pointer references.
func (c *compressor) appendName(buf []byte, name string) ([]byte, error) {
	if name == "" || name == "." {
		return append(buf, 0), nil
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")

	for i := 0; i < len(labels); i++ {
		// Build the suffix from labels[i:].
		suffix := strings.ToLower(strings.Join(labels[i:], "."))
		if off, ok := c.offsets[suffix]; ok && off <= pointerOffsetMax {
			// Emit pointer.
			ptr := 0xC000 | off
			buf = append(buf, byte(ptr>>8), byte(ptr))
			return buf, nil
		}
		// Record offset of this suffix.
		curOff := len(buf)
		if curOff <= pointerOffsetMax {
			c.offsets[suffix] = uint16(curOff)
		}
		// Emit label.
		lbl := labels[i]
		n := len(lbl)
		if n == 0 || n > maxLabelLen {
			return nil, errInvalidName
		}
		buf = append(buf, byte(n))
		buf = append(buf, lbl...)
	}
	buf = append(buf, 0) // root label
	return buf, nil
}

// appendServiceInstanceName encodes "<instance>.<service>.<domain>" where
// instance is treated as a single label (may contain dots).
func (c *compressor) appendServiceInstanceName(buf []byte, instance, serviceType, domain string) ([]byte, error) {
	// Encode the instance as a single label.
	n := len(instance)
	if n == 0 || n > maxLabelLen {
		return nil, errInvalidName
	}

	// Check for pointer to the rest of the name (service.domain).
	rest := strings.ToLower(serviceType + "." + strings.TrimSuffix(domain, "."))
	if off, ok := c.offsets[rest]; ok && off <= pointerOffsetMax {
		curOff := len(buf)
		instLower := strings.ToLower(instance) + "." + rest
		if curOff <= pointerOffsetMax {
			c.offsets[instLower] = uint16(curOff)
		}
		buf = append(buf, byte(n))
		buf = append(buf, instance...)
		ptr := 0xC000 | off
		buf = append(buf, byte(ptr>>8), byte(ptr))
		return buf, nil
	}

	// No compression available; encode fully.
	fullName := instance + "." + serviceType + "." + domain
	return c.appendName(buf, fullName)
}

// ---------------------------------------------------------------------------
// Name decoding
// ---------------------------------------------------------------------------

// decodeName reads a DNS name from data starting at offset, following
// compression pointers. Returns the name and the number of bytes consumed
// at the original position (before any pointer jumps).
func decodeName(data []byte, offset int) (string, int, error) {
	var labels []string
	visited := make(map[int]bool) // detect pointer loops
	pos := offset
	jumped := false
	consumed := 0 // bytes consumed at original position

	for {
		if pos >= len(data) {
			return "", 0, errTruncated
		}
		length := int(data[pos])

		if length == 0 {
			if !jumped {
				consumed = pos - offset + 1
			}
			break
		}

		if length&pointerMask == pointerMask {
			// Compression pointer.
			if pos+1 >= len(data) {
				return "", 0, errTruncated
			}
			if !jumped {
				consumed = pos - offset + 2
			}
			ptr := int(binary.BigEndian.Uint16(data[pos:pos+2])) & pointerOffsetMax
			if visited[ptr] {
				return "", 0, errInvalidName // pointer loop
			}
			visited[ptr] = true
			pos = ptr
			jumped = true
			continue
		}

		if length > maxLabelLen {
			return "", 0, errInvalidName
		}
		pos++
		if pos+length > len(data) {
			return "", 0, errTruncated
		}
		labels = append(labels, string(data[pos:pos+length]))
		pos += length
	}

	name := strings.Join(labels, ".")
	return name, consumed, nil
}

// ---------------------------------------------------------------------------
// Record encoding helpers
// ---------------------------------------------------------------------------

// appendQuestion appends a DNS question to buf using the compressor.
func (c *compressor) appendQuestion(buf []byte, name string, qtype, qclass uint16) ([]byte, error) {
	var err error
	buf, err = c.appendName(buf, name)
	if err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, qclass)
	return buf, nil
}

// appendRecord appends a DNS resource record to buf using the compressor.
func (c *compressor) appendRecord(buf []byte, name string, rtype, rclass uint16, ttl uint32, rdata []byte) ([]byte, error) {
	var err error
	buf, err = c.appendName(buf, name)
	if err != nil {
		return nil, err
	}
	buf = binary.BigEndian.AppendUint16(buf, rtype)
	buf = binary.BigEndian.AppendUint16(buf, rclass)
	buf = binary.BigEndian.AppendUint32(buf, ttl)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(rdata)))
	buf = append(buf, rdata...)
	return buf, nil
}

// ---------------------------------------------------------------------------
// Record RDATA builders
// ---------------------------------------------------------------------------

// buildAAAARData builds the RDATA for an AAAA record (16-byte IPv6 address).
func buildAAAARData(ip []byte) []byte {
	if len(ip) < 16 {
		return nil
	}
	rdata := make([]byte, 16)
	copy(rdata, ip[:16])
	return rdata
}

// buildARData builds the RDATA for an A record (4-byte IPv4 address).
func buildARData(ip []byte) []byte {
	if len(ip) < 4 {
		return nil
	}
	rdata := make([]byte, 4)
	copy(rdata, ip[:4])
	return rdata
}

// buildPTRRData builds the RDATA for a PTR record — a DNS name.
func buildPTRRData(name string) ([]byte, error) {
	return encodeName(name)
}

// buildSRVRData builds the RDATA for an SRV record.
func buildSRVRData(priority, weight, port uint16, target string) ([]byte, error) {
	targetWire, err := encodeName(target)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 6, 6+len(targetWire))
	binary.BigEndian.PutUint16(buf[0:2], priority)
	binary.BigEndian.PutUint16(buf[2:4], weight)
	binary.BigEndian.PutUint16(buf[4:6], port)
	buf = append(buf, targetWire...)
	return buf, nil
}

// buildTXTRData encodes TXT data. If data is nil/empty, returns a single
// zero-length string per RFC 6763.
func buildTXTRData(data []byte) []byte {
	if len(data) == 0 {
		return []byte{0}
	}
	rdata := make([]byte, len(data))
	copy(rdata, data)
	return rdata
}

// buildKeyRData wraps raw key data.
func buildKeyRData(keyData []byte) []byte {
	rdata := make([]byte, len(keyData))
	copy(rdata, keyData)
	return rdata
}

// buildNSECRData builds a minimal NSEC record for the given owner name
// and set of record types to assert non-existence of other types.
func buildNSECRData(ownerName string, rrTypes []uint16) ([]byte, error) {
	nameWire, err := encodeName(ownerName)
	if err != nil {
		return nil, err
	}

	// Build the type bitmap: we only need window 0 (types 0-255).
	var bitmapBuf [32]byte // window 0: 256 bits = 32 bytes
	maxByte := 0
	for _, t := range rrTypes {
		if t > 255 {
			continue // Only window 0
		}
		byteIdx := int(t / 8)
		bitIdx := 7 - (t % 8)
		bitmapBuf[byteIdx] |= 1 << bitIdx
		if byteIdx > maxByte {
			maxByte = byteIdx
		}
	}
	bitmapLen := maxByte + 1

	// NSEC RDATA: next domain name + type bitmap blocks
	// Window block: window=0, length=bitmapLen, bitmap
	buf := make([]byte, 0, len(nameWire)+2+bitmapLen)
	buf = append(buf, nameWire...)
	buf = append(buf, 0)               // window number 0
	buf = append(buf, byte(bitmapLen)) // bitmap length
	buf = append(buf, bitmapBuf[:bitmapLen]...)
	return buf, nil
}

// ---------------------------------------------------------------------------
// Record RDATA parsers
// ---------------------------------------------------------------------------

// parseSRVRData parses an SRV RDATA field.
func parseSRVRData(rdata []byte) (priority, weight, port uint16, target string, err error) {
	if len(rdata) < 7 { // 6 bytes + at least 1 for name
		return 0, 0, 0, "", errTruncated
	}
	priority = binary.BigEndian.Uint16(rdata[0:2])
	weight = binary.BigEndian.Uint16(rdata[2:4])
	port = binary.BigEndian.Uint16(rdata[4:6])
	target, _, err = decodeName(rdata, 6)
	return
}

// parsePTRRData parses a PTR RDATA field.
func parsePTRRData(rdata []byte) (string, error) {
	name, _, err := decodeName(rdata, 0)
	return name, err
}

// ---------------------------------------------------------------------------
// Message parsing
// ---------------------------------------------------------------------------

// parseMessage fully parses a DNS/mDNS message from wire format.
func parseMessage(data []byte) (*parsedMessage, error) {
	hdr, ok := unmarshalHeader(data)
	if !ok {
		return nil, errTruncated
	}

	msg := &parsedMessage{Header: hdr}
	offset := headerSize

	// Parse questions.
	for i := 0; i < int(hdr.QDCount); i++ {
		name, consumed, err := decodeName(data, offset)
		if err != nil {
			return nil, err
		}
		offset += consumed
		if offset+4 > len(data) {
			return nil, errTruncated
		}
		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		msg.Questions = append(msg.Questions, question{Name: name, Type: qtype, Class: qclass})
	}

	// Parse resource record sections.
	parseRRs := func(count int) ([]resourceRecord, error) {
		var rrs []resourceRecord
		for i := 0; i < count; i++ {
			name, consumed, err := decodeName(data, offset)
			if err != nil {
				return nil, err
			}
			offset += consumed
			if offset+10 > len(data) {
				return nil, errTruncated
			}
			rtype := binary.BigEndian.Uint16(data[offset : offset+2])
			rclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
			rdlen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
			offset += 10
			if offset+int(rdlen) > len(data) {
				return nil, errTruncated
			}
			rd := make([]byte, rdlen)
			copy(rd, data[offset:offset+int(rdlen)])
			offset += int(rdlen)
			rrs = append(rrs, resourceRecord{
				Name:  name,
				Type:  rtype,
				Class: rclass,
				TTL:   ttl,
				RData: rd,
			})
		}
		return rrs, nil
	}

	var err error
	msg.Answers, err = parseRRs(int(hdr.ANCount))
	if err != nil {
		return nil, err
	}
	msg.Authorities, err = parseRRs(int(hdr.NSCount))
	if err != nil {
		return nil, err
	}
	msg.Additionals, err = parseRRs(int(hdr.ARCount))
	if err != nil {
		return nil, err
	}

	return msg, nil
}

// ---------------------------------------------------------------------------
// Message building
// ---------------------------------------------------------------------------

// messageBuilder constructs a DNS/mDNS message with name compression.
type messageBuilder struct {
	comp    *compressor
	header  msgHeader
	buf     []byte
	maxSize int
}

func newMessageBuilder(maxSize int) *messageBuilder {
	if maxSize <= 0 {
		maxSize = maxUDPSize
	}
	// Pre-allocate header space so compressor offsets account for the
	// 12-byte header and match the final wire-format positions.
	return &messageBuilder{
		comp:    newCompressor(),
		buf:     make([]byte, headerSize),
		maxSize: maxSize,
	}
}

func (b *messageBuilder) setResponse() {
	b.header.setResponse()
	b.header.setAA()
}

func (b *messageBuilder) addQuestion(name string, qtype, qclass uint16) error {
	newBuf, err := b.comp.appendQuestion(b.buf, name, qtype, qclass)
	if err != nil {
		return err
	}
	if len(newBuf) > b.maxSize {
		return errNoSpace
	}
	b.buf = newBuf
	b.header.QDCount++
	return nil
}

func (b *messageBuilder) addAnswer(name string, rtype, rclass uint16, ttl uint32, rdata []byte) error {
	newBuf, err := b.comp.appendRecord(b.buf, name, rtype, rclass, ttl, rdata)
	if err != nil {
		return err
	}
	if len(newBuf) > b.maxSize {
		return errNoSpace
	}
	b.buf = newBuf
	b.header.ANCount++
	return nil
}

func (b *messageBuilder) addAuthority(name string, rtype, rclass uint16, ttl uint32, rdata []byte) error {
	newBuf, err := b.comp.appendRecord(b.buf, name, rtype, rclass, ttl, rdata)
	if err != nil {
		return err
	}
	if len(newBuf) > b.maxSize {
		return errNoSpace
	}
	b.buf = newBuf
	b.header.NSCount++
	return nil
}

func (b *messageBuilder) addAdditional(name string, rtype, rclass uint16, ttl uint32, rdata []byte) error {
	newBuf, err := b.comp.appendRecord(b.buf, name, rtype, rclass, ttl, rdata)
	if err != nil {
		return err
	}
	if len(newBuf) > b.maxSize {
		return errNoSpace
	}
	b.buf = newBuf
	b.header.ARCount++
	return nil
}

func (b *messageBuilder) build() []byte {
	hdr := b.header.marshal()
	// Copy header into the reserved first 12 bytes.
	copy(b.buf[:headerSize], hdr)
	result := make([]byte, len(b.buf))
	copy(result, b.buf)
	return result
}

func (b *messageBuilder) isEmpty() bool {
	return b.header.QDCount == 0 && b.header.ANCount == 0 &&
		b.header.NSCount == 0 && b.header.ARCount == 0
}

func (b *messageBuilder) totalRecords() int {
	return int(b.header.QDCount) + int(b.header.ANCount) +
		int(b.header.NSCount) + int(b.header.ARCount)
}
