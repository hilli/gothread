// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dnssdserver

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// DNS record type constants.
const (
	TypeA    uint16 = 1
	TypeNS   uint16 = 2
	TypeSOA  uint16 = 6
	TypePTR  uint16 = 12
	TypeTXT  uint16 = 16
	TypeAAAA uint16 = 28
	TypeSRV  uint16 = 33
	TypeNSEC uint16 = 47
	TypeANY  uint16 = 255
)

// DNS class constants.
const (
	ClassIN uint16 = 1
)

// DNS header flag masks and positions.
const (
	headerSize = 12

	flagQR     uint16 = 0x8000 // Query/Response
	flagOpcode uint16 = 0x7800 // Opcode (4 bits)
	flagAA     uint16 = 0x0400 // Authoritative Answer
	flagTC     uint16 = 0x0200 // Truncation
	flagRD     uint16 = 0x0100 // Recursion Desired
	flagRA     uint16 = 0x0080 // Recursion Available
	flagRCode  uint16 = 0x000F // Response Code (4 bits)
)

// DnsQuery represents a parsed DNS query message.
type DnsQuery struct {
	ID                 uint16
	Questions          []DnsQuestion
	IsRecursionDesired bool
}

// DnsQuestion represents a single DNS question.
type DnsQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

// DnsRecord represents a DNS resource record.
type DnsRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// ParseDnsQuery parses an incoming DNS query message from wire format.
func ParseDnsQuery(data []byte) (*DnsQuery, error) {
	if len(data) < headerSize {
		return nil, fmt.Errorf("message too short: %d bytes", len(data))
	}

	id := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdCount := binary.BigEndian.Uint16(data[4:6])

	// Verify it's a query (QR bit = 0).
	if flags&flagQR != 0 {
		return nil, fmt.Errorf("not a query message")
	}

	query := &DnsQuery{
		ID:                 id,
		IsRecursionDesired: flags&flagRD != 0,
	}

	offset := headerSize
	for i := 0; i < int(qdCount); i++ {
		name, newOffset, err := DecodeDnsName(data, offset)
		if err != nil {
			return nil, fmt.Errorf("failed to decode question name: %w", err)
		}
		offset = newOffset

		if offset+4 > len(data) {
			return nil, fmt.Errorf("truncated question section")
		}

		qtype := binary.BigEndian.Uint16(data[offset : offset+2])
		qclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4

		query.Questions = append(query.Questions, DnsQuestion{
			Name:  name,
			Type:  qtype,
			Class: qclass,
		})
	}

	return query, nil
}

// BuildDnsResponse builds a DNS response message in wire format.
func BuildDnsResponse(query *DnsQuery, answers []DnsRecord, authorities []DnsRecord, additional []DnsRecord, rcode uint8) ([]byte, error) {
	buf := make([]byte, 0, 512)

	// Header
	var header [headerSize]byte
	binary.BigEndian.PutUint16(header[0:2], query.ID)

	flags := flagQR | flagAA // Response, Authoritative
	if query.IsRecursionDesired {
		flags |= flagRD
	}
	flags |= uint16(rcode) & flagRCode
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], uint16(len(query.Questions)))
	binary.BigEndian.PutUint16(header[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(header[8:10], uint16(len(authorities)))
	binary.BigEndian.PutUint16(header[10:12], uint16(len(additional)))
	buf = append(buf, header[:]...)

	// Encode questions.
	for _, q := range query.Questions {
		buf = append(buf, EncodeDnsName(q.Name)...)
		var qfield [4]byte
		binary.BigEndian.PutUint16(qfield[0:2], q.Type)
		binary.BigEndian.PutUint16(qfield[2:4], q.Class)
		buf = append(buf, qfield[:]...)
	}

	// Encode resource record sections.
	encodeSection := func(records []DnsRecord) error {
		for _, r := range records {
			buf = append(buf, EncodeDnsName(r.Name)...)
			var rr [10]byte
			binary.BigEndian.PutUint16(rr[0:2], r.Type)
			binary.BigEndian.PutUint16(rr[2:4], r.Class)
			binary.BigEndian.PutUint32(rr[4:8], r.TTL)
			binary.BigEndian.PutUint16(rr[8:10], uint16(len(r.RData)))
			buf = append(buf, rr[:]...)
			buf = append(buf, r.RData...)
		}
		return nil
	}

	if err := encodeSection(answers); err != nil {
		return nil, err
	}
	if err := encodeSection(authorities); err != nil {
		return nil, err
	}
	if err := encodeSection(additional); err != nil {
		return nil, err
	}

	return buf, nil
}

// EncodeDnsName encodes a DNS name with length-prefixed labels.
// The name should be a dot-separated FQDN (e.g., "example.com." or "example.com").
func EncodeDnsName(name string) []byte {
	// Remove trailing dot if present.
	name = strings.TrimSuffix(name, ".")

	if name == "" {
		return []byte{0}
	}

	labels := strings.Split(name, ".")
	var buf []byte
	for _, label := range labels {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0) // Root label.
	return buf
}

// DecodeDnsName decodes a DNS name from wire format starting at offset,
// supporting pointer compression (RFC 1035 Section 4.1.4).
// Returns the decoded name, the new offset after the name, and any error.
func DecodeDnsName(data []byte, offset int) (string, int, error) {
	if offset >= len(data) {
		return "", 0, fmt.Errorf("offset %d out of bounds (len=%d)", offset, len(data))
	}

	var labels []string
	endOffset := -1               // The offset after the name (set on first pointer).
	visited := make(map[int]bool) // Detect loops.
	cur := offset

	for {
		if cur >= len(data) {
			return "", 0, fmt.Errorf("truncated name at offset %d", cur)
		}

		b := data[cur]

		if b == 0 {
			// Root label — end of name.
			if endOffset < 0 {
				endOffset = cur + 1
			}
			break
		}

		if b&0xC0 == 0xC0 {
			// Pointer.
			if cur+1 >= len(data) {
				return "", 0, fmt.Errorf("truncated pointer at offset %d", cur)
			}
			ptr := int(binary.BigEndian.Uint16(data[cur:cur+2])) & 0x3FFF
			if endOffset < 0 {
				endOffset = cur + 2
			}
			if visited[ptr] {
				return "", 0, fmt.Errorf("pointer loop detected at offset %d", cur)
			}
			visited[ptr] = true
			cur = ptr
			continue
		}

		if b&0xC0 != 0 {
			return "", 0, fmt.Errorf("invalid label type 0x%02x at offset %d", b, cur)
		}

		labelLen := int(b)
		cur++
		if cur+labelLen > len(data) {
			return "", 0, fmt.Errorf("label extends beyond data at offset %d", cur)
		}
		labels = append(labels, string(data[cur:cur+labelLen]))
		cur += labelLen
	}

	name := strings.Join(labels, ".") + "."
	return name, endOffset, nil
}

// EncodePtrRData encodes PTR record RDATA (a DNS name).
func EncodePtrRData(targetName string) []byte {
	return EncodeDnsName(targetName)
}

// EncodeSrvRData encodes SRV record RDATA.
func EncodeSrvRData(priority, weight, port uint16, targetHost string) []byte {
	var buf [6]byte
	binary.BigEndian.PutUint16(buf[0:2], priority)
	binary.BigEndian.PutUint16(buf[2:4], weight)
	binary.BigEndian.PutUint16(buf[4:6], port)
	result := make([]byte, 0, 6+len(targetHost)+2)
	result = append(result, buf[:]...)
	result = append(result, EncodeDnsName(targetHost)...)
	return result
}

// EncodeAAAARData encodes AAAA record RDATA (16-byte IPv6 address).
func EncodeAAAARData(addr [16]byte) []byte {
	result := make([]byte, 16)
	copy(result, addr[:])
	return result
}

// EncodeTxtRData encodes TXT record RDATA.
// If txtData is nil or empty, returns a single zero-length string.
func EncodeTxtRData(txtData []byte) []byte {
	if len(txtData) == 0 {
		return []byte{0}
	}
	result := make([]byte, len(txtData))
	copy(result, txtData)
	return result
}
