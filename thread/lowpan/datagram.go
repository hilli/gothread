// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package lowpan

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
)

// IPv6MTU is the supported IPv6 link MTU, before header compression.
const IPv6MTU = 1280

// IPv6Dispatch identifies an uncompressed IPv6 header (RFC 4944 section 5.1).
const IPv6Dispatch byte = 0x41

// AppendFragmentHeader appends an RFC 4944 header. Size and offset are in
// uncompressed IPv6 bytes; the wire offset is encoded in eight-octet units.
func AppendFragmentHeader(dst []byte, size, tag, offset uint16) ([]byte, error) {
	if size < ipv6HeaderSize || size > 0x7ff || offset >= size || offset%8 != 0 {
		return nil, errors.ErrInvalidArgs
	}
	dispatch := FragFirstDispatch
	if offset != 0 {
		dispatch = FragSubsequentDispatch
	}
	dst = append(dst, dispatch|byte(size>>8), byte(size), byte(tag>>8), byte(tag))
	if offset != 0 {
		dst = append(dst, byte(offset/8))
	}
	return dst, nil
}

// DecompressDatagram expands the headers in an unfragmented frame or FRAG1.
// size is the RFC 4944 uncompressed datagram_size, or zero for an unfragmented
// packet. FRAG1's returned slice represents its ORIGINAL IPv6 byte range;
// subsequent fragments can therefore be placed at their wire offsets directly.
//
// Only IPv6 base headers and UDP NHC are supported here. NHC extension chains
// and checksum elision require additional protocol support and are rejected.
func DecompressDatagram(data []byte, addresses AddressContext, size uint16) ([]byte, error) {
	if len(data) == 0 || len(data) > IPv6MTU+1 || size > IPv6MTU {
		return nil, errors.ErrParse
	}
	var header [ipv6HeaderSize]byte
	var consumed int
	var compressed bool
	if data[0] == IPv6Dispatch {
		if len(data) < 1+ipv6HeaderSize {
			return nil, errors.ErrParse
		}
		copy(header[:], data[1:1+ipv6HeaderSize])
		if header[0]>>4 != 6 {
			return nil, errors.ErrParse
		}
		consumed = 1 + ipv6HeaderSize
	} else {
		if !IsLowpanHc(data) || binary.BigEndian.Uint16(data[:2])&(HcContextID|HcSrcAddrContext|HcDstAddrContext) != 0 {
			return nil, errors.ErrParse
		}
		var err error
		header, consumed, compressed, err = DecompressHeader(data, addresses, nil)
		if err != nil {
			return nil, err
		}
	}

	packet := make([]byte, ipv6HeaderSize, ipv6HeaderSize+len(data)-consumed+udpHeaderSize)
	copy(packet, header[:])
	if compressed {
		if consumed >= len(data) || data[consumed]&NhcUDPDispatchMask != NhcUDPDispatch ||
			data[consumed]&NhcUDPChecksum != 0 {
			return nil, errors.ErrParse
		}
		udpHeader, count, err := DecompressUDPHeader(data[consumed:])
		if err != nil {
			return nil, err
		}
		consumed += count
		packet[6] = 17
		total := int(size)
		if total == 0 {
			total = ipv6HeaderSize + udpHeaderSize + len(data) - consumed
		}
		if total < ipv6HeaderSize+udpHeaderSize {
			return nil, errors.ErrParse
		}
		binary.BigEndian.PutUint16(udpHeader[4:6], uint16(total-ipv6HeaderSize))
		packet = append(packet, udpHeader[:]...)
	}
	packet = append(packet, data[consumed:]...)
	total := int(size)
	if total == 0 {
		total = len(packet)
	}
	if total < ipv6HeaderSize || total > IPv6MTU || len(packet) > total {
		return nil, errors.ErrParse
	}
	if data[0] == IPv6Dispatch && int(binary.BigEndian.Uint16(header[4:6]))+ipv6HeaderSize != total {
		return nil, errors.ErrParse
	}
	binary.BigEndian.PutUint16(packet[4:6], uint16(total-ipv6HeaderSize))
	if packet[6] == 17 && len(packet) >= ipv6HeaderSize+udpHeaderSize &&
		(int(binary.BigEndian.Uint16(packet[44:46])) != total-ipv6HeaderSize ||
			binary.BigEndian.Uint16(packet[46:48]) == 0) {
		return nil, errors.ErrParse
	}
	return packet, nil
}
