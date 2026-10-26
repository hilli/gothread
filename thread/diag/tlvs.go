// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package diag

import (
	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/tlv"
)

// --- Connectivity ---

// MarshalConnectivity serializes a Connectivity value into a TLV.
func MarshalConnectivity(c *Connectivity) tlv.TLV {
	v := make([]byte, ConnectivitySize)
	v[0] = byte(c.ParentPriority)
	v[1] = c.LinkQuality3
	v[2] = c.LinkQuality2
	v[3] = c.LinkQuality1
	v[4] = c.LeaderCost
	v[5] = c.IDSequence
	v[6] = c.ActiveRouters
	encoding.BigEndianWriteUint16(c.SEDBufferSize, v[7:9])
	v[9] = c.SEDDatagramCount
	return tlv.TLV{Type: TypeConnectivity, Length: ConnectivitySize, Value: v}
}

// UnmarshalConnectivity parses a Connectivity value from a TLV value slice.
func UnmarshalConnectivity(data []byte) (Connectivity, error) {
	if len(data) < ConnectivitySize {
		return Connectivity{}, errors.ErrParse
	}
	return Connectivity{
		ParentPriority:   int8(data[0]),
		LinkQuality3:     data[1],
		LinkQuality2:     data[2],
		LinkQuality1:     data[3],
		LeaderCost:       data[4],
		IDSequence:       data[5],
		ActiveRouters:    data[6],
		SEDBufferSize:    encoding.BigEndianReadUint16(data[7:9]),
		SEDDatagramCount: data[9],
	}, nil
}

// --- Route64 ---

// MarshalRoute64 serializes a Route64 value into a TLV.
//
// Each route entry is exactly 1 byte on the wire:
//
//	bits 7-6: Link Quality Out (2 bits)
//	bits 5-4: Link Quality In (2 bits)
//	bits 3-0: Route Cost (4 bits)
func MarshalRoute64(r *Route64) tlv.TLV {
	numEntries := len(r.RouteData)
	totalLen := 1 + 8 + numEntries // idSequence + routerIDSet + route data

	v := make([]byte, totalLen)
	v[0] = r.IDSequence
	copy(v[1:9], r.RouterIDSet[:])

	for i, entry := range r.RouteData {
		packed := (entry.LinkQualityOut&0x03)<<6 | (entry.LinkQualityIn&0x03)<<4 | (entry.RouteCost & 0x0F)
		v[9+i] = packed
	}

	return tlv.TLV{Type: TypeRoute64, Length: uint16(totalLen), Value: v}
}

// UnmarshalRoute64 parses a Route64 value from a TLV value slice.
func UnmarshalRoute64(data []byte) (Route64, error) {
	if len(data) < 9 {
		return Route64{}, errors.ErrParse
	}

	r := Route64{
		IDSequence: data[0],
	}
	copy(r.RouterIDSet[:], data[1:9])

	// Count allocated routers from the bit set.
	routeDataLen := len(data) - 9
	r.RouteData = make([]Route64Entry, routeDataLen)

	// Assign router IDs from the bit set in order.
	routerIdx := 0
	for id := uint8(0); id < 64 && routerIdx < routeDataLen; id++ {
		byteIdx := id / 8
		bitIdx := 7 - (id % 8) // MSB-first
		if r.RouterIDSet[byteIdx]&(1<<bitIdx) != 0 {
			if routerIdx < routeDataLen {
				b := data[9+routerIdx]
				r.RouteData[routerIdx] = Route64Entry{
					RouterID:       id,
					LinkQualityOut: (b >> 6) & 0x03,
					LinkQualityIn:  (b >> 4) & 0x03,
					RouteCost:      b & 0x0F,
				}
				routerIdx++
			}
		}
	}
	r.RouteData = r.RouteData[:routerIdx]

	return r, nil
}

// --- MacCounters ---

// MarshalMacCounters serializes MacCounters into a TLV.
func MarshalMacCounters(c *MacCounters) tlv.TLV {
	v := make([]byte, MacCountersSize)
	encoding.BigEndianWriteUint32(c.IfInUnknownProtos, v[0:4])
	encoding.BigEndianWriteUint32(c.IfInErrors, v[4:8])
	encoding.BigEndianWriteUint32(c.IfOutErrors, v[8:12])
	encoding.BigEndianWriteUint32(c.IfInUcastPkts, v[12:16])
	encoding.BigEndianWriteUint32(c.IfInBroadcastPkts, v[16:20])
	encoding.BigEndianWriteUint32(c.IfInDiscards, v[20:24])
	encoding.BigEndianWriteUint32(c.IfOutUcastPkts, v[24:28])
	encoding.BigEndianWriteUint32(c.IfOutBroadcastPkts, v[28:32])
	encoding.BigEndianWriteUint32(c.IfOutDiscards, v[32:36])
	return tlv.TLV{Type: TypeMacCounters, Length: MacCountersSize, Value: v}
}

// UnmarshalMacCounters parses MacCounters from a TLV value slice.
func UnmarshalMacCounters(data []byte) (MacCounters, error) {
	if len(data) < MacCountersSize {
		return MacCounters{}, errors.ErrParse
	}
	return MacCounters{
		IfInUnknownProtos:  encoding.BigEndianReadUint32(data[0:4]),
		IfInErrors:         encoding.BigEndianReadUint32(data[4:8]),
		IfOutErrors:        encoding.BigEndianReadUint32(data[8:12]),
		IfInUcastPkts:      encoding.BigEndianReadUint32(data[12:16]),
		IfInBroadcastPkts:  encoding.BigEndianReadUint32(data[16:20]),
		IfInDiscards:       encoding.BigEndianReadUint32(data[20:24]),
		IfOutUcastPkts:     encoding.BigEndianReadUint32(data[24:28]),
		IfOutBroadcastPkts: encoding.BigEndianReadUint32(data[28:32]),
		IfOutDiscards:      encoding.BigEndianReadUint32(data[32:36]),
	}, nil
}

// --- MleCounters ---

// MarshalMleCounters serializes MleCounters into a TLV.
func MarshalMleCounters(c *MleCounters) tlv.TLV {
	v := make([]byte, MleCountersSize)
	encoding.BigEndianWriteUint16(c.DisabledRole, v[0:2])
	encoding.BigEndianWriteUint16(c.DetachedRole, v[2:4])
	encoding.BigEndianWriteUint16(c.ChildRole, v[4:6])
	encoding.BigEndianWriteUint16(c.RouterRole, v[6:8])
	encoding.BigEndianWriteUint16(c.LeaderRole, v[8:10])
	encoding.BigEndianWriteUint16(c.AttachAttempts, v[10:12])
	encoding.BigEndianWriteUint16(c.PartitionIDChanges, v[12:14])
	encoding.BigEndianWriteUint16(c.BetterPartitionAttachAttempts, v[14:16])
	encoding.BigEndianWriteUint16(c.ParentChanges, v[16:18])
	encoding.BigEndianWriteUint64(c.TrackedTime, v[18:26])
	encoding.BigEndianWriteUint64(c.DisabledTime, v[26:34])
	encoding.BigEndianWriteUint64(c.DetachedTime, v[34:42])
	encoding.BigEndianWriteUint64(c.ChildTime, v[42:50])
	encoding.BigEndianWriteUint64(c.RouterTime, v[50:58])
	encoding.BigEndianWriteUint64(c.LeaderTime, v[58:66])
	return tlv.TLV{Type: TypeMleCounters, Length: MleCountersSize, Value: v}
}

// UnmarshalMleCounters parses MleCounters from a TLV value slice.
func UnmarshalMleCounters(data []byte) (MleCounters, error) {
	if len(data) < MleCountersSize {
		return MleCounters{}, errors.ErrParse
	}
	return MleCounters{
		DisabledRole:                  encoding.BigEndianReadUint16(data[0:2]),
		DetachedRole:                  encoding.BigEndianReadUint16(data[2:4]),
		ChildRole:                     encoding.BigEndianReadUint16(data[4:6]),
		RouterRole:                    encoding.BigEndianReadUint16(data[6:8]),
		LeaderRole:                    encoding.BigEndianReadUint16(data[8:10]),
		AttachAttempts:                encoding.BigEndianReadUint16(data[10:12]),
		PartitionIDChanges:            encoding.BigEndianReadUint16(data[12:14]),
		BetterPartitionAttachAttempts: encoding.BigEndianReadUint16(data[14:16]),
		ParentChanges:                 encoding.BigEndianReadUint16(data[16:18]),
		TrackedTime:                   encoding.BigEndianReadUint64(data[18:26]),
		DisabledTime:                  encoding.BigEndianReadUint64(data[26:34]),
		DetachedTime:                  encoding.BigEndianReadUint64(data[34:42]),
		ChildTime:                     encoding.BigEndianReadUint64(data[42:50]),
		RouterTime:                    encoding.BigEndianReadUint64(data[50:58]),
		LeaderTime:                    encoding.BigEndianReadUint64(data[58:66]),
	}, nil
}

// --- ChildTableEntry ---

// MarshalChildTableEntry serializes a single ChildTableEntry into 3 bytes.
func MarshalChildTableEntry(e *ChildTableEntry) []byte {
	buf := make([]byte, ChildTableEntrySize)
	// Pack: bits 15..11 = timeout, bits 10..9 = linkQualityIn, bits 8..0 = childID
	packed := uint16(e.Timeout&0x1F)<<11 | uint16(e.LinkQualityIn&0x03)<<9 | (e.ChildID & 0x01FF)
	encoding.BigEndianWriteUint16(packed, buf[0:2])
	buf[2] = e.Mode
	return buf
}

// UnmarshalChildTableEntry parses a single ChildTableEntry from 3 bytes.
func UnmarshalChildTableEntry(data []byte) (ChildTableEntry, error) {
	if len(data) < ChildTableEntrySize {
		return ChildTableEntry{}, errors.ErrParse
	}
	packed := encoding.BigEndianReadUint16(data[0:2])
	return ChildTableEntry{
		Timeout:       uint8((packed >> 11) & 0x1F),
		LinkQualityIn: uint8((packed >> 9) & 0x03),
		ChildID:       packed & 0x01FF,
		Mode:          data[2],
	}, nil
}

// MarshalChildTable serializes a slice of ChildTableEntry values into a TLV.
func MarshalChildTable(entries []ChildTableEntry) tlv.TLV {
	v := make([]byte, 0, len(entries)*ChildTableEntrySize)
	for i := range entries {
		v = append(v, MarshalChildTableEntry(&entries[i])...)
	}
	return tlv.TLV{Type: TypeChildTable, Length: uint16(len(v)), Value: v}
}

// UnmarshalChildTable parses all ChildTableEntry values from a TLV value slice.
func UnmarshalChildTable(data []byte) ([]ChildTableEntry, error) {
	if len(data)%ChildTableEntrySize != 0 {
		return nil, errors.ErrParse
	}
	count := len(data) / ChildTableEntrySize
	entries := make([]ChildTableEntry, count)
	for i := 0; i < count; i++ {
		e, err := UnmarshalChildTableEntry(data[i*ChildTableEntrySize:])
		if err != nil {
			return nil, err
		}
		entries[i] = e
	}
	return entries, nil
}

// --- ChildTlv ---

// MarshalChildTlv serializes a ChildTlv into a TLV.
func MarshalChildTlv(c *ChildTlv) tlv.TLV {
	v := make([]byte, ChildTlvSize)
	v[0] = c.Flags
	encoding.BigEndianWriteUint16(c.RLOC16, v[1:3])
	copy(v[3:11], c.ExtAddress[:])
	encoding.BigEndianWriteUint16(c.Version, v[11:13])
	encoding.BigEndianWriteUint32(c.Timeout, v[13:17])
	encoding.BigEndianWriteUint32(c.Age, v[17:21])
	encoding.BigEndianWriteUint32(c.ConnectionTime, v[21:25])
	encoding.BigEndianWriteUint16(c.SupervisionInterval, v[25:27])
	return tlv.TLV{Type: TypeChild, Length: ChildTlvSize, Value: v}
}

// UnmarshalChildTlv parses a ChildTlv from a TLV value slice.
func UnmarshalChildTlv(data []byte) (ChildTlv, error) {
	if len(data) < ChildTlvSize {
		return ChildTlv{}, errors.ErrParse
	}
	c := ChildTlv{
		Flags:               data[0],
		RLOC16:              encoding.BigEndianReadUint16(data[1:3]),
		Version:             encoding.BigEndianReadUint16(data[11:13]),
		Timeout:             encoding.BigEndianReadUint32(data[13:17]),
		Age:                 encoding.BigEndianReadUint32(data[17:21]),
		ConnectionTime:      encoding.BigEndianReadUint32(data[21:25]),
		SupervisionInterval: encoding.BigEndianReadUint16(data[25:27]),
	}
	copy(c.ExtAddress[:], data[3:11])
	return c, nil
}

// --- RouterNeighborTlv ---

// MarshalRouterNeighborTlv serializes a RouterNeighborTlv into a TLV.
func MarshalRouterNeighborTlv(r *RouterNeighborTlv) tlv.TLV {
	v := make([]byte, RouterNeighborTlvSize)
	v[0] = r.Flags
	encoding.BigEndianWriteUint16(r.RLOC16, v[1:3])
	copy(v[3:11], r.ExtAddress[:])
	encoding.BigEndianWriteUint16(r.Version, v[11:13])
	encoding.BigEndianWriteUint32(r.ConnectionTime, v[13:17])
	v[17] = r.LinkMargin
	v[18] = byte(r.AverageRSSI)
	v[19] = byte(r.LastRSSI)
	encoding.BigEndianWriteUint16(r.FrameErrorRate, v[20:22])
	encoding.BigEndianWriteUint16(r.MessageErrorRate, v[22:24])
	return tlv.TLV{Type: TypeRouterNeighbor, Length: RouterNeighborTlvSize, Value: v}
}

// UnmarshalRouterNeighborTlv parses a RouterNeighborTlv from a TLV value slice.
func UnmarshalRouterNeighborTlv(data []byte) (RouterNeighborTlv, error) {
	if len(data) < RouterNeighborTlvSize {
		return RouterNeighborTlv{}, errors.ErrParse
	}
	r := RouterNeighborTlv{
		Flags:            data[0],
		RLOC16:           encoding.BigEndianReadUint16(data[1:3]),
		Version:          encoding.BigEndianReadUint16(data[11:13]),
		ConnectionTime:   encoding.BigEndianReadUint32(data[13:17]),
		LinkMargin:       data[17],
		AverageRSSI:      int8(data[18]),
		LastRSSI:         int8(data[19]),
		FrameErrorRate:   encoding.BigEndianReadUint16(data[20:22]),
		MessageErrorRate: encoding.BigEndianReadUint16(data[22:24]),
	}
	copy(r.ExtAddress[:], data[3:11])
	return r, nil
}

// --- AnswerTlv ---

// MarshalAnswerTlv serializes an AnswerTlv into a TLV.
func MarshalAnswerTlv(a *AnswerTlv) tlv.TLV {
	v := make([]byte, AnswerTlvSize)
	val := a.Index & 0x7FFF
	if a.IsLast {
		val |= 0x8000
	}
	encoding.BigEndianWriteUint16(val, v[0:2])
	return tlv.TLV{Type: TypeAnswer, Length: AnswerTlvSize, Value: v}
}

// UnmarshalAnswerTlv parses an AnswerTlv from a TLV value slice.
func UnmarshalAnswerTlv(data []byte) (AnswerTlv, error) {
	if len(data) < AnswerTlvSize {
		return AnswerTlv{}, errors.ErrParse
	}
	val := encoding.BigEndianReadUint16(data[0:2])
	return AnswerTlv{
		IsLast: (val & 0x8000) != 0,
		Index:  val & 0x7FFF,
	}, nil
}

// --- Simple scalar TLV helpers ---

// MarshalUint16TLV creates a TLV with a big-endian uint16 value.
func MarshalUint16TLV(typ uint8, val uint16) tlv.TLV {
	v := make([]byte, 2)
	encoding.BigEndianWriteUint16(val, v)
	return tlv.TLV{Type: typ, Length: 2, Value: v}
}

// UnmarshalUint16TLV reads a big-endian uint16 from a TLV value.
func UnmarshalUint16TLV(data []byte) (uint16, error) {
	if len(data) < 2 {
		return 0, errors.ErrParse
	}
	return encoding.BigEndianReadUint16(data), nil
}

// MarshalUint32TLV creates a TLV with a big-endian uint32 value.
func MarshalUint32TLV(typ uint8, val uint32) tlv.TLV {
	v := make([]byte, 4)
	encoding.BigEndianWriteUint32(val, v)
	return tlv.TLV{Type: typ, Length: 4, Value: v}
}

// UnmarshalUint32TLV reads a big-endian uint32 from a TLV value.
func UnmarshalUint32TLV(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, errors.ErrParse
	}
	return encoding.BigEndianReadUint32(data), nil
}

// MarshalByteTLV creates a TLV with a single-byte value.
func MarshalByteTLV(typ, val uint8) tlv.TLV {
	return tlv.TLV{Type: typ, Length: 1, Value: []byte{val}}
}

// MarshalBytesTLV creates a TLV with an arbitrary byte-slice value.
func MarshalBytesTLV(typ uint8, val []byte) tlv.TLV {
	v := make([]byte, len(val))
	copy(v, val)
	return tlv.TLV{Type: typ, Length: uint16(len(val)), Value: v}
}

// MarshalStringTLV creates a TLV with a UTF-8 string value.
func MarshalStringTLV(typ uint8, val string) tlv.TLV {
	return MarshalBytesTLV(typ, []byte(val))
}

// --- ParseDiagnosticTLVs ---

// ParseDiagnosticTLVs parses raw bytes into a slice of TLVs using the
// standard TLV parser. This is a convenience wrapper.
func ParseDiagnosticTLVs(data []byte) ([]tlv.TLV, error) {
	return tlv.ParseAll(data)
}
