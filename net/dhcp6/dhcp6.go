// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package dhcp6 implements DHCPv6 wire-format types, client, and server
// for Thread networks.
//
// This is a clean-room Go port of the DHCPv6 subsystem in OpenThread's
// src/core/net/dhcp6_types.{hpp,cpp}, dhcp6_client.{hpp,cpp}, and
// dhcp6_server.{hpp,cpp}.
package dhcp6

import (
	"crypto/rand"
	"encoding/binary"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Ports and well-known addresses
// ---------------------------------------------------------------------------

const (
	// ClientPort is the DHCPv6 client port (RFC 8415).
	ClientPort uint16 = 546
	// ServerPort is the DHCPv6 server port (RFC 8415).
	ServerPort uint16 = 547
)

// AllDHCPRelayAgentsAndServers is the link-local multicast address
// ff02::1:2 used to reach all DHCPv6 relay agents and servers.
var AllDHCPRelayAgentsAndServers = ip6.Address{
	0xff, 0x02, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0x01, 0, 0x02,
}

// ---------------------------------------------------------------------------
// Message types (RFC 8415 Section 7.3)
// ---------------------------------------------------------------------------

// MsgType identifies a DHCPv6 message type.
type MsgType uint8

const (
	MsgTypeSolicit            MsgType = 1
	MsgTypeAdvertise          MsgType = 2
	MsgTypeRequest            MsgType = 3
	MsgTypeConfirm            MsgType = 4
	MsgTypeRenew              MsgType = 5
	MsgTypeRebind             MsgType = 6
	MsgTypeReply              MsgType = 7
	MsgTypeRelease            MsgType = 8
	MsgTypeDecline            MsgType = 9
	MsgTypeReconfigure        MsgType = 10
	MsgTypeInformationRequest MsgType = 11
	MsgTypeRelayForward       MsgType = 12
	MsgTypeRelayReply         MsgType = 13
	MsgTypeLeaseQuery         MsgType = 14
	MsgTypeLeaseQueryReply    MsgType = 15
)

// ---------------------------------------------------------------------------
// TransactionID
// ---------------------------------------------------------------------------

// TransactionIDSize is the size in bytes of a DHCPv6 transaction ID.
const TransactionIDSize = 3

// TransactionID is the 24-bit transaction identifier in a DHCPv6 message.
type TransactionID [TransactionIDSize]byte

// GenerateRandom fills the transaction ID with cryptographically random bytes.
func (t *TransactionID) GenerateRandom() error {
	_, err := rand.Read(t[:])
	return err
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

// HeaderSize is the fixed size of a DHCPv6 message header.
const HeaderSize = 4

// Header is a DHCPv6 message header: 1 byte message type + 3 bytes
// transaction ID.
type Header struct {
	Type          MsgType
	TransactionID TransactionID
}

// MarshalBinary encodes the header into wire format.
func (h *Header) MarshalBinary() ([]byte, error) {
	buf := make([]byte, HeaderSize)
	buf[0] = byte(h.Type)
	copy(buf[1:4], h.TransactionID[:])
	return buf, nil
}

// UnmarshalBinary decodes a header from wire format.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return errors.ErrParse
	}
	h.Type = MsgType(data[0])
	copy(h.TransactionID[:], data[1:4])
	return nil
}

// ---------------------------------------------------------------------------
// Option codes (RFC 8415 and extensions)
// ---------------------------------------------------------------------------

// OptionCode identifies a DHCPv6 option.
type OptionCode uint16

const (
	OptionCodeClientID      OptionCode = 1
	OptionCodeServerID      OptionCode = 2
	OptionCodeIaNa          OptionCode = 3
	OptionCodeIaTa          OptionCode = 4
	OptionCodeIaAddress     OptionCode = 5
	OptionCodeOptionReq     OptionCode = 6
	OptionCodePreference    OptionCode = 7
	OptionCodeElapsedTime   OptionCode = 8
	OptionCodeRelayMsg      OptionCode = 9
	OptionCodeStatusCode    OptionCode = 13
	OptionCodeRapidCommit   OptionCode = 14
	OptionCodeServerUnicast OptionCode = 12
	OptionCodeIaPd          OptionCode = 25
	OptionCodeIaPrefix      OptionCode = 26
	OptionCodeSolMaxRt      OptionCode = 82
)

// ---------------------------------------------------------------------------
// OptionHeader
// ---------------------------------------------------------------------------

// OptionHeaderSize is the size of a DHCPv6 option header (code + length).
const OptionHeaderSize = 4

// OptionHeader represents the code and length fields of a DHCPv6 option.
type OptionHeader struct {
	Code   OptionCode
	Length uint16
}

// MarshalBinary encodes the option header into wire format.
func (oh *OptionHeader) MarshalBinary() ([]byte, error) {
	buf := make([]byte, OptionHeaderSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(oh.Code))
	binary.BigEndian.PutUint16(buf[2:4], oh.Length)
	return buf, nil
}

// UnmarshalBinary decodes an option header from wire format.
func (oh *OptionHeader) UnmarshalBinary(data []byte) error {
	if len(data) < OptionHeaderSize {
		return errors.ErrParse
	}
	oh.Code = OptionCode(binary.BigEndian.Uint16(data[0:2]))
	oh.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}

// ---------------------------------------------------------------------------
// Option (header + raw data)
// ---------------------------------------------------------------------------

// Option is a DHCPv6 option consisting of a header and raw data bytes.
type Option struct {
	Header OptionHeader
	Data   []byte
}

// MarshalBinary encodes the option into wire format.
func (o *Option) MarshalBinary() ([]byte, error) {
	o.Header.Length = uint16(len(o.Data))
	hdr, err := o.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, OptionHeaderSize+len(o.Data))
	buf = append(buf, hdr...)
	buf = append(buf, o.Data...)
	return buf, nil
}

// UnmarshalBinary decodes an option from wire format.
func (o *Option) UnmarshalBinary(data []byte) error {
	if err := o.Header.UnmarshalBinary(data); err != nil {
		return err
	}
	end := OptionHeaderSize + int(o.Header.Length)
	if len(data) < end {
		return errors.ErrParse
	}
	o.Data = make([]byte, o.Header.Length)
	copy(o.Data, data[OptionHeaderSize:end])
	return nil
}

// TotalLength returns the total wire size of the option (header + data).
func (o *Option) TotalLength() int {
	return OptionHeaderSize + len(o.Data)
}

// ---------------------------------------------------------------------------
// ParseOptions / FindOption
// ---------------------------------------------------------------------------

// ParseOptions parses a sequence of DHCPv6 options from raw bytes.
func ParseOptions(data []byte) ([]Option, error) {
	var opts []Option
	for len(data) >= OptionHeaderSize {
		var opt Option
		if err := opt.UnmarshalBinary(data); err != nil {
			return opts, err
		}
		opts = append(opts, opt)
		data = data[opt.TotalLength():]
	}
	return opts, nil
}

// FindOption searches a slice of options for the first option with the given
// code. Returns nil if not found.
func FindOption(opts []Option, code OptionCode) *Option {
	for i := range opts {
		if opts[i].Header.Code == code {
			return &opts[i]
		}
	}
	return nil
}

// FindOptionInBytes searches raw option bytes for the first option with the
// given code. Returns nil if not found.
func FindOptionInBytes(data []byte, code OptionCode) *Option {
	opts, _ := ParseOptions(data)
	return FindOption(opts, code)
}

// ---------------------------------------------------------------------------
// DUID types and hardware types
// ---------------------------------------------------------------------------

// DUIDType identifies a DUID type (RFC 8415 Section 11).
type DUIDType uint16

const (
	DUIDTypeLinkLayerPlusTime DUIDType = 1
	DUIDTypeEnterprise        DUIDType = 2
	DUIDTypeLinkLayer         DUIDType = 3
)

// HardwareType identifies a hardware type (IANA).
type HardwareType uint16

const (
	HardwareTypeEUI64 HardwareType = 27
)

// ---------------------------------------------------------------------------
// Eui64DUID
// ---------------------------------------------------------------------------

// Eui64DUIDSize is the wire size of a DUID-LL with EUI-64 identifier.
const Eui64DUIDSize = 12

// Eui64DUID is a DUID-LL (link-layer) identifier using an EUI-64 address.
// Wire format: 2 bytes DUIDType + 2 bytes HardwareType + 8 bytes ExtAddress.
type Eui64DUID struct {
	Type         DUIDType
	HardwareType HardwareType
	ExtAddress   types.ExtAddress
}

// Init initializes the DUID as a DUID-LL with EUI-64 hardware type.
func (d *Eui64DUID) Init(extAddr types.ExtAddress) {
	d.Type = DUIDTypeLinkLayer
	d.HardwareType = HardwareTypeEUI64
	d.ExtAddress = extAddr
}

// IsValid returns true if the DUID has valid type and hardware type fields.
func (d *Eui64DUID) IsValid() bool {
	return d.Type == DUIDTypeLinkLayer && d.HardwareType == HardwareTypeEUI64
}

// MarshalBinary encodes the DUID into wire format.
func (d *Eui64DUID) MarshalBinary() ([]byte, error) {
	buf := make([]byte, Eui64DUIDSize)
	binary.BigEndian.PutUint16(buf[0:2], uint16(d.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(d.HardwareType))
	copy(buf[4:12], d.ExtAddress[:])
	return buf, nil
}

// UnmarshalBinary decodes a DUID from wire format.
func (d *Eui64DUID) UnmarshalBinary(data []byte) error {
	if len(data) < Eui64DUIDSize {
		return errors.ErrParse
	}
	d.Type = DUIDType(binary.BigEndian.Uint16(data[0:2]))
	d.HardwareType = HardwareType(binary.BigEndian.Uint16(data[2:4]))
	copy(d.ExtAddress[:], data[4:12])
	return nil
}

// ---------------------------------------------------------------------------
// IaNa (Identity Association for Non-temporary Addresses)
// ---------------------------------------------------------------------------

// IaNaSize is the fixed wire size of the IA_NA fields (excluding sub-options).
const IaNaSize = 12

// IaNa represents the IA_NA option data (RFC 8415 Section 21.4).
// Wire format: 4 bytes IAID + 4 bytes T1 + 4 bytes T2, followed by
// sub-options.
type IaNa struct {
	IAID       uint32
	T1         uint32
	T2         uint32
	SubOptions []byte // raw sub-option bytes
}

// MarshalBinary encodes the IA_NA into wire format.
func (ia *IaNa) MarshalBinary() ([]byte, error) {
	buf := make([]byte, IaNaSize+len(ia.SubOptions))
	binary.BigEndian.PutUint32(buf[0:4], ia.IAID)
	binary.BigEndian.PutUint32(buf[4:8], ia.T1)
	binary.BigEndian.PutUint32(buf[8:12], ia.T2)
	copy(buf[12:], ia.SubOptions)
	return buf, nil
}

// UnmarshalBinary decodes an IA_NA from wire format.
func (ia *IaNa) UnmarshalBinary(data []byte) error {
	if len(data) < IaNaSize {
		return errors.ErrParse
	}
	ia.IAID = binary.BigEndian.Uint32(data[0:4])
	ia.T1 = binary.BigEndian.Uint32(data[4:8])
	ia.T2 = binary.BigEndian.Uint32(data[8:12])
	if len(data) > IaNaSize {
		ia.SubOptions = make([]byte, len(data)-IaNaSize)
		copy(ia.SubOptions, data[IaNaSize:])
	} else {
		ia.SubOptions = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// IaAddress
// ---------------------------------------------------------------------------

// IaAddressSize is the fixed wire size of the IA Address fields (excluding
// sub-options).
const IaAddressSize = 24

// IaAddress represents the IA Address option data (RFC 8415 Section 21.6).
// Wire format: 16 bytes Address + 4 bytes PreferredLifetime + 4 bytes
// ValidLifetime, followed by sub-options.
type IaAddress struct {
	Address           ip6.Address
	PreferredLifetime uint32
	ValidLifetime     uint32
	SubOptions        []byte
}

// InfiniteLifetime is the value 0xFFFFFFFF indicating an infinite lifetime.
const InfiniteLifetime uint32 = 0xFFFFFFFF

// MarshalBinary encodes the IA Address into wire format.
func (ia *IaAddress) MarshalBinary() ([]byte, error) {
	buf := make([]byte, IaAddressSize+len(ia.SubOptions))
	copy(buf[0:16], ia.Address[:])
	binary.BigEndian.PutUint32(buf[16:20], ia.PreferredLifetime)
	binary.BigEndian.PutUint32(buf[20:24], ia.ValidLifetime)
	copy(buf[24:], ia.SubOptions)
	return buf, nil
}

// UnmarshalBinary decodes an IA Address from wire format.
func (ia *IaAddress) UnmarshalBinary(data []byte) error {
	if len(data) < IaAddressSize {
		return errors.ErrParse
	}
	copy(ia.Address[:], data[0:16])
	ia.PreferredLifetime = binary.BigEndian.Uint32(data[16:20])
	ia.ValidLifetime = binary.BigEndian.Uint32(data[20:24])
	if len(data) > IaAddressSize {
		ia.SubOptions = make([]byte, len(data)-IaAddressSize)
		copy(ia.SubOptions, data[IaAddressSize:])
	} else {
		ia.SubOptions = nil
	}
	return nil
}

// ---------------------------------------------------------------------------
// Status codes (RFC 8415 Section 21.13)
// ---------------------------------------------------------------------------

// StatusCodeValue represents a DHCPv6 status code.
type StatusCodeValue uint16

const (
	StatusSuccess          StatusCodeValue = 0
	StatusUnspecFail       StatusCodeValue = 1
	StatusNoAddrsAvail     StatusCodeValue = 2
	StatusNoBinding        StatusCodeValue = 3
	StatusNotOnLink        StatusCodeValue = 4
	StatusUseMulticast     StatusCodeValue = 5
	StatusNoPrefixAvail    StatusCodeValue = 6
	StatusUnknownQueryType StatusCodeValue = 7
	StatusMalformedQuery   StatusCodeValue = 8
	StatusNotConfigured    StatusCodeValue = 9
	StatusNotAllowed       StatusCodeValue = 10
)

// StatusCodeSize is the minimum wire size of the Status Code option data
// (just the 2-byte status code, no message).
const StatusCodeSize = 2

// StatusCode represents the Status Code option data (RFC 8415 Section 21.13).
type StatusCode struct {
	Code    StatusCodeValue
	Message string // optional status message
}

// MarshalBinary encodes the Status Code into wire format.
func (sc *StatusCode) MarshalBinary() ([]byte, error) {
	buf := make([]byte, StatusCodeSize+len(sc.Message))
	binary.BigEndian.PutUint16(buf[0:2], uint16(sc.Code))
	copy(buf[2:], sc.Message)
	return buf, nil
}

// UnmarshalBinary decodes a Status Code from wire format.
func (sc *StatusCode) UnmarshalBinary(data []byte) error {
	if len(data) < StatusCodeSize {
		return errors.ErrParse
	}
	sc.Code = StatusCodeValue(binary.BigEndian.Uint16(data[0:2]))
	if len(data) > StatusCodeSize {
		sc.Message = string(data[StatusCodeSize:])
	} else {
		sc.Message = ""
	}
	return nil
}

// ReadStatusFrom reads a status code from the given option data. If no
// StatusCode option is found, it returns StatusSuccess.
func ReadStatusFrom(optionData []byte) (StatusCodeValue, error) {
	opt := FindOptionInBytes(optionData, OptionCodeStatusCode)
	if opt == nil {
		return StatusSuccess, nil
	}
	var sc StatusCode
	if err := sc.UnmarshalBinary(opt.Data); err != nil {
		return StatusSuccess, err
	}
	return sc.Code, nil
}

// ---------------------------------------------------------------------------
// ElapsedTime
// ---------------------------------------------------------------------------

// ElapsedTimeSize is the wire size of the Elapsed Time option data.
const ElapsedTimeSize = 2

// ElapsedTime represents the Elapsed Time option data (RFC 8415 Section 21.9).
// The value is in hundredths of a second.
type ElapsedTime struct {
	ElapsedTime uint16
}

// MarshalBinary encodes the Elapsed Time into wire format.
func (et *ElapsedTime) MarshalBinary() ([]byte, error) {
	buf := make([]byte, ElapsedTimeSize)
	binary.BigEndian.PutUint16(buf[0:2], et.ElapsedTime)
	return buf, nil
}

// UnmarshalBinary decodes an Elapsed Time from wire format.
func (et *ElapsedTime) UnmarshalBinary(data []byte) error {
	if len(data) < ElapsedTimeSize {
		return errors.ErrParse
	}
	et.ElapsedTime = binary.BigEndian.Uint16(data[0:2])
	return nil
}

// ---------------------------------------------------------------------------
// RapidCommit
// ---------------------------------------------------------------------------

// RapidCommit is the Rapid Commit option (RFC 8415 Section 21.14).
// It has no data; its presence alone signals rapid commit.
type RapidCommit struct{}

// HasRapidCommit returns true if a Rapid Commit option is present in the
// given options.
func HasRapidCommit(opts []Option) bool {
	return FindOption(opts, OptionCodeRapidCommit) != nil
}

// HasRapidCommitInBytes returns true if a Rapid Commit option is present in
// the given raw option bytes.
func HasRapidCommitInBytes(data []byte) bool {
	return FindOptionInBytes(data, OptionCodeRapidCommit) != nil
}

// ---------------------------------------------------------------------------
// Preference
// ---------------------------------------------------------------------------

// PreferenceSize is the wire size of the Preference option data.
const PreferenceSize = 1

// Preference represents the Preference option data (RFC 8415 Section 21.8).
type Preference struct {
	Value uint8
}

// MarshalBinary encodes the Preference into wire format.
func (p *Preference) MarshalBinary() ([]byte, error) {
	return []byte{p.Value}, nil
}

// UnmarshalBinary decodes a Preference from wire format.
func (p *Preference) UnmarshalBinary(data []byte) error {
	if len(data) < PreferenceSize {
		return errors.ErrParse
	}
	p.Value = data[0]
	return nil
}

// ---------------------------------------------------------------------------
// Option building helpers
// ---------------------------------------------------------------------------

// BuildOption creates a raw Option from a code and data payload.
func BuildOption(code OptionCode, data []byte) Option {
	return Option{
		Header: OptionHeader{
			Code:   code,
			Length: uint16(len(data)),
		},
		Data: data,
	}
}

// AppendOption appends a marshaled option to a byte buffer.
func AppendOption(buf []byte, code OptionCode, data []byte) []byte {
	opt := BuildOption(code, data)
	b, _ := opt.MarshalBinary()
	return append(buf, b...)
}

// AppendRapidCommitOption appends a Rapid Commit option (no data) to a
// byte buffer.
func AppendRapidCommitOption(buf []byte) []byte {
	return AppendOption(buf, OptionCodeRapidCommit, nil)
}

// AppendElapsedTimeOption appends an Elapsed Time option to a byte buffer.
func AppendElapsedTimeOption(buf []byte, hundredths uint16) []byte {
	et := ElapsedTime{ElapsedTime: hundredths}
	data, _ := et.MarshalBinary()
	return AppendOption(buf, OptionCodeElapsedTime, data)
}

// AppendClientIDOption appends a Client ID option containing an Eui64DUID.
func AppendClientIDOption(buf []byte, duid *Eui64DUID) []byte {
	data, _ := duid.MarshalBinary()
	return AppendOption(buf, OptionCodeClientID, data)
}

// AppendServerIDOption appends a Server ID option containing an Eui64DUID.
func AppendServerIDOption(buf []byte, duid *Eui64DUID) []byte {
	data, _ := duid.MarshalBinary()
	return AppendOption(buf, OptionCodeServerID, data)
}

// AppendStatusCodeOption appends a Status Code option to a byte buffer.
func AppendStatusCodeOption(buf []byte, code StatusCodeValue) []byte {
	sc := StatusCode{Code: code}
	data, _ := sc.MarshalBinary()
	return AppendOption(buf, OptionCodeStatusCode, data)
}

// AppendIaNaOption appends an IA_NA option to a byte buffer.
func AppendIaNaOption(buf []byte, ia *IaNa) []byte {
	data, _ := ia.MarshalBinary()
	return AppendOption(buf, OptionCodeIaNa, data)
}

// AppendIaAddressOption appends an IA Address option to a byte buffer.
func AppendIaAddressOption(buf []byte, ia *IaAddress) []byte {
	data, _ := ia.MarshalBinary()
	return AppendOption(buf, OptionCodeIaAddress, data)
}

// ---------------------------------------------------------------------------
// Address construction helper
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// IaPd (Identity Association for Prefix Delegation)
// ---------------------------------------------------------------------------

// IaPdSize is the fixed wire size of the IA_PD fields (excluding sub-options).
const IaPdSize = 12

// IaPd represents the IA_PD option data (RFC 8415 Section 21.21).
// Wire format: 4 bytes IAID + 4 bytes T1 + 4 bytes T2, followed by
// sub-options.
type IaPd struct {
	IAID       uint32
	T1         uint32 // seconds
	T2         uint32 // seconds
	SubOptions []byte // raw sub-option bytes
}

// Marshal encodes the IA_PD fixed fields into a 12-byte array.
func (ia *IaPd) Marshal() [IaPdSize]byte {
	var buf [IaPdSize]byte
	binary.BigEndian.PutUint32(buf[0:4], ia.IAID)
	binary.BigEndian.PutUint32(buf[4:8], ia.T1)
	binary.BigEndian.PutUint32(buf[8:12], ia.T2)
	return buf
}

// Unmarshal decodes the IA_PD fixed fields from wire format.
func (ia *IaPd) Unmarshal(data []byte) error {
	if len(data) < IaPdSize {
		return errors.ErrParse
	}
	ia.IAID = binary.BigEndian.Uint32(data[0:4])
	ia.T1 = binary.BigEndian.Uint32(data[4:8])
	ia.T2 = binary.BigEndian.Uint32(data[8:12])
	if len(data) > IaPdSize {
		ia.SubOptions = make([]byte, len(data)-IaPdSize)
		copy(ia.SubOptions, data[IaPdSize:])
	} else {
		ia.SubOptions = nil
	}
	return nil
}

// MarshalBinary encodes the IA_PD into wire format (fixed fields + sub-options).
func (ia *IaPd) MarshalBinary() ([]byte, error) {
	buf := make([]byte, IaPdSize+len(ia.SubOptions))
	binary.BigEndian.PutUint32(buf[0:4], ia.IAID)
	binary.BigEndian.PutUint32(buf[4:8], ia.T1)
	binary.BigEndian.PutUint32(buf[8:12], ia.T2)
	copy(buf[12:], ia.SubOptions)
	return buf, nil
}

// ---------------------------------------------------------------------------
// IaPrefix (IA Prefix option)
// ---------------------------------------------------------------------------

// IaPrefixSize is the fixed wire size of the IA Prefix option data
// (excluding sub-options).
const IaPrefixSize = 25

// IaPrefix represents the IA Prefix option data (RFC 8415 Section 21.22).
// Wire format: 4 bytes PreferredLifetime + 4 bytes ValidLifetime +
// 1 byte PrefixLength + 16 bytes Prefix.
type IaPrefix struct {
	PreferredLifetime uint32
	ValidLifetime     uint32
	PrefixLength      uint8
	Prefix            [16]byte
}

// Marshal encodes the IA Prefix into a 25-byte array.
func (iap *IaPrefix) Marshal() [IaPrefixSize]byte {
	var buf [IaPrefixSize]byte
	binary.BigEndian.PutUint32(buf[0:4], iap.PreferredLifetime)
	binary.BigEndian.PutUint32(buf[4:8], iap.ValidLifetime)
	buf[8] = iap.PrefixLength
	copy(buf[9:25], iap.Prefix[:])
	return buf
}

// Unmarshal decodes the IA Prefix from wire format.
func (iap *IaPrefix) Unmarshal(data []byte) error {
	if len(data) < IaPrefixSize {
		return errors.ErrParse
	}
	iap.PreferredLifetime = binary.BigEndian.Uint32(data[0:4])
	iap.ValidLifetime = binary.BigEndian.Uint32(data[4:8])
	iap.PrefixLength = data[8]
	copy(iap.Prefix[:], data[9:25])
	return nil
}

// MarshalBinary encodes the IA Prefix into wire format.
func (iap *IaPrefix) MarshalBinary() ([]byte, error) {
	b := iap.Marshal()
	return b[:], nil
}

// ---------------------------------------------------------------------------
// SolMaxRt (SOL_MAX_RT option)
// ---------------------------------------------------------------------------

// SolMaxRt constants per RFC 8415.
const (
	MinSolMaxRt uint32 = 60
	MaxSolMaxRt uint32 = 86400
)

// SolMaxRtSize is the wire size of the SOL_MAX_RT option data.
const SolMaxRtSize = 4

// SolMaxRt represents the SOL_MAX_RT option data (RFC 8415 Section 21.24).
type SolMaxRt struct {
	Value uint32 // seconds
}

// Marshal encodes the SOL_MAX_RT into a 4-byte array.
func (s *SolMaxRt) Marshal() [SolMaxRtSize]byte {
	var buf [SolMaxRtSize]byte
	binary.BigEndian.PutUint32(buf[0:4], s.Value)
	return buf
}

// Unmarshal decodes the SOL_MAX_RT from wire format.
func (s *SolMaxRt) Unmarshal(data []byte) error {
	if len(data) < SolMaxRtSize {
		return errors.ErrParse
	}
	s.Value = binary.BigEndian.Uint32(data[0:4])
	return nil
}

// IsValid returns true if the value is within the valid range [60, 86400].
func (s *SolMaxRt) IsValid() bool {
	return s.Value >= MinSolMaxRt && s.Value <= MaxSolMaxRt
}

// ---------------------------------------------------------------------------
// Additional option building helpers for PD
// ---------------------------------------------------------------------------

// AppendServerIDOptionRaw appends a Server Identifier option with arbitrary
// DUID bytes (not just EUI-64).
func AppendServerIDOptionRaw(buf []byte, duid []byte) []byte {
	return AppendOption(buf, OptionCodeServerID, duid)
}

// AppendIaPdOption appends an IA_PD option to a byte buffer.
func AppendIaPdOption(buf []byte, iapd *IaPd) []byte {
	data, _ := iapd.MarshalBinary()
	return AppendOption(buf, OptionCodeIaPd, data)
}

// AppendIaPrefixOption appends an IA Prefix option to a byte buffer.
func AppendIaPrefixOption(buf []byte, iap *IaPrefix) []byte {
	data, _ := iap.MarshalBinary()
	return AppendOption(buf, OptionCodeIaPrefix, data)
}

// MakeAddressFromPrefixEUI64 constructs an IPv6 address by combining a 64-bit
// network prefix with an EUI-64 interface identifier derived from the given
// ExtAddress.
func MakeAddressFromPrefixEUI64(prefix ip6.NetworkPrefix, extAddr types.ExtAddress) ip6.Address {
	var addr ip6.Address
	copy(addr[0:8], prefix[:])
	// EUI-64 IID: toggle the universal/local bit (bit 1 of byte 0).
	addr[8] = extAddr[0] ^ 0x02
	addr[9] = extAddr[1]
	addr[10] = extAddr[2]
	addr[11] = extAddr[3]
	addr[12] = extAddr[4]
	addr[13] = extAddr[5]
	addr[14] = extAddr[6]
	addr[15] = extAddr[7]
	return addr
}
