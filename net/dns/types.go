// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"encoding/binary"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Header Type / QR flag
// ---------------------------------------------------------------------------

// HeaderType indicates whether a DNS message is a query or response.
type HeaderType uint8

// DNS message types encoded in the header QR flag.
const (
	TypeQuery    HeaderType = 0 // Query message.
	TypeResponse HeaderType = 1 // Response message.
)

// ---------------------------------------------------------------------------
// OpCode (query type)
// ---------------------------------------------------------------------------

// OpCode represents the DNS message OpCode (bits 6-3 of flags[0]).
type OpCode uint8

// DNS operation codes encoded in the header.
const (
	OpcodeQuery   OpCode = 0 // Standard query.
	OpcodeInverse OpCode = 1 // Inverse query.
	OpcodeStatus  OpCode = 2 // Status request.
	OpcodeNotify  OpCode = 4 // Notify (RFC 1996).
	OpcodeUpdate  OpCode = 5 // DNS Update (RFC 2136).
	OpcodeDso     OpCode = 6 // DNS Stateful Operations (RFC 8490).
)

// ---------------------------------------------------------------------------
// Response Code (RCODE)
// ---------------------------------------------------------------------------

// ResponseCode represents a DNS response code (RCODE).
type ResponseCode uint8

// DNS response codes.
const (
	RcodeSuccess         ResponseCode = 0  // No error (NoError).
	RcodeFormatError     ResponseCode = 1  // Format error (FormErr).
	RcodeServerFailure   ResponseCode = 2  // Server failure (ServFail).
	RcodeNameError       ResponseCode = 3  // Non-existent domain (NXDomain).
	RcodeNotImplemented  ResponseCode = 4  // Not implemented (NotImp).
	RcodeRefused         ResponseCode = 5  // Refused.
	RcodeNameExists      ResponseCode = 6  // Name exists (YXDomain).
	RcodeRecordExists    ResponseCode = 7  // RR set exists (YXRRSet).
	RcodeRecordNotExists ResponseCode = 8  // RR set does not exist (NXRRSet).
	RcodeNotAuth         ResponseCode = 9  // Not authoritative (NotAuth).
	RcodeNotZone         ResponseCode = 10 // Not zone (NotZone).
	RcodeDsoNotImpl      ResponseCode = 11 // DSO-TYPE not implemented (DSOTYPENI).
	RcodeBadName         ResponseCode = 20 // Bad name (BADNAME).
	RcodeBadAlg          ResponseCode = 21 // Bad algorithm (BADALG).
	RcodeBadTruncation   ResponseCode = 22 // Bad truncation (BADTRUNC).
)

// ResponseCodeToError maps a DNS RCODE to an error value.
func ResponseCodeToError(rc ResponseCode) error {
	switch rc {
	case RcodeSuccess:
		return nil
	case RcodeFormatError, RcodeBadName, RcodeBadTruncation, RcodeNotZone:
		return errors.ErrParse
	case RcodeServerFailure:
		return errors.ErrFailed
	case RcodeNameError, RcodeRecordNotExists:
		return errors.ErrNotFound
	case RcodeNotImplemented, RcodeDsoNotImpl:
		return errors.ErrNotImplemented
	case RcodeBadAlg:
		return errors.ErrNotCapable
	case RcodeNameExists, RcodeRecordExists:
		return errors.ErrDuplicated
	case RcodeRefused, RcodeNotAuth:
		return errors.ErrSecurity
	default:
		return errors.ErrFailed
	}
}

// ---------------------------------------------------------------------------
// RR Type constants
// ---------------------------------------------------------------------------

// RRType represents a DNS resource record type.
type RRType uint16

// DNS resource record types.
const (
	RRTypeZero  RRType = 0   // SIG(0) special indicator.
	RRTypeA     RRType = 1   // IPv4 address (A).
	RRTypeNs    RRType = 2   // Authoritative name server (NS).
	RRTypeCname RRType = 5   // Canonical name (CNAME).
	RRTypeSoa   RRType = 6   // Start of authority (SOA).
	RRTypePtr   RRType = 12  // Pointer (PTR).
	RRTypeMx    RRType = 15  // Mail exchange (MX).
	RRTypeTxt   RRType = 16  // Text strings (TXT).
	RRTypeRp    RRType = 17  // Responsible person (RP).
	RRTypeAfsdb RRType = 18  // AFS Data Base location.
	RRTypeRt    RRType = 21  // Route Through.
	RRTypeSig   RRType = 24  // Signature (SIG).
	RRTypeKey   RRType = 25  // Public key (KEY).
	RRTypePx    RRType = 26  // X.400 mail mapping (PX).
	RRTypeAaaa  RRType = 28  // IPv6 address (AAAA).
	RRTypeSrv   RRType = 33  // Service locator (SRV).
	RRTypeKx    RRType = 36  // Key Exchanger (KX).
	RRTypeDname RRType = 39  // Delegation name (DNAME).
	RRTypeOpt   RRType = 41  // Option (OPT / EDNS).
	RRTypeNsec  RRType = 47  // NSEC.
	RRTypeAny   RRType = 255 // Wildcard match (*).
)

// RRTypeToString returns a human-readable name for the given RR type.
func RRTypeToString(t RRType) string {
	switch t {
	case RRTypeA:
		return "A"
	case RRTypeNs:
		return "NS"
	case RRTypeCname:
		return "CNAME"
	case RRTypeSoa:
		return "SOA"
	case RRTypePtr:
		return "PTR"
	case RRTypeMx:
		return "MX"
	case RRTypeTxt:
		return "TXT"
	case RRTypeRp:
		return "RP"
	case RRTypeAfsdb:
		return "AFSDB"
	case RRTypeRt:
		return "RT"
	case RRTypeSig:
		return "SIG"
	case RRTypeKey:
		return "KEY"
	case RRTypePx:
		return "PX"
	case RRTypeAaaa:
		return "AAAA"
	case RRTypeSrv:
		return "SRV"
	case RRTypeKx:
		return "KX"
	case RRTypeDname:
		return "DNAME"
	case RRTypeOpt:
		return "OPT"
	case RRTypeNsec:
		return "NSEC"
	case RRTypeAny:
		return "ANY"
	default:
		return "UNKNOWN"
	}
}

// ---------------------------------------------------------------------------
// RR Class constants
// ---------------------------------------------------------------------------

// RRClass represents a DNS resource record class.
type RRClass uint16

// DNS resource record classes.
const (
	ClassInternet RRClass = 1   // Internet (IN).
	ClassNone     RRClass = 254 // None (RFC 2136).
	ClassAny      RRClass = 255 // Any (*).
)

// ---------------------------------------------------------------------------
// Header (12 bytes wire format)
// ---------------------------------------------------------------------------

// HeaderSize is the wire size of a DNS header in bytes.
const HeaderSize = 12

// Header is a DNS message header (RFC 1035 section 4.1.1).
//
// Wire format (12 bytes, big-endian):
//
//	Offset  Size  Field
//	  0       2   MessageID
//	  2       1   Flags[0]: QR(1) | OpCode(4) | AA(1) | TC(1) | RD(1)
//	  3       1   Flags[1]: RA(1) | Z(3) | RCODE(4)
//	  4       2   QDCount
//	  6       2   ANCount
//	  8       2   NSCount
//	 10       2   ARCount
type Header struct {
	MessageID uint16
	Flags     [2]byte
	QDCount   uint16 // Question count.
	ANCount   uint16 // Answer count.
	NSCount   uint16 // Authority record count.
	ARCount   uint16 // Additional record count.
}

// Flag bit positions and masks.
const (
	// Flags[0] bits.
	qrFlagMask  = 0x80
	opCodeMask  = 0x78
	opCodeShift = 3
	aaFlagMask  = 0x04
	tcFlagMask  = 0x02
	rdFlagMask  = 0x01

	// Flags[1] bits.
	raFlagMask = 0x80
	rcodeMask  = 0x0F
)

// --- Getters/Setters -------------------------------------------------------

// GetType returns the QR flag (query or response).
func (h *Header) GetType() HeaderType {
	if h.Flags[0]&qrFlagMask != 0 {
		return TypeResponse
	}
	return TypeQuery
}

// SetType sets the QR flag.
func (h *Header) SetType(t HeaderType) {
	if t == TypeResponse {
		h.Flags[0] |= qrFlagMask
	} else {
		h.Flags[0] &^= qrFlagMask
	}
}

// GetOpCode returns the OpCode.
func (h *Header) GetOpCode() OpCode {
	return OpCode((h.Flags[0] & opCodeMask) >> opCodeShift)
}

// SetOpCode sets the OpCode.
func (h *Header) SetOpCode(oc OpCode) {
	h.Flags[0] = (h.Flags[0] &^ opCodeMask) | (byte(oc) << opCodeShift)
}

// IsAuthoritativeAnswer returns the AA flag.
func (h *Header) IsAuthoritativeAnswer() bool { return h.Flags[0]&aaFlagMask != 0 }

// SetAuthoritativeAnswer sets the AA flag.
func (h *Header) SetAuthoritativeAnswer(v bool) {
	if v {
		h.Flags[0] |= aaFlagMask
	} else {
		h.Flags[0] &^= aaFlagMask
	}
}

// IsTruncated returns the TC flag.
func (h *Header) IsTruncated() bool { return h.Flags[0]&tcFlagMask != 0 }

// SetTruncated sets the TC flag.
func (h *Header) SetTruncated(v bool) {
	if v {
		h.Flags[0] |= tcFlagMask
	} else {
		h.Flags[0] &^= tcFlagMask
	}
}

// IsRecursionDesired returns the RD flag.
func (h *Header) IsRecursionDesired() bool { return h.Flags[0]&rdFlagMask != 0 }

// SetRecursionDesired sets the RD flag.
func (h *Header) SetRecursionDesired(v bool) {
	if v {
		h.Flags[0] |= rdFlagMask
	} else {
		h.Flags[0] &^= rdFlagMask
	}
}

// IsRecursionAvailable returns the RA flag.
func (h *Header) IsRecursionAvailable() bool { return h.Flags[1]&raFlagMask != 0 }

// SetRecursionAvailable sets the RA flag.
func (h *Header) SetRecursionAvailable(v bool) {
	if v {
		h.Flags[1] |= raFlagMask
	} else {
		h.Flags[1] &^= raFlagMask
	}
}

// GetResponseCode returns the RCODE.
func (h *Header) GetResponseCode() ResponseCode {
	return ResponseCode(h.Flags[1] & rcodeMask)
}

// SetResponseCode sets the RCODE.
func (h *Header) SetResponseCode(rc ResponseCode) {
	h.Flags[1] = (h.Flags[1] &^ rcodeMask) | (byte(rc) & rcodeMask)
}

// MarshalBinary encodes the Header into 12 bytes of wire format.
func (h *Header) MarshalBinary() [HeaderSize]byte {
	var buf [HeaderSize]byte
	binary.BigEndian.PutUint16(buf[0:2], h.MessageID)
	buf[2] = h.Flags[0]
	buf[3] = h.Flags[1]
	binary.BigEndian.PutUint16(buf[4:6], h.QDCount)
	binary.BigEndian.PutUint16(buf[6:8], h.ANCount)
	binary.BigEndian.PutUint16(buf[8:10], h.NSCount)
	binary.BigEndian.PutUint16(buf[10:12], h.ARCount)
	return buf
}

// UnmarshalBinary decodes a 12-byte wire-format header.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return errors.ErrParse
	}
	h.MessageID = binary.BigEndian.Uint16(data[0:2])
	h.Flags[0] = data[2]
	h.Flags[1] = data[3]
	h.QDCount = binary.BigEndian.Uint16(data[4:6])
	h.ANCount = binary.BigEndian.Uint16(data[6:8])
	h.NSCount = binary.BigEndian.Uint16(data[8:10])
	h.ARCount = binary.BigEndian.Uint16(data[10:12])
	return nil
}

// ---------------------------------------------------------------------------
// UpdateHeader (DNS Update, RFC 2136)
// ---------------------------------------------------------------------------

// UpdateHeader is a DNS Update header. It has the same wire format as Header
// but provides aliases for the section counts per RFC 2136.
type UpdateHeader struct {
	Header
}

// NewUpdateHeader creates an UpdateHeader with OpCode set to Update.
func NewUpdateHeader() UpdateHeader {
	var uh UpdateHeader
	uh.SetOpCode(OpcodeUpdate)
	return uh
}

// ZoneCount returns the zone record count (QDCount alias).
func (uh *UpdateHeader) ZoneCount() uint16 { return uh.QDCount }

// SetZoneCount sets the zone record count.
func (uh *UpdateHeader) SetZoneCount(n uint16) { uh.QDCount = n }

// PrerequisiteCount returns the prerequisite record count (ANCount alias).
func (uh *UpdateHeader) PrerequisiteCount() uint16 { return uh.ANCount }

// SetPrerequisiteCount sets the prerequisite record count.
func (uh *UpdateHeader) SetPrerequisiteCount(n uint16) { uh.ANCount = n }

// UpdateCount returns the update record count (NSCount alias).
func (uh *UpdateHeader) UpdateCount() uint16 { return uh.NSCount }

// SetUpdateCount sets the update record count.
func (uh *UpdateHeader) SetUpdateCount(n uint16) { uh.NSCount = n }

// ---------------------------------------------------------------------------
// Question (4 bytes wire format, follows encoded name)
// ---------------------------------------------------------------------------

// QuestionSize is the wire size of a Question in bytes (excluding the name).
const QuestionSize = 4

// Question is a DNS question entry (RFC 1035 section 4.1.2).
//
// Wire format (4 bytes, big-endian, follows encoded name):
//
//	Offset  Size  Field
//	  0       2   QType
//	  2       2   QClass
type Question struct {
	Type  RRType
	Class RRClass
}

// MarshalBinary encodes the Question into 4 bytes.
func (q *Question) MarshalBinary() [QuestionSize]byte {
	var buf [QuestionSize]byte
	binary.BigEndian.PutUint16(buf[0:2], uint16(q.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(q.Class))
	return buf
}

// UnmarshalBinary decodes a 4-byte wire-format question.
func (q *Question) UnmarshalBinary(data []byte) error {
	if len(data) < QuestionSize {
		return errors.ErrParse
	}
	q.Type = RRType(binary.BigEndian.Uint16(data[0:2]))
	q.Class = RRClass(binary.BigEndian.Uint16(data[2:4]))
	return nil
}

// ---------------------------------------------------------------------------
// Zone (DNS Update zone section, RFC 2136)
// ---------------------------------------------------------------------------

// Zone is a DNS Update zone entry. Same wire format as Question.
// Per RFC 2136, Type is always SOA and Class is always Internet.
type Zone struct {
	Question
}

// NewZone creates a Zone with Type=SOA, Class=Internet.
func NewZone() Zone {
	return Zone{Question{Type: RRTypeSoa, Class: ClassInternet}}
}

// ---------------------------------------------------------------------------
// ResourceRecord (10 bytes wire format, follows encoded name)
// ---------------------------------------------------------------------------

// ResourceRecordSize is the wire size of the fixed part of a resource record
// (excluding the name and RDATA).
const ResourceRecordSize = 10

// ResourceRecord is the fixed portion of a DNS resource record
// (RFC 1035 section 4.1.3).
//
// Wire format (10 bytes, big-endian, follows encoded name):
//
//	Offset  Size  Field
//	  0       2   Type
//	  2       2   Class
//	  4       4   TTL
//	  8       2   RDLength
type ResourceRecord struct {
	Type     RRType
	Class    RRClass
	TTL      uint32
	RDLength uint16
}

// Init initializes the resource record with the given type and class.
func (rr *ResourceRecord) Init(t RRType, class RRClass) {
	rr.Type = t
	rr.Class = class
	rr.TTL = 0
	rr.RDLength = 0
}

// Matches returns true if the record matches the given type and class.
func (rr *ResourceRecord) Matches(t RRType, class RRClass) bool {
	return rr.Type == t && rr.Class == class
}

// GetSize returns the total size of the record (fixed part + RDATA).
func (rr *ResourceRecord) GetSize() int {
	return ResourceRecordSize + int(rr.RDLength)
}

// MarshalBinary encodes the ResourceRecord fixed fields into 10 bytes.
func (rr *ResourceRecord) MarshalBinary() [ResourceRecordSize]byte {
	var buf [ResourceRecordSize]byte
	binary.BigEndian.PutUint16(buf[0:2], uint16(rr.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(rr.Class))
	binary.BigEndian.PutUint32(buf[4:8], rr.TTL)
	binary.BigEndian.PutUint16(buf[8:10], rr.RDLength)
	return buf
}

// UnmarshalBinary decodes a 10-byte wire-format resource record header.
func (rr *ResourceRecord) UnmarshalBinary(data []byte) error {
	if len(data) < ResourceRecordSize {
		return errors.ErrParse
	}
	rr.Type = RRType(binary.BigEndian.Uint16(data[0:2]))
	rr.Class = RRClass(binary.BigEndian.Uint16(data[2:4]))
	rr.TTL = binary.BigEndian.Uint32(data[4:8])
	rr.RDLength = binary.BigEndian.Uint16(data[8:10])
	return nil
}

// ---------------------------------------------------------------------------
// ARecord (A, type 1)
// ---------------------------------------------------------------------------

// ARecordRDataSize is the RDATA size for an A record (4 bytes).
const ARecordRDataSize = 4

// ARecord is a DNS A record (IPv4 address).
type ARecord struct {
	ResourceRecord
	Address [4]byte // IPv4 address.
}

// Init initializes an A record.
func (r *ARecord) Init() {
	r.ResourceRecord.Init(RRTypeA, ClassInternet)
	r.RDLength = ARecordRDataSize
}

// MarshalBinary encodes the A record (header + 4-byte address).
func (r *ARecord) MarshalBinary() []byte {
	hdr := r.ResourceRecord.MarshalBinary()
	buf := make([]byte, ResourceRecordSize+ARecordRDataSize)
	copy(buf, hdr[:])
	copy(buf[ResourceRecordSize:], r.Address[:])
	return buf
}

// UnmarshalBinary decodes an A record from wire data.
func (r *ARecord) UnmarshalBinary(data []byte) error {
	if err := r.ResourceRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(data) < ResourceRecordSize+ARecordRDataSize {
		return errors.ErrParse
	}
	copy(r.Address[:], data[ResourceRecordSize:ResourceRecordSize+ARecordRDataSize])
	return nil
}

// ---------------------------------------------------------------------------
// AaaaRecord (AAAA, type 28)
// ---------------------------------------------------------------------------

// AaaaRecordRDataSize is the RDATA size for an AAAA record (16 bytes).
const AaaaRecordRDataSize = 16

// AaaaRecord is a DNS AAAA record (IPv6 address).
type AaaaRecord struct {
	ResourceRecord
	Address ip6.Address // 16-byte IPv6 address.
}

// Init initializes an AAAA record.
func (r *AaaaRecord) Init() {
	r.ResourceRecord.Init(RRTypeAaaa, ClassInternet)
	r.RDLength = AaaaRecordRDataSize
}

// IsValid returns true if the record has the correct type and size.
func (r *AaaaRecord) IsValid() bool {
	return r.Type == RRTypeAaaa && r.RDLength == AaaaRecordRDataSize
}

// MarshalBinary encodes the AAAA record (header + 16-byte address).
func (r *AaaaRecord) MarshalBinary() []byte {
	hdr := r.ResourceRecord.MarshalBinary()
	buf := make([]byte, ResourceRecordSize+AaaaRecordRDataSize)
	copy(buf, hdr[:])
	copy(buf[ResourceRecordSize:], r.Address[:])
	return buf
}

// UnmarshalBinary decodes an AAAA record from wire data.
func (r *AaaaRecord) UnmarshalBinary(data []byte) error {
	if err := r.ResourceRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(data) < ResourceRecordSize+AaaaRecordRDataSize {
		return errors.ErrParse
	}
	copy(r.Address[:], data[ResourceRecordSize:ResourceRecordSize+AaaaRecordRDataSize])
	return nil
}

// ---------------------------------------------------------------------------
// PtrRecord (PTR, type 12)
// ---------------------------------------------------------------------------

// PtrRecord is a DNS PTR record. The RDATA is a variable-length encoded
// DNS name, so there are no extra fixed fields beyond ResourceRecord.
type PtrRecord struct {
	ResourceRecord
}

// Init initializes a PTR record.
func (r *PtrRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypePtr, class)
}

// ReadPtrName reads the domain name from PTR RDATA in message data.
// The data parameter is the complete DNS message, and offset must point
// to the start of the RDATA. Returns the name and the offset past the record.
func (r *PtrRecord) ReadPtrName(data []byte, offset int) (ptrName string, nextOffset int, readErr error) {
	name, _, err := ReadName(data, offset)
	if err != nil {
		return "", offset, err
	}
	endOffset := offset + int(r.RDLength)
	return name, endOffset, nil
}

// ---------------------------------------------------------------------------
// CnameRecord (CNAME, type 5)
// ---------------------------------------------------------------------------

// CnameRecord is a DNS CNAME record. The RDATA is a variable-length encoded
// DNS name.
type CnameRecord struct {
	ResourceRecord
}

// Init initializes a CNAME record.
func (r *CnameRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeCname, class)
}

// ReadCanonicalName reads the canonical name from CNAME RDATA.
func (r *CnameRecord) ReadCanonicalName(data []byte, offset int) (canonicalName string, nextOffset int, readErr error) {
	name, _, err := ReadName(data, offset)
	if err != nil {
		return "", offset, err
	}
	endOffset := offset + int(r.RDLength)
	return name, endOffset, nil
}

// ---------------------------------------------------------------------------
// TxtRecord (TXT, type 16)
// ---------------------------------------------------------------------------

// TxtRecord is a DNS TXT record. The RDATA is a sequence of
// length-prefixed character strings.
type TxtRecord struct {
	ResourceRecord
}

// Init initializes a TXT record.
func (r *TxtRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeTxt, class)
}

// ReadTxtData reads the raw TXT data from RDATA. The caller provides a
// buffer; if it is too small, as many bytes as fit are copied and ErrNoBufs
// is returned. The returned int is the number of bytes copied.
func (r *TxtRecord) ReadTxtData(data []byte, offset int) (outputData []byte, copiedBytes int, readErr error) {
	rdLen := int(r.RDLength)
	endOffset := offset + rdLen
	if endOffset > len(data) {
		return nil, offset, errors.ErrParse
	}
	txtData := make([]byte, rdLen)
	copy(txtData, data[offset:endOffset])
	return txtData, endOffset, nil
}

// VerifyTxtData validates TXT record data. The data must be a sequence
// of length-prefixed strings that exactly consume the buffer.
// If allowEmpty is false, zero-length data is rejected.
func VerifyTxtData(data []byte, allowEmpty bool) bool {
	if !allowEmpty && len(data) == 0 {
		return false
	}
	i := 0
	for i < len(data) {
		entryLen := int(data[i])
		i++
		i += entryLen
	}
	return i == len(data)
}

// ---------------------------------------------------------------------------
// SrvRecord (SRV, type 33)
// ---------------------------------------------------------------------------

// SrvRecordFixedSize is the size of the fixed RDATA fields of an SRV record
// (priority + weight + port = 6 bytes).
const SrvRecordFixedSize = 6

// SrvRecord is a DNS SRV record (RFC 2782).
//
// RDATA format:
//
//	Offset  Size  Field
//	  0       2   Priority
//	  2       2   Weight
//	  4       2   Port
//	  6       *   Target host name (encoded DNS name)
type SrvRecord struct {
	ResourceRecord
	Priority uint16
	Weight   uint16
	Port     uint16
}

// Init initializes an SRV record.
func (r *SrvRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeSrv, class)
}

// MarshalBinary encodes the SRV record fixed fields (header + priority/weight/port).
func (r *SrvRecord) MarshalBinary() []byte {
	hdr := r.ResourceRecord.MarshalBinary()
	buf := make([]byte, ResourceRecordSize+SrvRecordFixedSize)
	copy(buf, hdr[:])
	binary.BigEndian.PutUint16(buf[ResourceRecordSize:], r.Priority)
	binary.BigEndian.PutUint16(buf[ResourceRecordSize+2:], r.Weight)
	binary.BigEndian.PutUint16(buf[ResourceRecordSize+4:], r.Port)
	return buf
}

// UnmarshalBinary decodes an SRV record from wire data.
func (r *SrvRecord) UnmarshalBinary(data []byte) error {
	if err := r.ResourceRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(data) < ResourceRecordSize+SrvRecordFixedSize {
		return errors.ErrParse
	}
	r.Priority = binary.BigEndian.Uint16(data[ResourceRecordSize:])
	r.Weight = binary.BigEndian.Uint16(data[ResourceRecordSize+2:])
	r.Port = binary.BigEndian.Uint16(data[ResourceRecordSize+4:])
	return nil
}

// ReadTargetHostName reads the target hostname from SRV RDATA.
// offset must point to the start of RDATA (after the ResourceRecord header).
func (r *SrvRecord) ReadTargetHostName(data []byte, rdataOffset int) (string, error) {
	nameOffset := rdataOffset + SrvRecordFixedSize
	name, _, err := ReadName(data, nameOffset)
	return name, err
}

// ---------------------------------------------------------------------------
// KEY record constants
// ---------------------------------------------------------------------------

// Key record protocol values.
const (
	KeyProtocolTls    uint8 = 1 //nolint:revive // TLS; preserve the exported API spelling for existing callers.
	KeyProtocolDnsSec uint8 = 3 //nolint:revive // DNSSEC; preserve the exported API spelling for existing callers.
)

// Key record algorithm values.
const (
	KeyAlgorithmEcdsaP256Sha256 uint8 = 13 // ECDSA P-256 with SHA-256.
	KeyAlgorithmEcdsaP384Sha384 uint8 = 14 // ECDSA P-384 with SHA-384.
	KeyAlgorithmEd25519         uint8 = 15 // Ed25519.
	KeyAlgorithmEd448           uint8 = 16 // Ed448.
)

// KeyUseFlags represents the use flags of a KEY record.
type KeyUseFlags uint8

// KEY record flags controlling authentication and confidentiality use.
const (
	KeyUseAuthConfidPermitted KeyUseFlags = 0x00 // Auth and/or confidentiality permitted.
	KeyUseAuthPermitted       KeyUseFlags = 0x40 // Only authentication permitted.
	KeyUseConfidPermitted     KeyUseFlags = 0x80 // Only confidentiality permitted.
	KeyUseNoKey               KeyUseFlags = 0xC0 // No key value.
)

// KeyOwnerFlags represents the owner flags of a KEY record.
type KeyOwnerFlags uint8

// KEY record flags identifying the key owner.
const (
	KeyOwnerUser     KeyOwnerFlags = 0x00 // User/account key.
	KeyOwnerZone     KeyOwnerFlags = 0x01 // Zone key.
	KeyOwnerNonZone  KeyOwnerFlags = 0x02 // Non-zone entity key.
	KeyOwnerReserved KeyOwnerFlags = 0x03 // Reserved.
)

// Signatory flag constants (RFC 2137).
const (
	KeySignatoryFlagZone    uint8 = 0x08 // Authorized for zone ops.
	KeySignatoryFlagStrong  uint8 = 0x04 // Can add/delete RRs even if auth'd by other key.
	KeySignatoryFlagUnique  uint8 = 0x02 // Can add/update RRs for single owner name.
	KeySignatoryFlagGeneral uint8 = 0x01 // General update key.
)

// ---------------------------------------------------------------------------
// KeyRecord (KEY, type 25)
// ---------------------------------------------------------------------------

// KeyRecordFixedSize is the size of the fixed RDATA fields of a KEY record
// (flags + protocol + algorithm = 4 bytes).
const KeyRecordFixedSize = 4

// KeyRecord is a DNS KEY record (RFC 2535).
//
// RDATA format:
//
//	Offset  Size  Field
//	  0       2   Flags (use[2] | z[1] | xt[1] | z[2] | owner[2] | z[4] | sig[4])
//	  2       1   Protocol
//	  3       1   Algorithm
//	  4       *   Public key data
type KeyRecord struct {
	ResourceRecord
	Flags     [2]byte
	Protocol  uint8
	Algorithm uint8
}

// Flag masks within Flags bytes.
const (
	keyUseFlagsMask      = 0xC0
	keyOwnerFlagsMask    = 0x03
	keySignatoryFlagMask = 0x0F
)

// Init initializes a KEY record.
func (r *KeyRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeKey, class)
}

// IsValid returns true if the record type is KEY.
func (r *KeyRecord) IsValid() bool {
	return r.Type == RRTypeKey
}

// GetUseFlags returns the use flags from Flags[0].
func (r *KeyRecord) GetUseFlags() KeyUseFlags {
	return KeyUseFlags(r.Flags[0] & keyUseFlagsMask)
}

// GetOwnerFlags returns the owner flags from Flags[0].
func (r *KeyRecord) GetOwnerFlags() KeyOwnerFlags {
	return KeyOwnerFlags(r.Flags[0] & keyOwnerFlagsMask)
}

// GetSignatoryFlags returns the signatory flags from Flags[1].
func (r *KeyRecord) GetSignatoryFlags() uint8 {
	return r.Flags[1] & keySignatoryFlagMask
}

// SetFlags sets the use, owner, and signatory flags.
func (r *KeyRecord) SetFlags(use KeyUseFlags, owner KeyOwnerFlags, sig uint8) {
	r.Flags[0] = byte(use) | byte(owner)
	r.Flags[1] = sig & keySignatoryFlagMask
}

// MarshalBinary encodes the KEY record (header + flags/protocol/algorithm).
func (r *KeyRecord) MarshalBinary() []byte {
	hdr := r.ResourceRecord.MarshalBinary()
	buf := make([]byte, ResourceRecordSize+KeyRecordFixedSize)
	copy(buf, hdr[:])
	buf[ResourceRecordSize] = r.Flags[0]
	buf[ResourceRecordSize+1] = r.Flags[1]
	buf[ResourceRecordSize+2] = r.Protocol
	buf[ResourceRecordSize+3] = r.Algorithm
	return buf
}

// UnmarshalBinary decodes a KEY record from wire data.
func (r *KeyRecord) UnmarshalBinary(data []byte) error {
	if err := r.ResourceRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	if len(data) < ResourceRecordSize+KeyRecordFixedSize {
		return errors.ErrParse
	}
	r.Flags[0] = data[ResourceRecordSize]
	r.Flags[1] = data[ResourceRecordSize+1]
	r.Protocol = data[ResourceRecordSize+2]
	r.Algorithm = data[ResourceRecordSize+3]
	return nil
}

// ---------------------------------------------------------------------------
// Ecdsa256KeyRecord (KEY with ECDSA P-256 public key, 64 bytes)
// ---------------------------------------------------------------------------

// Ecdsa256KeySize is the size of an ECDSA P-256 public key (uncompressed x,y).
const Ecdsa256KeySize = 64

// Ecdsa256KeyRecord is a KEY record containing an ECDSA P-256 public key.
type Ecdsa256KeyRecord struct {
	KeyRecord
	Key [Ecdsa256KeySize]byte
}

// Init initializes an ECDSA P-256 KEY record.
func (r *Ecdsa256KeyRecord) Init() {
	r.KeyRecord.Init(ClassInternet)
	r.Algorithm = KeyAlgorithmEcdsaP256Sha256
	r.RDLength = KeyRecordFixedSize + Ecdsa256KeySize
}

// IsValid returns true if the record is a valid ECDSA P-256 KEY record.
func (r *Ecdsa256KeyRecord) IsValid() bool {
	return r.KeyRecord.IsValid() &&
		r.RDLength == KeyRecordFixedSize+Ecdsa256KeySize &&
		r.Algorithm == KeyAlgorithmEcdsaP256Sha256
}

// MarshalBinary encodes the ECDSA-256 KEY record.
func (r *Ecdsa256KeyRecord) MarshalBinary() []byte {
	keyBase := r.KeyRecord.MarshalBinary()
	buf := make([]byte, len(keyBase)+Ecdsa256KeySize)
	copy(buf, keyBase)
	copy(buf[len(keyBase):], r.Key[:])
	return buf
}

// UnmarshalBinary decodes an ECDSA-256 KEY record from wire data.
func (r *Ecdsa256KeyRecord) UnmarshalBinary(data []byte) error {
	if err := r.KeyRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	keyStart := ResourceRecordSize + KeyRecordFixedSize
	if len(data) < keyStart+Ecdsa256KeySize {
		return errors.ErrParse
	}
	copy(r.Key[:], data[keyStart:keyStart+Ecdsa256KeySize])
	return nil
}

// ---------------------------------------------------------------------------
// SigRecord (SIG, type 24)
// ---------------------------------------------------------------------------

// SigRecordFixedSize is the size of the fixed RDATA fields of a SIG record
// (typeCovered + algorithm + labels + origTTL + expiration + inception +
// keyTag = 18 bytes).
const SigRecordFixedSize = 18

// SigRecord is a DNS SIG record (RFC 2535 section 4.1).
//
// RDATA format:
//
//	Offset  Size  Field
//	  0       2   TypeCovered
//	  2       1   Algorithm
//	  3       1   Labels
//	  4       4   OriginalTTL
//	  8       4   Expiration   (seconds since Jan 1 1970)
//	 12       4   Inception    (seconds since Jan 1 1970)
//	 16       2   KeyTag
//	 18       *   Signer name  (encoded DNS name)
//	  *       *   Signature    (variable)
type SigRecord struct {
	ResourceRecord
	TypeCovered uint16
	Algorithm   uint8
	Labels      uint8
	OriginalTTL uint32
	Expiration  uint32
	Inception   uint32
	KeyTag      uint16
}

// Init initializes a SIG record. For SIG(0), use ClassAny.
func (r *SigRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeSig, class)
}

// IsValid returns true if the record is a valid SIG record.
func (r *SigRecord) IsValid() bool {
	return r.Type == RRTypeSig && r.RDLength >= SigRecordFixedSize
}

// MarshalBinary encodes the SIG record fixed fields.
func (r *SigRecord) MarshalBinary() []byte {
	hdr := r.ResourceRecord.MarshalBinary()
	buf := make([]byte, ResourceRecordSize+SigRecordFixedSize)
	copy(buf, hdr[:])
	off := ResourceRecordSize
	binary.BigEndian.PutUint16(buf[off:], r.TypeCovered)
	buf[off+2] = r.Algorithm
	buf[off+3] = r.Labels
	binary.BigEndian.PutUint32(buf[off+4:], r.OriginalTTL)
	binary.BigEndian.PutUint32(buf[off+8:], r.Expiration)
	binary.BigEndian.PutUint32(buf[off+12:], r.Inception)
	binary.BigEndian.PutUint16(buf[off+16:], r.KeyTag)
	return buf
}

// UnmarshalBinary decodes a SIG record from wire data.
func (r *SigRecord) UnmarshalBinary(data []byte) error {
	if err := r.ResourceRecord.UnmarshalBinary(data); err != nil {
		return err
	}
	off := ResourceRecordSize
	if len(data) < off+SigRecordFixedSize {
		return errors.ErrParse
	}
	r.TypeCovered = binary.BigEndian.Uint16(data[off:])
	r.Algorithm = data[off+2]
	r.Labels = data[off+3]
	r.OriginalTTL = binary.BigEndian.Uint32(data[off+4:])
	r.Expiration = binary.BigEndian.Uint32(data[off+8:])
	r.Inception = binary.BigEndian.Uint32(data[off+12:])
	r.KeyTag = binary.BigEndian.Uint16(data[off+16:])
	return nil
}

// ReadSignerName reads the signer name from SIG RDATA.
// rdataOffset must point to the start of RDATA. Returns the signer name
// and the offset of the signature data (immediately after the signer name).
func (r *SigRecord) ReadSignerName(data []byte, rdataOffset int) (signerName string, signatureOffset int, readErr error) {
	nameOffset := rdataOffset + SigRecordFixedSize
	name, sigOffset, err := ReadName(data, nameOffset)
	if err != nil {
		return "", rdataOffset, err
	}
	return name, sigOffset, nil
}

// ---------------------------------------------------------------------------
// OptRecord (OPT / EDNS, type 41)
// ---------------------------------------------------------------------------

// OptRecord is a DNS OPT pseudo-record (EDNS, RFC 6891).
// The Class field is repurposed as UDP payload size.
// The TTL field is repurposed as: ExtRcode(8) | Version(8) | Flags(16).
type OptRecord struct {
	ResourceRecord
}

// TTL byte indices for the reinterpreted fields.
const (
	optExtRCodeByteIndex = 0
	optVersionByteIndex  = 1
	optFlagByteIndex     = 2
	optDNSSecFlagBit     = 0x80
)

// Init initializes an OPT record.
func (r *OptRecord) Init() {
	r.ResourceRecord.Init(RRTypeOpt, 0)
	r.TTL = 0
}

// GetUDPPayloadSize returns the UDP payload size (from Class field).
func (r *OptRecord) GetUDPPayloadSize() uint16 { return uint16(r.Class) }

// SetUDPPayloadSize sets the UDP payload size (into Class field).
func (r *OptRecord) SetUDPPayloadSize(size uint16) { r.Class = RRClass(size) }

// GetExtendedResponseCode returns the extended RCODE (upper 8 bits).
func (r *OptRecord) GetExtendedResponseCode() uint8 {
	return uint8(r.TTL >> 24)
}

// SetExtendedResponseCode sets the extended RCODE.
func (r *OptRecord) SetExtendedResponseCode(code uint8) {
	r.TTL = (r.TTL & 0x00FFFFFF) | (uint32(code) << 24)
}

// GetVersion returns the EDNS version.
func (r *OptRecord) GetVersion() uint8 {
	return uint8(r.TTL >> 16)
}

// SetVersion sets the EDNS version.
func (r *OptRecord) SetVersion(v uint8) {
	r.TTL = (r.TTL & 0xFF00FFFF) | (uint32(v) << 16)
}

// IsDnsSecOK returns the DO (DNSSEC OK) flag.
func (r *OptRecord) IsDnsSecOK() bool { //nolint:revive // Preserve the exported API spelling for existing callers.
	return (r.TTL>>8)&uint32(optDNSSecFlagBit) != 0
}

// SetDnsSecOK sets or clears the DO flag.
func (r *OptRecord) SetDnsSecOK(v bool) { //nolint:revive // Preserve the exported API spelling for existing callers.
	if v {
		r.TTL |= uint32(optDNSSecFlagBit) << 8
	} else {
		r.TTL &^= uint32(optDNSSecFlagBit) << 8
	}
}

// ---------------------------------------------------------------------------
// Option (EDNS option, in OPT RDATA)
// ---------------------------------------------------------------------------

// OptionSize is the wire size of the Option header (code + length = 4 bytes).
const OptionSize = 4

// OptionCode constants.
const (
	OptionCodeUpdateLease uint16 = 2 // DNS Update Lease option.
)

// Option is an EDNS option entry within OPT RDATA.
//
// Wire format (4 bytes header + variable data):
//
//	Offset  Size  Field
//	  0       2   OptionCode
//	  2       2   OptionLength
//	  4       *   OptionData
type Option struct {
	Code   uint16
	Length uint16
}

// GetSize returns the total size of the option (header + data).
func (o *Option) GetSize() int { return OptionSize + int(o.Length) }

// MarshalBinary encodes the Option header into 4 bytes.
func (o *Option) MarshalBinary() [OptionSize]byte {
	var buf [OptionSize]byte
	binary.BigEndian.PutUint16(buf[0:2], o.Code)
	binary.BigEndian.PutUint16(buf[2:4], o.Length)
	return buf
}

// UnmarshalBinary decodes an Option header from wire data.
func (o *Option) UnmarshalBinary(data []byte) error {
	if len(data) < OptionSize {
		return errors.ErrParse
	}
	o.Code = binary.BigEndian.Uint16(data[0:2])
	o.Length = binary.BigEndian.Uint16(data[2:4])
	return nil
}

// ---------------------------------------------------------------------------
// LeaseOption (DNS Update Lease, option code 2)
// ---------------------------------------------------------------------------

// LeaseOption is a DNS Update Lease option (draft-sekar-dns-ul-02).
//
// Short variant (option length = 4): LeaseInterval only.
// Long variant (option length = 8): LeaseInterval + KeyLeaseInterval.
type LeaseOption struct {
	Option
	LeaseInterval    uint32
	KeyLeaseInterval uint32
}

// InitShort initializes a short-variant lease option (lease only).
func (lo *LeaseOption) InitShort(leaseInterval uint32) {
	lo.Code = OptionCodeUpdateLease
	lo.Length = 4
	lo.LeaseInterval = leaseInterval
	lo.KeyLeaseInterval = leaseInterval
}

// InitLong initializes a long-variant lease option (lease + key lease).
func (lo *LeaseOption) InitLong(leaseInterval, keyLeaseInterval uint32) {
	lo.Code = OptionCodeUpdateLease
	lo.Length = 8
	lo.LeaseInterval = leaseInterval
	lo.KeyLeaseInterval = keyLeaseInterval
}

// IsShortVariant returns true if this is a short-variant option.
func (lo *LeaseOption) IsShortVariant() bool { return lo.Length == 4 }

// IsValid validates the lease option.
func (lo *LeaseOption) IsValid() bool {
	if lo.Length == 4 {
		return true
	}
	if lo.Length >= 8 {
		return lo.LeaseInterval <= lo.KeyLeaseInterval
	}
	return false
}

// MarshalBinary encodes the lease option.
func (lo *LeaseOption) MarshalBinary() []byte {
	hdr := lo.Option.MarshalBinary()
	buf := make([]byte, OptionSize+int(lo.Length))
	copy(buf, hdr[:])
	binary.BigEndian.PutUint32(buf[OptionSize:], lo.LeaseInterval)
	if lo.Length >= 8 {
		binary.BigEndian.PutUint32(buf[OptionSize+4:], lo.KeyLeaseInterval)
	}
	return buf
}

// UnmarshalBinary decodes a lease option from wire data.
func (lo *LeaseOption) UnmarshalBinary(data []byte) error {
	if err := lo.Option.UnmarshalBinary(data); err != nil {
		return err
	}
	if lo.Length < 4 || len(data) < OptionSize+int(lo.Length) {
		return errors.ErrParse
	}
	lo.LeaseInterval = binary.BigEndian.Uint32(data[OptionSize:])
	if lo.Length >= 8 {
		lo.KeyLeaseInterval = binary.BigEndian.Uint32(data[OptionSize+4:])
	} else {
		lo.KeyLeaseInterval = lo.LeaseInterval
	}
	return nil
}

// FindLeaseOption searches OPT record RDATA for an UpdateLease option.
// data is the OPT RDATA, starting at the first option.
// Returns nil if not found.
func FindLeaseOption(data []byte) (*LeaseOption, error) {
	offset := 0
	for offset+OptionSize <= len(data) {
		var opt Option
		if err := opt.UnmarshalBinary(data[offset:]); err != nil {
			return nil, err
		}
		if opt.Code == OptionCodeUpdateLease {
			var lo LeaseOption
			if err := lo.UnmarshalBinary(data[offset:]); err != nil {
				return nil, err
			}
			if !lo.IsValid() {
				return nil, errors.ErrParse
			}
			return &lo, nil
		}
		offset += opt.GetSize()
	}
	return nil, errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// NsecRecord (NSEC, type 47)
// ---------------------------------------------------------------------------

// NsecRecord is a DNS NSEC record (RFC 3845). The RDATA contains a
// "next domain name" followed by type bit maps. This struct only
// represents the ResourceRecord header; the RDATA is parsed separately.
type NsecRecord struct {
	ResourceRecord
}

// Init initializes an NSEC record.
func (r *NsecRecord) Init(class RRClass) {
	r.ResourceRecord.Init(RRTypeNsec, class)
}

// ---------------------------------------------------------------------------
// TypeBitMap (NSEC type bit map, RFC 3845 section 2.1.2)
// ---------------------------------------------------------------------------

// TypeBitMapMinSize is the minimum wire size of a TypeBitMap (2 bytes).
const TypeBitMapMinSize = 2

// TypeBitMapMaxLength is the maximum bitmap length (32 bytes = 256 bits).
const TypeBitMapMaxLength = 32

// TypeBitMap represents an NSEC type bitmap for a single window block.
//
// Wire format:
//
//	Offset  Size    Field
//	  0       1     BlockNumber (window block number, 0-255)
//	  1       1     BitmapLength (1-32)
//	  2     1-32    Bitmaps
type TypeBitMap struct {
	BlockNumber  uint8
	BitmapLength uint8
	Bitmaps      [TypeBitMapMaxLength]byte
}

// GetSize returns the wire size of this TypeBitMap entry.
func (tbm *TypeBitMap) GetSize() int {
	return 2 + int(tbm.BitmapLength)
}

// AddType adds an RR type to the bitmap. The type must be in the
// block indicated by BlockNumber (type >> 8 == BlockNumber).
func (tbm *TypeBitMap) AddType(rrType RRType) {
	if uint16(rrType)>>8 != uint16(tbm.BlockNumber) {
		return
	}
	typeByte := uint8(rrType & 0xFF)
	index := typeByte / 8
	mask := uint8(0x80) >> (typeByte % 8)
	tbm.Bitmaps[index] |= mask
	if index+1 > tbm.BitmapLength {
		tbm.BitmapLength = index + 1
	}
}

// ContainsType reports whether the bitmap contains the given RR type.
func (tbm *TypeBitMap) ContainsType(rrType RRType) bool {
	if uint16(rrType)>>8 != uint16(tbm.BlockNumber) {
		return false
	}
	typeByte := uint8(rrType & 0xFF)
	index := typeByte / 8
	mask := uint8(0x80) >> (typeByte % 8)
	if index >= tbm.BitmapLength {
		return false
	}
	return tbm.Bitmaps[index]&mask != 0
}

// MarshalBinary encodes the TypeBitMap.
func (tbm *TypeBitMap) MarshalBinary() []byte {
	size := tbm.GetSize()
	buf := make([]byte, size)
	buf[0] = tbm.BlockNumber
	buf[1] = tbm.BitmapLength
	copy(buf[2:], tbm.Bitmaps[:tbm.BitmapLength])
	return buf
}

// UnmarshalBinary decodes a TypeBitMap from wire data.
func (tbm *TypeBitMap) UnmarshalBinary(data []byte) error {
	if len(data) < TypeBitMapMinSize {
		return errors.ErrParse
	}
	tbm.BlockNumber = data[0]
	tbm.BitmapLength = data[1]
	if tbm.BitmapLength == 0 || tbm.BitmapLength > TypeBitMapMaxLength {
		return errors.ErrParse
	}
	if len(data) < 2+int(tbm.BitmapLength) {
		return errors.ErrParse
	}
	copy(tbm.Bitmaps[:tbm.BitmapLength], data[2:2+int(tbm.BitmapLength)])
	return nil
}

// ---------------------------------------------------------------------------
// TxtEntry (TXT record key-value entry, RFC 6763 section 6.3)
// ---------------------------------------------------------------------------

// TXT entry constants.
const (
	TxtKeyMinLength  = 1  // Minimum TXT key length (RFC 6763).
	TxtKeyMaxLength  = 9  // Recommended max TXT key length (RFC 6763).
	TxtKeyIterMaxLen = 64 // Max key length supported by TxtIterator.
)

// TxtEntry represents a single key-value entry in a TXT record.
//
// Encoding rules (RFC 6763):
//   - If Key is non-empty, the entry encodes as "<length><key=value>" or
//     "<length><key>" (boolean, when Value is nil).
//   - If Key is empty and Value is non-nil, Value is treated as pre-encoded
//     TXT-DATA and appended as-is.
type TxtEntry struct {
	Key   string // Key string; empty means pre-encoded value.
	Value []byte // Value bytes; nil means boolean attribute.
}

// AppendTo encodes the TxtEntry and appends it to buf.
func (e *TxtEntry) AppendTo(buf []byte) ([]byte, error) {
	if e.Key == "" {
		// Pre-encoded data: append as-is.
		if len(e.Value) > 0 {
			buf = append(buf, e.Value...)
		}
		return buf, nil
	}

	keyLen := len(e.Key)
	if keyLen < TxtKeyMinLength {
		return buf, errors.ErrInvalidArgs
	}

	if e.Value == nil {
		// Boolean attribute: "key" with no value.
		if keyLen > 255 {
			return buf, errors.ErrInvalidArgs
		}
		buf = append(buf, byte(keyLen))
		buf = append(buf, e.Key...)
		return buf, nil
	}

	// Key=value pair.
	totalLen := keyLen + 1 + len(e.Value) // key + '=' + value
	if totalLen > 255 {
		return buf, errors.ErrInvalidArgs
	}
	buf = append(buf, byte(totalLen))
	buf = append(buf, e.Key...)
	buf = append(buf, '=')
	buf = append(buf, e.Value...)
	return buf, nil
}

// AppendTxtEntries encodes an array of TxtEntry values and appends them to buf.
// If no entries produce output, a single zero byte is appended per RFC 6763.
func AppendTxtEntries(buf []byte, entries []TxtEntry) ([]byte, error) {
	startLen := len(buf)
	for i := range entries {
		var err error
		buf, err = entries[i].AppendTo(buf)
		if err != nil {
			return buf, err
		}
	}
	// If nothing was appended, emit a single zero byte.
	if len(buf) == startLen {
		buf = append(buf, 0)
	}
	return buf, nil
}

// ---------------------------------------------------------------------------
// TxtIterator iterates over key-value entries in TXT record data.
// ---------------------------------------------------------------------------

// TxtIterator parses TXT record data into key-value entries.
type TxtIterator struct {
	data   []byte
	offset int
}

// NewTxtIterator creates a new TxtIterator over the given TXT data.
func NewTxtIterator(data []byte) *TxtIterator {
	return &TxtIterator{data: data}
}

// Next returns the next TxtEntry. Returns ErrNotFound when done, or
// ErrParse on malformed data.
//
// Entries with empty strings or strings starting with '=' are silently
// skipped. Keys longer than TxtKeyIterMaxLen cause the entry to be
// returned with Key="" and the entire string in Value.
func (it *TxtIterator) Next() (TxtEntry, error) {
	for it.offset < len(it.data) {
		if it.offset >= len(it.data) {
			break
		}
		entryLen := int(it.data[it.offset])
		it.offset++

		end := it.offset + entryLen
		if end > len(it.data) {
			return TxtEntry{}, errors.ErrParse
		}

		entryData := it.data[it.offset:end]
		it.offset = end

		// Skip empty strings.
		if entryLen == 0 {
			continue
		}

		// Skip strings starting with '='.
		if entryData[0] == '=' {
			continue
		}

		// Scan for '=' separator.
		for i := 0; i < len(entryData); i++ {
			if entryData[i] == '=' {
				key := string(entryData[:i])
				if i > TxtKeyIterMaxLen {
					// Key too long: return raw entry.
					return TxtEntry{Key: "", Value: entryData}, nil
				}
				value := entryData[i+1:]
				return TxtEntry{Key: key, Value: value}, nil
			}

			if i >= TxtKeyIterMaxLen {
				// Key exceeds max length before finding '='.
				return TxtEntry{Key: "", Value: entryData}, nil
			}
		}

		// No '=' found: boolean attribute.
		key := string(entryData)
		if len(key) > TxtKeyIterMaxLen {
			return TxtEntry{Key: "", Value: entryData}, nil
		}
		return TxtEntry{Key: key, Value: nil}, nil
	}

	return TxtEntry{}, errors.ErrNotFound
}

// ---------------------------------------------------------------------------
// SkipName skips over an encoded DNS name in wire data at offset.
// Returns the offset past the name field.
// ---------------------------------------------------------------------------

// SkipName skips over an encoded DNS name in data starting at offset,
// returning the offset past the name field. This is equivalent to
// OpenThread's Name::ParseName.
func SkipName(data []byte, offset int) (int, error) {
	if offset < 0 || offset >= len(data) {
		return offset, errors.ErrParse
	}

	nameEndOffset := -1
	minOffset := offset

	for {
		if offset < 0 || offset >= len(data) {
			return 0, errors.ErrParse
		}

		labelByte := data[offset]
		labelType := labelByte & labelTypeMask

		switch labelType {
		case textLabelType:
			labelLen := int(labelByte)
			if labelLen == 0 {
				if nameEndOffset < 0 {
					nameEndOffset = offset + 1
				}
				return nameEndOffset, nil
			}
			offset = offset + 1 + labelLen
			if offset > len(data) {
				return 0, errors.ErrParse
			}

		case pointerLabelType:
			if offset+1 >= len(data) {
				return 0, errors.ErrParse
			}
			if nameEndOffset < 0 {
				nameEndOffset = offset + 2
			}
			ptrVal := (int(data[offset])<<8 | int(data[offset+1])) & pointerOffsetMask
			if ptrVal >= minOffset {
				return 0, errors.ErrParse
			}
			offset = ptrVal
			minOffset = ptrVal

		default:
			return 0, errors.ErrParse
		}
	}
}

// ---------------------------------------------------------------------------
// ParseRecords skips over numRecords resource records starting at offset.
// Each record consists of: encoded name + ResourceRecord header + RDATA.
// Returns the offset past the last record.
// ---------------------------------------------------------------------------

// ParseRecords skips over numRecords resource records in data starting at
// offset. Returns the updated offset past all skipped records.
func ParseRecords(data []byte, offset, numRecords int) (int, error) {
	for i := 0; i < numRecords; i++ {
		// Skip the name.
		var err error
		offset, err = SkipName(data, offset)
		if err != nil {
			return offset, err
		}

		// Read the resource record header.
		var rr ResourceRecord
		if err := rr.UnmarshalBinary(data[offset:]); err != nil {
			return offset, err
		}

		// Skip past the header + RDATA.
		offset += rr.GetSize()
		if offset > len(data) {
			return offset, errors.ErrParse
		}
	}
	return offset, nil
}
