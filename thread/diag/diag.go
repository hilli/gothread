// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package diag

import (
	"sync"

	"github.com/hilli/gothread/encoding"
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/tlv"
)

// ResponseHandler is called when a diagnostic response is received.
// source is the IPv6 address of the responding device,
// tlvs contains the parsed diagnostic TLVs from the response.
type ResponseHandler func(source ip6.Address, tlvs []tlv.TLV)

// pendingQuery tracks an outstanding diagnostic get request.
type pendingQuery struct {
	queryID     uint16
	destination ip6.Address
	handler     ResponseHandler
}

// Client manages outgoing network diagnostic requests.
type Client struct {
	mu          sync.Mutex
	nextQueryID uint16
	pending     []pendingQuery
}

// NewClient creates a new diagnostic Client.
func NewClient() *Client {
	return &Client{}
}

// nextID returns the next query ID and increments the counter.
func (c *Client) nextID() uint16 {
	id := c.nextQueryID
	c.nextQueryID++
	return id
}

// BuildDiagnosticGetRequest constructs the payload for a Diagnostic Get
// request message. The payload is a Type List TLV containing the requested
// diagnostic TLV types.
//
// Returns the serialized request payload and the assigned query ID.
func (c *Client) BuildDiagnosticGetRequest(tlvTypes []uint8) (request []byte, id uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()

	queryID := c.nextID()

	// Build the payload: TypeList TLV + QueryID TLV.
	typeListTLV := MarshalBytesTLV(TypeTypeList, tlvTypes)
	queryIDTLV := MarshalUint16TLV(TypeQueryID, queryID)

	payload := typeListTLV.Marshal()
	payload = append(payload, queryIDTLV.Marshal()...)

	return payload, queryID
}

// RegisterQuery registers a pending query with a response handler.
// Call this after sending the diagnostic get request to track responses.
func (c *Client) RegisterQuery(queryID uint16, destination ip6.Address, handler ResponseHandler) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.pending = append(c.pending, pendingQuery{
		queryID:     queryID,
		destination: destination,
		handler:     handler,
	})
}

// HandleResponse processes an incoming diagnostic response.
// It matches the response to a pending query by query ID and invokes the
// registered handler. Returns ErrNotFound if no matching query exists.
func (c *Client) HandleResponse(source ip6.Address, data []byte) error {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return errors.ErrParse
	}

	// Look for a QueryID TLV in the response.
	queryIDTlv := tlv.FindByType(tlvs, TypeQueryID)
	if queryIDTlv == nil {
		return errors.ErrParse
	}

	queryID, err2 := UnmarshalUint16TLV(queryIDTlv.Value)
	if err2 != nil {
		return errors.ErrParse
	}

	c.mu.Lock()
	var matched *pendingQuery
	matchIdx := -1
	for i := range c.pending {
		if c.pending[i].queryID == queryID {
			matched = &c.pending[i]
			matchIdx = i
			break
		}
	}

	if matched == nil {
		c.mu.Unlock()
		return errors.ErrNotFound
	}

	handler := matched.handler

	// Check if this is the last answer fragment.
	answerTlv := tlv.FindByType(tlvs, TypeAnswer)
	isLast := true
	if answerTlv != nil {
		answer, err3 := UnmarshalAnswerTlv(answerTlv.Value)
		if err3 == nil {
			isLast = answer.IsLast
		}
	}

	// Remove the query if this is the last fragment.
	if isLast {
		c.pending = append(c.pending[:matchIdx], c.pending[matchIdx+1:]...)
	}
	c.mu.Unlock()

	if handler != nil {
		handler(source, tlvs)
	}

	return nil
}

// CancelQuery removes a pending query by its query ID.
// Returns ErrNotFound if the query ID is not pending.
func (c *Client) CancelQuery(queryID uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.pending {
		if c.pending[i].queryID == queryID {
			c.pending = append(c.pending[:i], c.pending[i+1:]...)
			return nil
		}
	}
	return errors.ErrNotFound
}

// PendingCount returns the number of outstanding queries.
func (c *Client) PendingCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending)
}

// Server handles incoming network diagnostic requests by building
// responses from a provider.
type Server struct {
	provider DiagnosticProvider
}

// DiagnosticProvider is the interface that must be implemented to supply
// diagnostic data for response building. Each method corresponds to a
// diagnostic TLV type. Methods return the serialized TLV value and true
// if the data is available, or nil and false to skip.
type DiagnosticProvider interface {
	// GetExtMacAddress returns the extended MAC address TLV value (8 bytes).
	GetExtMacAddress() ([]byte, bool)
	// GetAddress16 returns the RLOC16 as a big-endian uint16 (2 bytes).
	GetAddress16() (uint16, bool)
	// GetMode returns the device mode byte.
	GetMode() (uint8, bool)
	// GetTimeout returns the SED polling timeout in seconds.
	GetTimeout() (uint32, bool)
	// GetConnectivity returns the connectivity metrics.
	GetConnectivity() (*Connectivity, bool)
	// GetRoute64 returns the route table.
	GetRoute64() (*Route64, bool)
	// GetLeaderData returns the leader data TLV value (8 bytes).
	GetLeaderData() ([]byte, bool)
	// GetNetworkData returns the raw network data.
	GetNetworkData() ([]byte, bool)
	// GetIPv6AddressList returns the IPv6 address list (16 bytes per address).
	GetIPv6AddressList() ([]byte, bool)
	// GetMacCounters returns the MAC counters.
	GetMacCounters() (*MacCounters, bool)
	// GetBatteryLevel returns the battery level (0-100).
	GetBatteryLevel() (uint8, bool)
	// GetSupplyVoltage returns the supply voltage in millivolts.
	GetSupplyVoltage() (uint16, bool)
	// GetChildTable returns the child table entries.
	GetChildTable() ([]ChildTableEntry, bool)
	// GetChannelPages returns the channel pages data.
	GetChannelPages() ([]byte, bool)
	// GetMaxChildTimeout returns the max child timeout.
	GetMaxChildTimeout() (uint32, bool)
	// GetVersion returns the Thread version number.
	GetVersion() (uint16, bool)
	// GetVendorName returns the vendor name string.
	GetVendorName() (string, bool)
	// GetVendorModel returns the vendor model string.
	GetVendorModel() (string, bool)
	// GetVendorSWVersion returns the vendor software version string.
	GetVendorSWVersion() (string, bool)
	// GetThreadStackVersion returns the Thread stack version string.
	GetThreadStackVersion() (string, bool)
	// GetMleCounters returns the MLE counters.
	GetMleCounters() (*MleCounters, bool)
}

// NewServer creates a new diagnostic Server with the given provider.
func NewServer(provider DiagnosticProvider) *Server {
	return &Server{provider: provider}
}

// HandleGetRequest processes an incoming Diagnostic Get request.
// It reads the requested TLV types from the payload and builds a response
// containing the requested diagnostic data.
//
// Returns the serialized response payload.
func (s *Server) HandleGetRequest(data []byte) ([]byte, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, errors.ErrParse
	}

	// Find the Type List TLV to know which types are requested.
	typeListTlv := tlv.FindByType(tlvs, TypeTypeList)
	if typeListTlv == nil {
		return nil, errors.ErrParse
	}
	requestedTypes := typeListTlv.Value

	// Find the Query ID TLV if present.
	var queryID uint16
	hasQueryID := false
	queryIDTlv := tlv.FindByType(tlvs, TypeQueryID)
	if queryIDTlv != nil {
		qid, err2 := UnmarshalUint16TLV(queryIDTlv.Value)
		if err2 == nil {
			queryID = qid
			hasQueryID = true
		}
	}

	// Build response TLVs.
	var response []byte
	for _, typ := range requestedTypes {
		t := s.buildTLV(typ)
		if t != nil {
			response = append(response, t.Marshal()...)
		}
	}

	// Append the Query ID if one was provided in the request.
	if hasQueryID {
		qidTLV := MarshalUint16TLV(TypeQueryID, queryID)
		response = append(response, qidTLV.Marshal()...)
	}

	return response, nil
}

// buildTLV builds a single diagnostic TLV for the given type using the provider.
func (s *Server) buildTLV(typ uint8) *tlv.TLV {
	switch typ {
	case TypeExtMacAddress:
		if data, ok := s.provider.GetExtMacAddress(); ok {
			t := MarshalBytesTLV(TypeExtMacAddress, data)
			return &t
		}
	case TypeAddress16:
		if val, ok := s.provider.GetAddress16(); ok {
			t := MarshalUint16TLV(TypeAddress16, val)
			return &t
		}
	case TypeMode:
		if val, ok := s.provider.GetMode(); ok {
			t := MarshalByteTLV(TypeMode, val)
			return &t
		}
	case TypeTimeout:
		if val, ok := s.provider.GetTimeout(); ok {
			t := MarshalUint32TLV(TypeTimeout, val)
			return &t
		}
	case TypeConnectivity:
		if val, ok := s.provider.GetConnectivity(); ok {
			t := MarshalConnectivity(val)
			return &t
		}
	case TypeRoute64:
		if val, ok := s.provider.GetRoute64(); ok {
			t := MarshalRoute64(val)
			return &t
		}
	case TypeLeaderData:
		if data, ok := s.provider.GetLeaderData(); ok {
			t := MarshalBytesTLV(TypeLeaderData, data)
			return &t
		}
	case TypeNetworkData:
		if data, ok := s.provider.GetNetworkData(); ok {
			t := MarshalBytesTLV(TypeNetworkData, data)
			return &t
		}
	case TypeIPv6AddressList:
		if data, ok := s.provider.GetIPv6AddressList(); ok {
			t := MarshalBytesTLV(TypeIPv6AddressList, data)
			return &t
		}
	case TypeMacCounters:
		if val, ok := s.provider.GetMacCounters(); ok {
			t := MarshalMacCounters(val)
			return &t
		}
	case TypeBatteryLevel:
		if val, ok := s.provider.GetBatteryLevel(); ok {
			t := MarshalByteTLV(TypeBatteryLevel, val)
			return &t
		}
	case TypeSupplyVoltage:
		if val, ok := s.provider.GetSupplyVoltage(); ok {
			t := MarshalUint16TLV(TypeSupplyVoltage, val)
			return &t
		}
	case TypeChildTable:
		if entries, ok := s.provider.GetChildTable(); ok {
			t := MarshalChildTable(entries)
			return &t
		}
	case TypeChannelPages:
		if data, ok := s.provider.GetChannelPages(); ok {
			t := MarshalBytesTLV(TypeChannelPages, data)
			return &t
		}
	case TypeMaxChildTimeout:
		if val, ok := s.provider.GetMaxChildTimeout(); ok {
			t := MarshalUint32TLV(TypeMaxChildTimeout, val)
			return &t
		}
	case TypeVersion:
		if val, ok := s.provider.GetVersion(); ok {
			t := MarshalUint16TLV(TypeVersion, val)
			return &t
		}
	case TypeVendorName:
		if val, ok := s.provider.GetVendorName(); ok {
			t := MarshalStringTLV(TypeVendorName, val)
			return &t
		}
	case TypeVendorModel:
		if val, ok := s.provider.GetVendorModel(); ok {
			t := MarshalStringTLV(TypeVendorModel, val)
			return &t
		}
	case TypeVendorSWVersion:
		if val, ok := s.provider.GetVendorSWVersion(); ok {
			t := MarshalStringTLV(TypeVendorSWVersion, val)
			return &t
		}
	case TypeThreadStackVersion:
		if val, ok := s.provider.GetThreadStackVersion(); ok {
			t := MarshalStringTLV(TypeThreadStackVersion, val)
			return &t
		}
	case TypeMleCounters:
		if val, ok := s.provider.GetMleCounters(); ok {
			t := MarshalMleCounters(val)
			return &t
		}
	}
	return nil
}

// BuildDiagnosticResetRequest constructs the payload for a Diagnostic Reset
// request message. The payload is a Type List TLV containing the TLV types
// to reset.
func BuildDiagnosticResetRequest(tlvTypes []uint8) []byte {
	typeListTLV := MarshalBytesTLV(TypeTypeList, tlvTypes)
	return typeListTLV.Marshal()
}

// ParseTypeList extracts the list of requested TLV types from a diagnostic
// request payload. Returns the type list or an error if the payload is malformed.
func ParseTypeList(data []byte) ([]uint8, error) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return nil, errors.ErrParse
	}

	typeListTlv := tlv.FindByType(tlvs, TypeTypeList)
	if typeListTlv == nil {
		return nil, errors.ErrParse
	}

	result := make([]uint8, len(typeListTlv.Value))
	copy(result, typeListTlv.Value)
	return result, nil
}

// ParseQueryID extracts the query ID from a diagnostic request/response payload.
// Returns the query ID and true if found, or 0 and false if not present.
func ParseQueryID(data []byte) (uint16, bool) {
	tlvs, err := tlv.ParseAll(data)
	if err != nil {
		return 0, false
	}

	queryIDTlv := tlv.FindByType(tlvs, TypeQueryID)
	if queryIDTlv == nil {
		return 0, false
	}

	qid := encoding.BigEndianReadUint16(queryIDTlv.Value)
	return qid, true
}
