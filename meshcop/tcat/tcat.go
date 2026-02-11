// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Package tcat implements the Thread Commissioning over Authenticated TLS
// (TCAT) agent, which provides BLE-based commissioning for Thread devices.
//
// Reference: openthread/src/core/meshcop/tcat_agent.hpp/cpp
package tcat

import (
	"encoding/binary"
	"fmt"
	"sync"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Command classes
// ---------------------------------------------------------------------------

// CommandClass identifies a TCAT command category.
type CommandClass uint8

const (
	// ClassGeneral covers general-purpose commands.
	ClassGeneral CommandClass = 0
	// ClassCommissioning covers commissioning commands (dataset provisioning).
	ClassCommissioning CommandClass = 1
	// ClassExtraction covers extraction commands (reading device data).
	ClassExtraction CommandClass = 2
	// ClassDecommissioning covers decommissioning commands (factory reset).
	ClassDecommissioning CommandClass = 3
	// ClassApplication covers application-specific commands.
	ClassApplication CommandClass = 4
)

// String returns the name of the command class.
func (c CommandClass) String() string {
	switch c {
	case ClassGeneral:
		return "General"
	case ClassCommissioning:
		return "Commissioning"
	case ClassExtraction:
		return "Extraction"
	case ClassDecommissioning:
		return "Decommissioning"
	case ClassApplication:
		return "Application"
	default:
		return fmt.Sprintf("CommandClass(%d)", c)
	}
}

// ---------------------------------------------------------------------------
// TLV types
// ---------------------------------------------------------------------------

// TlvType identifies a TCAT TLV type.
type TlvType uint8

const (
	// TlvResponseWithStatus is the Response-with-Status TLV.
	TlvResponseWithStatus TlvType = 1
	// TlvActiveDataset is the Active Operational Dataset TLV.
	TlvActiveDataset TlvType = 2
	// TlvCommissionerCert is the Commissioner Certificate TLV.
	TlvCommissionerCert TlvType = 3
	// TlvDeviceAuthData is the Device Authentication Data TLV.
	TlvDeviceAuthData TlvType = 4
	// TlvThreadDomainName is the Thread Domain Name TLV.
	TlvThreadDomainName TlvType = 5
	// TlvPendingDataset is the Pending Operational Dataset TLV.
	TlvPendingDataset TlvType = 6
	// TlvDecommission is the Decommission TLV.
	TlvDecommission TlvType = 7
	// TlvApplicationData is the Application-specific Data TLV.
	TlvApplicationData TlvType = 8
	// TlvDeviceID is the Device ID TLV.
	TlvDeviceID TlvType = 9
	// TlvVendorInfo is the Vendor Info TLV.
	TlvVendorInfo TlvType = 10
)

// String returns the name of the TLV type.
func (t TlvType) String() string {
	switch t {
	case TlvResponseWithStatus:
		return "ResponseWithStatus"
	case TlvActiveDataset:
		return "ActiveDataset"
	case TlvCommissionerCert:
		return "CommissionerCert"
	case TlvDeviceAuthData:
		return "DeviceAuthData"
	case TlvThreadDomainName:
		return "ThreadDomainName"
	case TlvPendingDataset:
		return "PendingDataset"
	case TlvDecommission:
		return "Decommission"
	case TlvApplicationData:
		return "ApplicationData"
	case TlvDeviceID:
		return "DeviceID"
	case TlvVendorInfo:
		return "VendorInfo"
	default:
		return fmt.Sprintf("TlvType(%d)", t)
	}
}

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

// StatusCode represents a TCAT response status.
type StatusCode uint8

const (
	// StatusSuccess indicates success.
	StatusSuccess StatusCode = 0
	// StatusUnsupported indicates the command is not supported.
	StatusUnsupported StatusCode = 1
	// StatusParseError indicates a TLV parse failure.
	StatusParseError StatusCode = 2
	// StatusBusy indicates the agent is busy.
	StatusBusy StatusCode = 3
	// StatusUndefined is reserved.
	StatusUndefined StatusCode = 4
	// StatusGeneral indicates a general/unspecified error.
	StatusGeneral StatusCode = 5
	// StatusAuth indicates an authentication failure.
	StatusAuth StatusCode = 6
	// StatusUnauthorized indicates insufficient authorization.
	StatusUnauthorized StatusCode = 16
)

// String returns the name of the status code.
func (s StatusCode) String() string {
	switch s {
	case StatusSuccess:
		return "Success"
	case StatusUnsupported:
		return "Unsupported"
	case StatusParseError:
		return "ParseError"
	case StatusBusy:
		return "Busy"
	case StatusUndefined:
		return "Undefined"
	case StatusGeneral:
		return "General"
	case StatusAuth:
		return "Auth"
	case StatusUnauthorized:
		return "Unauthorized"
	default:
		return fmt.Sprintf("StatusCode(%d)", s)
	}
}

// ---------------------------------------------------------------------------
// Vendor info
// ---------------------------------------------------------------------------

// VendorInfo holds TCAT vendor identification fields.
type VendorInfo struct {
	// Name is the vendor name (max 32 bytes).
	Name string
	// Model is the device model (max 32 bytes).
	Model string
	// SwVersion is the software version string (max 16 bytes).
	SwVersion string
}

// ---------------------------------------------------------------------------
// Authorization
// ---------------------------------------------------------------------------

// Authorization represents the set of command classes a connected
// commissioner is authorized to execute.
type Authorization struct {
	classes [5]bool // indexed by CommandClass
}

// Allow grants authorization for the given command class.
func (a *Authorization) Allow(c CommandClass) {
	if int(c) < len(a.classes) {
		a.classes[c] = true
	}
}

// IsAllowed reports whether the given command class is authorized.
func (a *Authorization) IsAllowed(c CommandClass) bool {
	if int(c) >= len(a.classes) {
		return false
	}
	return a.classes[c]
}

// AllowAll grants authorization for all command classes.
func (a *Authorization) AllowAll() {
	for i := range a.classes {
		a.classes[i] = true
	}
}

// Clear revokes all authorizations.
func (a *Authorization) Clear() {
	a.classes = [5]bool{}
}

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

// Agent implements the TCAT (Thread Commissioning over Authenticated TLS)
// protocol handler. It manages BLE-based commissioning sessions for
// provisioning Thread credentials to a device.
type Agent struct {
	mu sync.Mutex

	enabled   bool
	connected bool

	// Authorization of the current session.
	auth Authorization

	// Device identity.
	deviceID [8]byte

	// Vendor information.
	vendorInfo VendorInfo

	// Handler invoked when active dataset is received.
	datasetHandler func(data []byte) error
}

// NewAgent creates a new TCAT Agent.
func NewAgent() *Agent {
	return &Agent{}
}

// IsEnabled reports whether the TCAT agent is enabled.
func (a *Agent) IsEnabled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.enabled
}

// Enable enables the TCAT agent for accepting connections.
func (a *Agent) Enable() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.enabled {
		return goterrors.ErrAlready
	}
	a.enabled = true
	return nil
}

// Disable disables the TCAT agent. Any active connection is dropped.
func (a *Agent) Disable() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.enabled = false
	a.connected = false
	a.auth.Clear()
}

// IsConnected reports whether a BLE commissioner session is active.
func (a *Agent) IsConnected() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

// HandleConnect should be called when a BLE TLS connection is established.
// The authorization describes which command classes the peer is allowed.
func (a *Agent) HandleConnect(auth Authorization) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.enabled {
		return goterrors.ErrInvalidState
	}
	if a.connected {
		return goterrors.ErrBusy
	}
	a.connected = true
	a.auth = auth
	return nil
}

// HandleDisconnect should be called when the BLE TLS connection ends.
func (a *Agent) HandleDisconnect() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connected = false
	a.auth.Clear()
}

// GetDeviceID returns the device ID (typically derived from EUI-64).
func (a *Agent) GetDeviceID() [8]byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deviceID
}

// SetDeviceID sets the device ID.
func (a *Agent) SetDeviceID(id [8]byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.deviceID = id
}

// GetVendorInfo returns the current vendor info.
func (a *Agent) GetVendorInfo() VendorInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.vendorInfo
}

// SetVendorInfo sets the vendor information advertised to commissioners.
func (a *Agent) SetVendorInfo(info VendorInfo) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.vendorInfo = info
}

// SetDatasetHandler sets the callback invoked when an Active Dataset
// is received via TCAT commissioning.
func (a *Agent) SetDatasetHandler(handler func(data []byte) error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.datasetHandler = handler
}

// HandleSingleTlv processes a single TCAT TLV received from a commissioner.
// Returns a response TLV (ResponseWithStatus) and any error.
func (a *Agent) HandleSingleTlv(data []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled || !a.connected {
		return nil, goterrors.ErrInvalidState
	}

	if len(data) < 2 {
		return encodeStatusResponse(StatusParseError), goterrors.ErrParse
	}

	tlvType := TlvType(data[0])
	tlvLen := int(data[1])

	if len(data) < 2+tlvLen {
		return encodeStatusResponse(StatusParseError), goterrors.ErrParse
	}

	tlvValue := data[2 : 2+tlvLen]

	return a.handleTlvLocked(tlvType, tlvValue)
}

// HandleCommand processes a TCAT command identified by type and value.
func (a *Agent) HandleCommand(tlvType TlvType, value []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if !a.enabled || !a.connected {
		return nil, goterrors.ErrInvalidState
	}

	return a.handleTlvLocked(tlvType, value)
}

// handleTlvLocked dispatches a TLV to the appropriate handler.
// Must be called with a.mu held.
func (a *Agent) handleTlvLocked(tlvType TlvType, value []byte) ([]byte, error) {
	switch tlvType {
	case TlvActiveDataset:
		return a.handleActiveDatasetLocked(value)
	case TlvDeviceID:
		return a.handleDeviceIDGetLocked()
	case TlvVendorInfo:
		return a.handleVendorInfoGetLocked()
	case TlvDecommission:
		return a.handleDecommissionLocked()
	default:
		return encodeStatusResponse(StatusUnsupported), nil
	}
}

// handleActiveDatasetLocked processes an incoming Active Dataset TLV.
func (a *Agent) handleActiveDatasetLocked(value []byte) ([]byte, error) {
	if !a.auth.IsAllowed(ClassCommissioning) {
		return encodeStatusResponse(StatusUnauthorized), nil
	}

	if a.datasetHandler != nil {
		if err := a.datasetHandler(value); err != nil {
			return encodeStatusResponse(StatusGeneral), nil
		}
	}

	return encodeStatusResponse(StatusSuccess), nil
}

// handleDeviceIDGetLocked returns the device ID as a TLV.
func (a *Agent) handleDeviceIDGetLocked() ([]byte, error) {
	if !a.auth.IsAllowed(ClassGeneral) {
		return encodeStatusResponse(StatusUnauthorized), nil
	}

	return encodeTlv(TlvDeviceID, a.deviceID[:]), nil
}

// handleVendorInfoGetLocked returns vendor info as a TLV.
func (a *Agent) handleVendorInfoGetLocked() ([]byte, error) {
	if !a.auth.IsAllowed(ClassGeneral) {
		return encodeStatusResponse(StatusUnauthorized), nil
	}

	// Encode vendor info: name\0model\0swversion
	var payload []byte
	payload = append(payload, []byte(a.vendorInfo.Name)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(a.vendorInfo.Model)...)
	payload = append(payload, 0)
	payload = append(payload, []byte(a.vendorInfo.SwVersion)...)

	return encodeTlv(TlvVendorInfo, payload), nil
}

// handleDecommissionLocked processes a decommission request.
func (a *Agent) handleDecommissionLocked() ([]byte, error) {
	if !a.auth.IsAllowed(ClassDecommissioning) {
		return encodeStatusResponse(StatusUnauthorized), nil
	}

	// In a full implementation this would trigger a factory reset.
	return encodeStatusResponse(StatusSuccess), nil
}

// ---------------------------------------------------------------------------
// TLV encoding helpers
// ---------------------------------------------------------------------------

// encodeTlv encodes a single TLV as [type(1), length(1), value...].
func encodeTlv(typ TlvType, value []byte) []byte {
	buf := make([]byte, 2+len(value))
	buf[0] = uint8(typ)
	buf[1] = uint8(len(value))
	copy(buf[2:], value)
	return buf
}

// encodeStatusResponse builds a ResponseWithStatus TLV containing the
// given status code as a 2-byte big-endian value.
func encodeStatusResponse(status StatusCode) []byte {
	var val [2]byte
	binary.BigEndian.PutUint16(val[:], uint16(status))
	return encodeTlv(TlvResponseWithStatus, val[:])
}
