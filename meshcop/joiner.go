// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package meshcop

import (
	"crypto/sha256"
	"encoding/binary"
	"sync"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/coap"
)

// ---------------------------------------------------------------------------
// Joiner state machine
// ---------------------------------------------------------------------------

// JoinerState represents the state of the Joiner.
type JoinerState uint8

const (
	// JoinerStateIdle means the Joiner is not active.
	JoinerStateIdle JoinerState = iota
	// JoinerStateDiscover means the Joiner is scanning for Joiner Routers.
	JoinerStateDiscover
	// JoinerStateConnect means the DTLS handshake is in progress.
	JoinerStateConnect
	// JoinerStateConnected means the DTLS session is established; JOINER_FINALIZE sent.
	JoinerStateConnected
	// JoinerStateEntrust means the Joiner is waiting for JOINER_ENTRUST.
	JoinerStateEntrust
	// JoinerStateJoined means commissioning succeeded; credentials received.
	JoinerStateJoined
)

// String returns a human-readable name for the state.
func (s JoinerState) String() string {
	switch s {
	case JoinerStateIdle:
		return "Idle"
	case JoinerStateDiscover:
		return "Discover"
	case JoinerStateConnect:
		return "Connecting"
	case JoinerStateConnected:
		return "Connected"
	case JoinerStateEntrust:
		return "Entrust"
	case JoinerStateJoined:
		return "Joined"
	default:
		return "Unknown"
	}
}

// ---------------------------------------------------------------------------
// Joiner scan result and candidate
// ---------------------------------------------------------------------------

// JoinerScanResult describes a Joiner Router discovered during the scan.
type JoinerScanResult struct {
	// ExtAddress is the Joiner Router's extended address.
	ExtAddress types.ExtAddress
	// PanID is the discovered PAN ID.
	PanID uint16
	// JoinerUDPPort is the Joiner Router's UDP port for DTLS.
	JoinerUDPPort uint16
	// Channel is the radio channel.
	Channel uint8
	// SteeringData is the bloom filter from the Discovery Response.
	SteeringData SteeringData
}

// JoinerCandidate is a scored Joiner Router candidate from scanning.
type JoinerCandidate struct {
	ExtAddress    types.ExtAddress
	PanID         uint16
	JoinerUDPPort uint16
	Channel       uint8
	Priority      uint8 // 0 = unused; preferred: 129-255, normal: 1-128
}

// MaxJoinerCandidates is the maximum number of Joiner Router candidates to track.
const MaxJoinerCandidates = 4

// ScanVerdict controls whether a scan result is accepted.
type ScanVerdict uint8

const (
	// ScanVerdictIgnore means the scan result is not a viable candidate.
	ScanVerdictIgnore ScanVerdict = iota
	// ScanVerdictAccept means the scan result is accepted (allows-all).
	ScanVerdictAccept
	// ScanVerdictAcceptPreferred means the scan result matches this specific Joiner.
	ScanVerdictAcceptPreferred
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// joinerFinalizeTimeout is the timeout waiting for JOINER_FINALIZE response.
	joinerFinalizeTimeout = 4 * time.Second
	// joinerEntrustTimeout is the timeout waiting for JOINER_ENTRUST message.
	joinerEntrustTimeout = 4 * time.Second
	// joinerPostJoinDelay is the delay after join before randomizing ExtAddr.
	joinerPostJoinDelay = 100 * time.Millisecond
	// joinerFinalizeURI is the CoAP URI for JOINER_FINALIZE.
	joinerFinalizeURI = "c/jf"
	// joinerEntrustURI is the CoAP URI for JOINER_ENTRUST.
	joinerEntrustURI = "c/je"
	// MinJoinerPSKdLength is the minimum length of a Joiner PSKd.
	MinJoinerPSKdLength = 6
	// DefaultJoinerUDPPort is the default Joiner UDP port.
	DefaultJoinerUDPPort uint16 = 1000
)

// VendorStackVersion contains version information about the Thread stack.
type VendorStackVersion struct {
	OUI      [3]byte
	Major    uint8
	Minor    uint8
	Revision uint8
	Build    uint16
}

// Encode serializes the vendor stack version into 6 bytes:
// OUI(3) + Build(12bits):Revision(4bits) in 2 bytes + Minor(4bits):Major(4bits) in 1 byte.
func (v VendorStackVersion) Encode() []byte {
	buf := make([]byte, 6)
	copy(buf[0:3], v.OUI[:])
	// 2 bytes: upper 12 bits = Build, lower 4 bits = Revision
	br := (uint16(v.Build&0xFFF) << 4) | uint16(v.Revision&0x0F)
	binary.BigEndian.PutUint16(buf[3:5], br)
	// 1 byte: upper 4 bits = Minor, lower 4 bits = Major
	buf[5] = (v.Minor&0x0F)<<4 | (v.Major & 0x0F)
	return buf
}

// ---------------------------------------------------------------------------
// Interfaces for testability
// ---------------------------------------------------------------------------

// JoinerTransport abstracts CoAP messaging for the Joiner.
type JoinerTransport interface {
	// Connect initiates a DTLS handshake with the given peer address and port.
	Connect(addr [16]byte, port uint16, pskd string, cb func(connected bool)) error
	// Send sends application data (CoAP message) over the DTLS session.
	Send(data []byte) error
	// SetReceiveHandler sets the handler for incoming application data.
	SetReceiveHandler(handler func(data []byte))
	// Disconnect tears down the DTLS session.
	Disconnect()
	// RegisterHandler registers a handler for the given URI (unsecured CoAP).
	RegisterHandler(uri string, handler func(msg *coap.Message, info coap.MessageInfo))
	// UnregisterHandler removes the handler for the given URI.
	UnregisterHandler(uri string)
	// SendResponse sends a CoAP response to an incoming request.
	SendResponse(code coap.Code, req *coap.Message, info coap.MessageInfo)
}

// JoinerRadio abstracts radio operations for the Joiner.
type JoinerRadio interface {
	// GetIeeeEUI64 returns the factory IEEE EUI-64.
	GetIeeeEUI64() types.ExtAddress
	// SetChannel sets the radio channel.
	SetChannel(channel uint8)
	// SetPanID sets the radio PAN ID.
	SetPanID(panID uint16)
	// GetChannel returns the current radio channel.
	GetChannel() uint8
	// GetPanID returns the current radio PAN ID.
	GetPanID() uint16
}

// JoinerScanner abstracts MLE Discovery for the Joiner.
type JoinerScanner interface {
	// StartScan begins an MLE Discovery scan on all channels.
	// The callback is invoked for each result; a nil result signals scan complete.
	StartScan(callback func(result *JoinerScanResult)) error
	// StopScan stops an active scan.
	StopScan()
}

// JoinerDatasetSaver abstracts saving the received credentials.
type JoinerDatasetSaver interface {
	// SaveDataset saves the received network credentials.
	SaveDataset(info Info) error
}

// JoinerCompletionCallback is invoked when the join process finishes.
type JoinerCompletionCallback func(err error)

// ---------------------------------------------------------------------------
// Joiner client
// ---------------------------------------------------------------------------

// JoinerClient implements the Thread Joiner state machine.
//
// The join process is:
//  1. Start() → MLE Discovery scan for Joiner Routers
//  2. Evaluate each scan result via steering data check
//  3. Connect to best candidate via DTLS (EC-JPAKE with PSKd)
//  4. Send JOINER_FINALIZE over secure CoAP
//  5. Receive JOINER_FINALIZE response (accept/reject)
//  6. Disconnect DTLS; wait for JOINER_ENTRUST on unsecured CoAP
//  7. Save network credentials and complete
type JoinerClient struct {
	mu sync.Mutex

	state JoinerState

	// Joiner identity
	joinerID  [8]byte
	discerner JoinerDiscerner

	// Configuration (set in Start)
	pskd            string
	provisioningURL string
	vendorName      string
	vendorModel     string
	vendorSWVersion string
	vendorData      string
	stackVersion    VendorStackVersion

	// Pre-built JOINER_FINALIZE message payload (TLVs).
	finalizePayload []byte

	// Candidate management
	candidates   [MaxJoinerCandidates]JoinerCandidate
	candidateIdx int
	firstConnErr error
	hasConnected bool

	// Completion callback
	completionCB JoinerCompletionCallback

	// Dependencies
	transport    JoinerTransport
	radio        JoinerRadio
	scanner      JoinerScanner
	datasetSaver JoinerDatasetSaver

	// Timer injection for testing
	afterFunc func(d time.Duration, f func()) Timer
}

// Timer abstracts a cancellable timer.
type Timer interface {
	Stop() bool
}

// NewJoinerClient creates a new Joiner with the given dependencies.
func NewJoinerClient(
	transport JoinerTransport,
	radio JoinerRadio,
	scanner JoinerScanner,
	datasetSaver JoinerDatasetSaver,
) *JoinerClient {
	j := &JoinerClient{
		state:        JoinerStateIdle,
		transport:    transport,
		radio:        radio,
		scanner:      scanner,
		datasetSaver: datasetSaver,
		afterFunc:    defaultAfterFunc,
	}
	// Compute initial Joiner ID from the factory EUI-64.
	j.joinerID = ComputeJoinerIDFromEUI64(radio.GetIeeeEUI64())
	return j
}

func defaultAfterFunc(d time.Duration, f func()) Timer {
	return time.AfterFunc(d, f)
}

// ---------------------------------------------------------------------------
// Joiner ID computation (SHA-256 based per Thread spec)
// ---------------------------------------------------------------------------

// ComputeJoinerIDFromEUI64 derives a Joiner ID from an IEEE EUI-64.
// It computes SHA-256(EUI-64) and takes the first 8 bytes, then sets the
// Local bit (bit 1 of first byte).
func ComputeJoinerIDFromEUI64(eui64 types.ExtAddress) [8]byte {
	hash := sha256.Sum256(eui64[:])
	var id [8]byte
	copy(id[:], hash[:8])
	id[0] |= 0x02 // Set Local bit
	return id
}

// ---------------------------------------------------------------------------
// PSKd validation
// ---------------------------------------------------------------------------

// ValidateJoinerPSKd checks that a PSKd is valid per Thread spec:
// 6-32 characters, uppercase alphanumeric excluding I, O, Q, Z.
func ValidateJoinerPSKd(pskd string) error {
	if len(pskd) < MinJoinerPSKdLength || len(pskd) > MaxJoinerPSKdLength {
		return errors.ErrInvalidArgs
	}
	for _, c := range pskd {
		if !isValidPSKdChar(byte(c)) {
			return errors.ErrInvalidArgs
		}
	}
	return nil
}

func isValidPSKdChar(c byte) bool {
	// Valid: 0-9, A-H, J-N, P, R-Y (uppercase alphanumeric excluding I, O, Q, Z)
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'A' && c <= 'Z' {
		switch c {
		case 'I', 'O', 'Q', 'Z':
			return false
		default:
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// GetState returns the current Joiner state.
func (j *JoinerClient) GetState() JoinerState {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.state
}

// GetID returns the Joiner ID.
func (j *JoinerClient) GetID() [8]byte {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.joinerID
}

// SetDiscerner sets a Joiner Discerner which overrides EUI-64 based ID
// computation. Only allowed in Idle state.
func (j *JoinerClient) SetDiscerner(d JoinerDiscerner) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != JoinerStateIdle {
		return errors.ErrInvalidState
	}
	if d.BitLength == 0 || d.BitLength > 64 {
		return errors.ErrInvalidArgs
	}
	j.discerner = d
	j.joinerID = generateJoinerIDFromDiscerner(d)
	return nil
}

// ClearDiscerner clears the Joiner Discerner and recomputes the Joiner ID
// from the factory EUI-64. Only allowed in Idle state.
func (j *JoinerClient) ClearDiscerner() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.state != JoinerStateIdle {
		return errors.ErrInvalidState
	}
	j.discerner = JoinerDiscerner{}
	j.joinerID = ComputeJoinerIDFromEUI64(j.radio.GetIeeeEUI64())
	return nil
}

// GetDiscerner returns the current discerner, or nil if none is set.
func (j *JoinerClient) GetDiscerner() *JoinerDiscerner {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.discerner.BitLength == 0 {
		return nil
	}
	d := j.discerner
	return &d
}

// Start begins the commissioning process.
//
// Parameters:
//   - pskd: Pre-Shared Key for the Device (6-32 chars, base32-thread)
//   - provisioningURL: optional provisioning URL (may be empty)
//   - vendorName: required vendor name
//   - vendorModel: required vendor model
//   - vendorSWVersion: required vendor software version
//   - vendorData: optional vendor data (may be empty)
//   - stackVersion: Thread stack version info
//   - cb: completion callback invoked on success or failure
func (j *JoinerClient) Start(
	pskd string,
	provisioningURL string,
	vendorName string,
	vendorModel string,
	vendorSWVersion string,
	vendorData string,
	stackVersion VendorStackVersion,
	cb JoinerCompletionCallback,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state != JoinerStateIdle {
		return errors.ErrInvalidState
	}

	// Validate PSKd.
	if err := ValidateJoinerPSKd(pskd); err != nil {
		return err
	}
	// Validate string lengths.
	if len(provisioningURL) > MaxProvisioningURLLength {
		return errors.ErrInvalidArgs
	}
	if len(vendorName) > MaxVendorNameLength || vendorName == "" {
		return errors.ErrInvalidArgs
	}
	if len(vendorModel) > MaxVendorModelLength || vendorModel == "" {
		return errors.ErrInvalidArgs
	}
	if len(vendorSWVersion) > MaxVendorSWVersionLength || vendorSWVersion == "" {
		return errors.ErrInvalidArgs
	}
	if len(vendorData) > MaxVendorDataLength {
		return errors.ErrInvalidArgs
	}

	j.pskd = pskd
	j.provisioningURL = provisioningURL
	j.vendorName = vendorName
	j.vendorModel = vendorModel
	j.vendorSWVersion = vendorSWVersion
	j.vendorData = vendorData
	j.stackVersion = stackVersion
	j.completionCB = cb

	// Refresh Joiner ID from EUI-64 if no discerner.
	if j.discerner.BitLength == 0 {
		j.joinerID = ComputeJoinerIDFromEUI64(j.radio.GetIeeeEUI64())
	}

	// Pre-build JOINER_FINALIZE payload.
	j.finalizePayload = j.buildFinalizePayload()

	// Clear candidates.
	j.candidates = [MaxJoinerCandidates]JoinerCandidate{}
	j.candidateIdx = 0
	j.firstConnErr = nil
	j.hasConnected = false

	// Transition to Discover.
	j.state = JoinerStateDiscover

	// Start MLE Discovery scan.
	err := j.scanner.StartScan(j.handleScanResult)
	if err != nil {
		j.state = JoinerStateIdle
		j.finalizePayload = nil
		return err
	}

	return nil
}

// Stop aborts the join process. The completion callback is NOT invoked.
func (j *JoinerClient) Stop() error {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state == JoinerStateIdle {
		return errors.ErrInvalidState
	}

	// Clear callback so Finish doesn't invoke it.
	j.completionCB = nil
	j.finishLocked(errors.ErrAbort)
	return nil
}

// ---------------------------------------------------------------------------
// Scan handling
// ---------------------------------------------------------------------------

func (j *JoinerClient) handleScanResult(result *JoinerScanResult) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state != JoinerStateDiscover {
		return
	}

	if result == nil {
		// Scan complete.
		j.handleScanCompletedLocked()
		return
	}

	// Validate.
	if result.JoinerUDPPort == 0 || !result.SteeringData.IsValid() {
		return
	}

	// Evaluate the scan result against our Joiner ID / Discerner.
	verdict := j.evaluateScanResult(result)
	if verdict == ScanVerdictIgnore {
		return
	}

	// Compute priority. RSSI isn't available in our abstraction, so use
	// a fixed base. Preferred results get 200, normal get 100.
	var priority uint8
	if verdict == ScanVerdictAcceptPreferred {
		priority = 200
	} else {
		priority = 100
	}

	j.saveCandidate(result, priority)
}

func (j *JoinerClient) evaluateScanResult(result *JoinerScanResult) ScanVerdict {
	sd := &result.SteeringData

	// Check if the steering data permits all joiners.
	if sd.PermitsAllJoiners() {
		return ScanVerdictAccept
	}

	// Check if our specific ID or discerner is in the steering data.
	if j.discerner.BitLength > 0 {
		if sd.ContainsDiscerner(j.discerner.Value, j.discerner.BitLength) {
			return ScanVerdictAcceptPreferred
		}
	} else {
		if sd.Contains(j.joinerID) {
			return ScanVerdictAcceptPreferred
		}
	}

	return ScanVerdictIgnore
}

func (j *JoinerClient) saveCandidate(result *JoinerScanResult, priority uint8) {
	// Find the lowest-priority slot to replace (or an empty slot).
	minIdx := -1
	minPri := priority

	for i := 0; i < MaxJoinerCandidates; i++ {
		if j.candidates[i].Priority == 0 {
			// Empty slot.
			minIdx = i
			break
		}
		if j.candidates[i].Priority < minPri {
			minPri = j.candidates[i].Priority
			minIdx = i
		}
	}

	if minIdx < 0 {
		// All candidates have higher priority; skip.
		return
	}

	j.candidates[minIdx] = JoinerCandidate{
		ExtAddress:    result.ExtAddress,
		PanID:         result.PanID,
		JoinerUDPPort: result.JoinerUDPPort,
		Channel:       result.Channel,
		Priority:      priority,
	}
}

func (j *JoinerClient) handleScanCompletedLocked() {
	if j.state != JoinerStateDiscover {
		return
	}

	// Sort candidates by priority (highest first) using simple insertion sort.
	j.sortCandidates()

	// Set candidate iteration index.
	j.candidateIdx = 0

	// Try connecting to the first candidate.
	j.tryNextCandidateLocked(nil)
}

func (j *JoinerClient) sortCandidates() {
	n := MaxJoinerCandidates
	for i := 1; i < n; i++ {
		key := j.candidates[i]
		k := i - 1
		for k >= 0 && j.candidates[k].Priority < key.Priority {
			j.candidates[k+1] = j.candidates[k]
			k--
		}
		j.candidates[k+1] = key
	}
}

// ---------------------------------------------------------------------------
// Connection management
// ---------------------------------------------------------------------------

func (j *JoinerClient) tryNextCandidateLocked(prevErr error) {
	// Track the first error from a successful connect attempt.
	if prevErr != nil && j.hasConnected {
		if j.firstConnErr == nil {
			j.firstConnErr = prevErr
		}
	}

	for j.candidateIdx < MaxJoinerCandidates {
		c := &j.candidates[j.candidateIdx]
		j.candidateIdx++

		if c.Priority == 0 {
			// No more candidates.
			break
		}

		err := j.connectToCandidateLocked(c)
		if err == nil {
			// Connection attempt started.
			return
		}
		// This candidate failed immediately; try next.
	}

	// No more candidates. Report the best error we have.
	finalErr := j.firstConnErr
	if finalErr == nil {
		finalErr = errors.ErrNotFound
	}
	j.finishLocked(finalErr)
}

func (j *JoinerClient) connectToCandidateLocked(c *JoinerCandidate) error {
	// Configure radio.
	j.radio.SetChannel(c.Channel)
	j.radio.SetPanID(c.PanID)

	// Build link-local IPv6 address from the Joiner Router's Extended Address.
	addr := linkLocalFromExtAddr(c.ExtAddress)

	j.state = JoinerStateConnect

	err := j.transport.Connect(addr, c.JoinerUDPPort, j.pskd, j.handleDTLSConnect)
	if err != nil {
		j.state = JoinerStateDiscover // Revert state on immediate failure.
		return err
	}

	j.hasConnected = true
	return nil
}

func (j *JoinerClient) handleDTLSConnect(connected bool) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state != JoinerStateConnect {
		return
	}

	if !connected {
		// DTLS handshake failed; try next candidate.
		j.tryNextCandidateLocked(errors.ErrSecurity)
		return
	}

	// DTLS handshake succeeded.
	j.state = JoinerStateConnected

	// Set up receive handler for JOINER_FINALIZE response.
	j.transport.SetReceiveHandler(j.handleSecureReceive)

	// Send JOINER_FINALIZE.
	j.sendJoinerFinalize()

	// Start response timeout.
	j.afterFunc(joinerFinalizeTimeout, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.state == JoinerStateConnected {
			j.finishLocked(errors.ErrResponseTimeout)
		}
	})
}

// ---------------------------------------------------------------------------
// JOINER_FINALIZE
// ---------------------------------------------------------------------------

func (j *JoinerClient) buildFinalizePayload() []byte {
	var payload []byte

	// State TLV: Accept
	payload = append(payload, encodeTLV(TLVState, []byte{StateAccept})...)

	// Vendor Name TLV
	payload = append(payload, encodeTLV(TLVVendorName, []byte(j.vendorName))...)

	// Vendor Model TLV
	payload = append(payload, encodeTLV(TLVVendorModel, []byte(j.vendorModel))...)

	// Vendor SW Version TLV
	payload = append(payload, encodeTLV(TLVVendorSWVersion, []byte(j.vendorSWVersion))...)

	// Vendor Stack Version TLV
	payload = append(payload, encodeTLV(TLVVendorStackVersion, j.stackVersion.Encode())...)

	// Vendor Data TLV (optional)
	if j.vendorData != "" {
		payload = append(payload, encodeTLV(TLVVendorData, []byte(j.vendorData))...)
	}

	// Provisioning URL TLV (optional)
	if j.provisioningURL != "" {
		payload = append(payload, encodeTLV(TLVProvisioningURL, []byte(j.provisioningURL))...)
	}

	return payload
}

func (j *JoinerClient) sendJoinerFinalize() {
	msg := buildCONPost(joinerFinalizeURI, j.finalizePayload)
	_ = j.transport.Send(msg.GetBytes())
}

// ---------------------------------------------------------------------------
// JOINER_FINALIZE response handling
// ---------------------------------------------------------------------------

func (j *JoinerClient) handleSecureReceive(data []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state != JoinerStateConnected {
		return
	}

	msg, err := coap.ParseMessage(data)
	if err != nil {
		return
	}

	// Expect an ACK with code 2.04 Changed.
	if msg.GetType() != coap.TypeAck || msg.GetCode() != coap.CodeChanged {
		return
	}

	// Parse State TLV from response payload.
	payload := msg.GetPayload()
	stateBytes := findTLVInBytes(payload, TLVState)
	if len(stateBytes) < 1 {
		j.finishLocked(errors.ErrParse)
		return
	}

	state := stateBytes[0]
	if state != StateAccept {
		j.finishLocked(errors.ErrRejected)
		return
	}

	// Transition to Entrust: disconnect DTLS and wait for JOINER_ENTRUST.
	j.state = JoinerStateEntrust

	// Disconnect the DTLS session.
	j.transport.Disconnect()

	// Register handler for JOINER_ENTRUST on the unsecured CoAP channel.
	j.transport.RegisterHandler(joinerEntrustURI, j.handleJoinerEntrust)

	// Start entrust timeout.
	j.afterFunc(joinerEntrustTimeout, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.state == JoinerStateEntrust {
			j.finishLocked(errors.ErrResponseTimeout)
		}
	})
}

// ---------------------------------------------------------------------------
// JOINER_ENTRUST handling
// ---------------------------------------------------------------------------

func (j *JoinerClient) handleJoinerEntrust(msg *coap.Message, info coap.MessageInfo) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if j.state != JoinerStateEntrust {
		return
	}

	// Must be a Confirmable POST.
	if msg.GetType() != coap.TypeConfirmable || msg.GetCode() != coap.CodePost {
		return
	}

	payload := msg.GetPayload()

	// Parse Network Key TLV (required).
	networkKeyBytes := findTLVInBytes(payload, TLVNetworkKey)
	if len(networkKeyBytes) != 16 {
		return
	}

	// Build dataset info with received credentials.
	var dsInfo Info
	copy(dsInfo.NetworkKey[:], networkKeyBytes)
	dsInfo.Components.NetworkKey = true

	// Channel and PAN ID come from the radio (set during connection setup).
	dsInfo.Channel = uint16(j.radio.GetChannel())
	dsInfo.Components.Channel = true

	dsInfo.PanID = j.radio.GetPanID()
	dsInfo.Components.PanID = true

	// Parse optional TLVs from the entrust message.
	j.parseEntrustOptionalTLVs(payload, &dsInfo)

	// Save the dataset.
	_ = j.datasetSaver.SaveDataset(dsInfo)

	// Send CoAP ACK response.
	j.transport.SendResponse(coap.CodeChanged, msg, info)

	// Transition to Joined.
	j.state = JoinerStateJoined

	// Start the post-join delay before signaling completion.
	j.afterFunc(joinerPostJoinDelay, func() {
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.state == JoinerStateJoined {
			j.finishLocked(nil)
		}
	})
}

// parseEntrustOptionalTLVs extracts optional dataset TLVs from the
// JOINER_ENTRUST payload.
func (j *JoinerClient) parseEntrustOptionalTLVs(payload []byte, info *Info) {
	// Network Name
	if v := findTLVInBytes(payload, TLVNetworkName); v != nil {
		info.NetworkName = string(v)
		info.Components.NetworkName = true
	}

	// Extended PAN ID
	if v := findTLVInBytes(payload, TLVExtendedPanID); len(v) == 8 {
		copy(info.ExtendedPanID[:], v)
		info.Components.ExtendedPanID = true
	}

	// Mesh-Local Prefix
	if v := findTLVInBytes(payload, TLVMeshLocalPrefix); len(v) == 8 {
		copy(info.MeshLocalPrefix[:], v)
		info.Components.MeshLocalPrefix = true
	}

	// Active Timestamp
	if v := findTLVInBytes(payload, TLVActiveTimestamp); len(v) == TimestampSize {
		var ts Timestamp
		if err := ts.UnmarshalBinary(v); err == nil {
			info.ActiveTimestamp = ts
			info.Components.ActiveTimestamp = true
		}
	}

	// PSKc
	if v := findTLVInBytes(payload, TLVPSKc); len(v) == 16 {
		copy(info.PSKc[:], v)
		info.Components.PSKc = true
	}

	// Channel Mask
	if v := findTLVInBytes(payload, TLVChannelMask); len(v) == 4 {
		info.ChannelMask = binary.BigEndian.Uint32(v)
		info.Components.ChannelMask = true
	}

	// Security Policy (rotation time 2 bytes + flags, handled by ParseFlags)
	if v := findTLVInBytes(payload, TLVSecurityPolicy); len(v) >= 3 {
		info.SecurityPolicy.RotationTime = binary.BigEndian.Uint16(v[0:2])
		info.SecurityPolicy.SetFlags(v[2:])
		info.Components.SecurityPolicy = true
	}
}

// ---------------------------------------------------------------------------
// Finish (cleanup and callback)
// ---------------------------------------------------------------------------

func (j *JoinerClient) finishLocked(err error) {
	if j.state == JoinerStateIdle {
		return
	}

	switch j.state {
	case JoinerStateConnect, JoinerStateConnected, JoinerStateEntrust, JoinerStateJoined:
		j.transport.Disconnect()
		fallthrough
	case JoinerStateDiscover:
		j.transport.UnregisterHandler(joinerEntrustURI)
		j.scanner.StopScan()
	}

	j.state = JoinerStateIdle
	j.finalizePayload = nil

	cb := j.completionCB
	j.completionCB = nil

	if cb != nil {
		cb(err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// linkLocalFromExtAddr builds a link-local IPv6 address from an Extended
// Address using the Modified EUI-64 method (RFC 4291 Appendix A).
func linkLocalFromExtAddr(ext types.ExtAddress) [16]byte {
	var addr [16]byte
	addr[0] = 0xfe
	addr[1] = 0x80
	// bytes 2-7 are zero
	// Interface identifier from Modified EUI-64
	addr[8] = ext[0] ^ 0x02 // Toggle U/L bit
	addr[9] = ext[1]
	addr[10] = ext[2]
	addr[11] = ext[3]
	addr[12] = ext[4]
	addr[13] = ext[5]
	addr[14] = ext[6]
	addr[15] = ext[7]
	return addr
}

// generateJoinerIDFromDiscerner generates a Joiner ID from a discerner.
// The discerner value is placed in the lowest BitLength bits of the 8-byte
// Joiner ID, and the Local bit is set.
func generateJoinerIDFromDiscerner(d JoinerDiscerner) [8]byte {
	var id [8]byte
	// Place discerner value in the lowest bits (big-endian, from the end).
	val := d.Value
	for i := 7; i >= 0; i-- {
		id[i] = byte(val & 0xFF)
		val >>= 8
	}
	id[0] |= 0x02 // Set Local bit
	return id
}

// GetCandidates returns a copy of the current candidates (for testing).
func (j *JoinerClient) GetCandidates() []JoinerCandidate {
	j.mu.Lock()
	defer j.mu.Unlock()
	var result []JoinerCandidate
	for _, c := range j.candidates {
		if c.Priority > 0 {
			result = append(result, c)
		}
	}
	return result
}
