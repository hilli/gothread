// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dns

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
	"time"

	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const (
	// DefaultResponseTimeout is the default time (ms) to wait for a DNS
	// response before retransmitting or failing.
	DefaultResponseTimeout = 6000

	// DefaultServerPort is the default DNS server port.
	DefaultServerPort = 53

	// DefaultMaxTxAttempts is the default maximum number of query
	// transmit attempts before reporting failure.
	DefaultMaxTxAttempts = 3

	// UDPQueryMaxSize is the maximum DNS message size for UDP transport.
	UDPQueryMaxSize = 512

	// maxCnameAliasChanges limits CNAME chain following to prevent loops.
	maxCnameAliasChanges = 40
)

// ---------------------------------------------------------------------------
// RecursionFlag
// ---------------------------------------------------------------------------

// RecursionFlag represents the "Recursion Desired" (RD) flag in a query.
type RecursionFlag uint8

const (
	// RecursionUnspecified means the flag is not specified; use default.
	RecursionUnspecified RecursionFlag = 0
	// RecursionDesired means the server can resolve the query recursively.
	RecursionDesired RecursionFlag = 1
	// NoRecursion means the server should not resolve recursively.
	NoRecursion RecursionFlag = 2
)

// ---------------------------------------------------------------------------
// ServiceMode
// ---------------------------------------------------------------------------

// ServiceMode represents the service resolution mode for DNS-SD queries.
type ServiceMode uint8

const (
	// ServiceModeUnspecified means use the default mode.
	ServiceModeUnspecified ServiceMode = 0
	// ServiceModeSrv requests only the SRV record.
	ServiceModeSrv ServiceMode = 1
	// ServiceModeTxt requests only the TXT record.
	ServiceModeTxt ServiceMode = 2
	// ServiceModeSrvTxt requests SRV and TXT in the same message.
	ServiceModeSrvTxt ServiceMode = 3
	// ServiceModeSrvTxtSeparate sends SRV and TXT in separate messages.
	ServiceModeSrvTxtSeparate ServiceMode = 4
	// ServiceModeSrvTxtOptimize tries same message first, falls back to separate.
	ServiceModeSrvTxtOptimize ServiceMode = 5
)

// ---------------------------------------------------------------------------
// QueryConfig
// ---------------------------------------------------------------------------

// QueryConfig holds DNS query parameters: server address, timeout, etc.
// Zero-valued fields are treated as "unspecified" and filled from defaults.
type QueryConfig struct {
	ServerAddr      ip6.Address
	ServerPort      uint16
	ResponseTimeout uint32 // milliseconds
	MaxTxAttempts   uint8
	RecursionFlag   RecursionFlag
	ServiceMode     ServiceMode
}

// SetFrom fills any unspecified (zero-valued) fields from defaults.
// If override is nil, the entire defaults config is used.
func (c *QueryConfig) SetFrom(override *QueryConfig, defaults QueryConfig) {
	if override == nil {
		*c = defaults
		return
	}
	*c = *override

	if c.ServerAddr == (ip6.Address{}) {
		c.ServerAddr = defaults.ServerAddr
	}
	if c.ServerPort == 0 {
		c.ServerPort = defaults.ServerPort
	}
	if c.ResponseTimeout == 0 {
		c.ResponseTimeout = defaults.ResponseTimeout
	}
	if c.MaxTxAttempts == 0 {
		c.MaxTxAttempts = defaults.MaxTxAttempts
	}
	if c.RecursionFlag == RecursionUnspecified {
		c.RecursionFlag = defaults.RecursionFlag
	}
	if c.ServiceMode == ServiceModeUnspecified {
		c.ServiceMode = defaults.ServiceMode
	}
}

// DefaultQueryConfig returns a QueryConfig populated with all default values.
func DefaultQueryConfig() QueryConfig {
	return QueryConfig{
		ServerPort:      DefaultServerPort,
		ResponseTimeout: DefaultResponseTimeout,
		MaxTxAttempts:   DefaultMaxTxAttempts,
		RecursionFlag:   RecursionDesired,
		ServiceMode:     ServiceModeSrvTxtOptimize,
	}
}

// ---------------------------------------------------------------------------
// QueryType
// ---------------------------------------------------------------------------

// QueryType identifies the kind of DNS query.
type QueryType uint8

const (
	// QueryTypeAddress resolves a hostname to IPv6 address(es) (AAAA).
	QueryTypeAddress QueryType = iota
	// QueryTypeBrowse enumerates service instances (PTR).
	QueryTypeBrowse
	// QueryTypeServiceSrvTxt resolves SRV+TXT in one message.
	QueryTypeServiceSrvTxt
	// QueryTypeServiceSrv resolves SRV only.
	QueryTypeServiceSrv
	// QueryTypeServiceTxt resolves TXT only.
	QueryTypeServiceTxt
)

// ---------------------------------------------------------------------------
// Timer abstraction (for testing)
// ---------------------------------------------------------------------------

// Timer represents a pending timer that can be stopped.
type Timer interface {
	Stop() bool
}

// AfterFunc is a function that schedules f to run after d.
// It returns a Timer that can be used to cancel the call.
type AfterFunc func(d time.Duration, f func()) Timer

// ---------------------------------------------------------------------------
// UDPSender
// ---------------------------------------------------------------------------

// UDPSender sends a UDP datagram to the given IPv6 address and port.
type UDPSender func(data []byte, peerAddr ip6.Address, peerPort uint16) error

// ---------------------------------------------------------------------------
// Callbacks
// ---------------------------------------------------------------------------

// AddressCallback is called when an address resolution query completes.
type AddressCallback func(err error, resp *AddressResponse)

// BrowseCallback is called when a browse (service enumeration) query completes.
type BrowseCallback func(err error, resp *BrowseResponse)

// ServiceCallback is called when a service resolution query completes.
type ServiceCallback func(err error, resp *ServiceResponse)

// ---------------------------------------------------------------------------
// ServiceInfo
// ---------------------------------------------------------------------------

// ServiceInfo holds information about a discovered DNS-SD service instance.
type ServiceInfo struct {
	HostName    string
	HostAddress ip6.Address
	Port        uint16
	Priority    uint16
	Weight      uint16
	TTL         uint32 // SRV record TTL
	HostAddrTTL uint32 // AAAA record TTL
	TxtData     []byte
	TxtDataTTL  uint32
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

// Response is a parsed DNS response message. It stores the raw bytes and
// section offsets for efficient record lookup.
type Response struct {
	data                  []byte // full DNS message
	queryName             string // name that was queried
	header                Header
	answerOffset          int
	answerRecordCount     int
	authorityOffset       int
	authorityRecordCount  int
	additionalOffset      int
	additionalRecordCount int
}

// section selects answer or additional data section.
type section uint8

const (
	sectionAnswer     section = 0
	sectionAdditional section = 1
)

// GetName returns the query name associated with this response.
func (r *Response) GetName() string {
	return r.queryName
}

// GetHeader returns the parsed DNS header.
func (r *Response) GetHeader() Header {
	return r.header
}

// populateFrom parses the raw DNS message and fills section offsets.
func (r *Response) populateFrom(data []byte) error {
	if len(data) < HeaderSize {
		return errors.ErrParse
	}

	if err := r.header.UnmarshalBinary(data); err != nil {
		return err
	}

	offset := HeaderSize

	// Skip questions.
	for i := 0; i < int(r.header.QDCount); i++ {
		var err error
		offset, err = SkipName(data, offset)
		if err != nil {
			return err
		}
		offset += QuestionSize
		if offset > len(data) {
			return errors.ErrParse
		}
	}

	r.answerOffset = offset
	r.answerRecordCount = int(r.header.ANCount)

	var err error
	offset, err = ParseRecords(data, offset, r.answerRecordCount)
	if err != nil {
		return err
	}

	r.authorityOffset = offset
	r.authorityRecordCount = int(r.header.NSCount)

	offset, err = ParseRecords(data, offset, r.authorityRecordCount)
	if err != nil {
		return err
	}

	r.additionalOffset = offset
	r.additionalRecordCount = int(r.header.ARCount)

	_, err = ParseRecords(data, offset, r.additionalRecordCount)
	if err != nil {
		return err
	}

	return nil
}

// selectSection returns the offset and record count for the given section.
func (r *Response) selectSection(s section) (offset, numRecords int) {
	switch s {
	case sectionAnswer:
		return r.answerOffset, r.answerRecordCount
	default:
		return r.additionalOffset, r.additionalRecordCount
	}
}

// findRecord searches for a resource record of the given type matching the
// given name in the specified section. aIndex selects the nth match (0-based).
// Returns the offset to the RDATA (past the RR header) and the parsed RR header.
func (r *Response) findRecord(s section, name string, rrType RRType, aIndex int) (rr ResourceRecord, rdataOffset int, err error) {
	offset, numRecords := r.selectSection(s)
	matchCount := 0

	for i := 0; i < numRecords; i++ {
		// Compare name.
		match, nameEnd, cmpErr := CompareName(r.data, offset, name)
		if cmpErr != nil {
			return ResourceRecord{}, 0, cmpErr
		}
		offset = nameEnd

		// Read RR header.
		if err := rr.UnmarshalBinary(r.data[offset:]); err != nil {
			return ResourceRecord{}, 0, err
		}

		rrHeaderEnd := offset + ResourceRecordSize
		rrEnd := rrHeaderEnd + int(rr.RDLength)
		if rrEnd > len(r.data) {
			return ResourceRecord{}, 0, errors.ErrParse
		}

		if match && rr.Type == rrType && rr.Class == ClassInternet {
			if matchCount == aIndex {
				return rr, rrHeaderEnd, nil
			}
			matchCount++
		}

		offset = rrEnd
	}

	return ResourceRecord{}, 0, errors.ErrNotFound
}

// checkForHostNameAlias follows CNAME chains in the given section.
// Returns the final hostname after resolving aliases.
func (r *Response) checkForHostNameAlias(s section, hostName string) (string, error) {
	name := hostName
	for i := 0; i < maxCnameAliasChanges; i++ {
		rr, rdataOffset, err := r.findRecord(s, name, RRTypeCname, 0)
		if err == errors.ErrNotFound {
			return name, nil
		}
		if err != nil {
			return "", err
		}

		// Read the canonical name from RDATA.
		var cname CnameRecord
		cname.ResourceRecord = rr
		canonName, _, readErr := cname.ReadCanonicalName(r.data, rdataOffset)
		if readErr != nil {
			return "", readErr
		}
		name = canonName
	}
	return "", errors.ErrParse
}

// findHostAddress looks up an AAAA record for hostName in the given section,
// following CNAME aliases. aIndex selects the nth address (0-based).
func (r *Response) findHostAddress(s section, hostName string, aIndex int) (ip6.Address, uint32, error) {
	name, err := r.checkForHostNameAlias(s, hostName)
	if err != nil {
		return ip6.Address{}, 0, err
	}

	rr, rdataOffset, err := r.findRecord(s, name, RRTypeAaaa, aIndex)
	if err != nil {
		return ip6.Address{}, 0, err
	}

	if int(rr.RDLength) < AaaaRecordRDataSize || rdataOffset+AaaaRecordRDataSize > len(r.data) {
		return ip6.Address{}, 0, errors.ErrParse
	}

	var addr ip6.Address
	copy(addr[:], r.data[rdataOffset:rdataOffset+AaaaRecordRDataSize])
	return addr, rr.TTL, nil
}

// readServiceInfo reads the SRV record matching name from the given section
// and fills a ServiceInfo. It also looks up the host AAAA in additional.
func (r *Response) readServiceInfo(s section, name string, info *ServiceInfo) error {
	// Already found SRV if TTL is non-zero.
	if info.TTL != 0 {
		return nil
	}

	rr, rdataOffset, err := r.findRecord(s, name, RRTypeSrv, 0)
	if err != nil {
		return err
	}

	if int(rr.RDLength) < SrvRecordFixedSize {
		return errors.ErrParse
	}

	// Parse SRV fixed fields from RDATA.
	info.Priority = binary.BigEndian.Uint16(r.data[rdataOffset:])
	info.Weight = binary.BigEndian.Uint16(r.data[rdataOffset+2:])
	info.Port = binary.BigEndian.Uint16(r.data[rdataOffset+4:])
	info.TTL = rr.TTL

	// Read target host name.
	hostName, _, readErr := ReadName(r.data, rdataOffset+SrvRecordFixedSize)
	if readErr != nil {
		return readErr
	}
	info.HostName = hostName

	// Look up AAAA for the host in additional section.
	if info.HostAddress == (ip6.Address{}) {
		addr, ttl, addrErr := r.findHostAddress(sectionAdditional, hostName, 0)
		if addrErr == nil {
			info.HostAddress = addr
			info.HostAddrTTL = ttl
		}
		// Not finding an address is not an error.
	}

	return nil
}

// readTxtRecord reads the TXT record matching name from the given section
// and fills TxtData/TxtDataTTL in info.
func (r *Response) readTxtRecord(s section, name string, info *ServiceInfo) error {
	if info.TxtDataTTL != 0 {
		return nil
	}

	rr, rdataOffset, err := r.findRecord(s, name, RRTypeTxt, 0)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil // TXT not found is not an error.
		}
		return err
	}

	rdLen := int(rr.RDLength)
	if rdataOffset+rdLen > len(r.data) {
		return errors.ErrParse
	}

	info.TxtData = make([]byte, rdLen)
	copy(info.TxtData, r.data[rdataOffset:rdataOffset+rdLen])
	info.TxtDataTTL = rr.TTL
	return nil
}

// ---------------------------------------------------------------------------
// AddressResponse
// ---------------------------------------------------------------------------

// AddressResponse is the response to an address resolution query.
type AddressResponse struct {
	Response
}

// GetHostName returns the queried hostname.
func (r *AddressResponse) GetHostName() string {
	return r.GetName()
}

// GetAddress returns the nth IPv6 address from the answer section.
// Returns ErrNotFound when there are no more addresses.
func (r *AddressResponse) GetAddress(index int) (ip6.Address, uint32, error) {
	return r.findHostAddress(sectionAnswer, r.queryName, index)
}

// ---------------------------------------------------------------------------
// BrowseResponse
// ---------------------------------------------------------------------------

// BrowseResponse is the response to a browse (service enumeration) query.
type BrowseResponse struct {
	Response
}

// GetServiceName returns the queried service name.
func (r *BrowseResponse) GetServiceName() string {
	return r.GetName()
}

// GetServiceInstance returns the nth service instance label from PTR records
// in the answer section. Returns ErrNotFound when no more instances.
func (r *BrowseResponse) GetServiceInstance(index int) (string, error) {
	rr, rdataOffset, err := r.findRecord(sectionAnswer, r.queryName, RRTypePtr, index)
	if err != nil {
		return "", err
	}

	var ptr PtrRecord
	ptr.ResourceRecord = rr
	name, _, readErr := ptr.ReadPtrName(r.data, rdataOffset)
	if readErr != nil {
		return "", readErr
	}

	// Extract the instance label (first label of the PTR target).
	label, err := ExtractLabels(name, r.queryName)
	if err != nil {
		return "", err
	}
	return label, nil
}

// GetServiceInfo looks up SRV+TXT+AAAA in the additional section for
// the given instance label.
func (r *BrowseResponse) GetServiceInfo(instanceLabel string) (*ServiceInfo, error) {
	// Build full instance name: <label>.<serviceName>
	instanceName := instanceLabel + "." + r.queryName

	info := &ServiceInfo{}
	if err := r.readServiceInfo(sectionAdditional, instanceName, info); err != nil {
		return nil, err
	}
	if err := r.readTxtRecord(sectionAdditional, instanceName, info); err != nil {
		return nil, err
	}
	if info.TxtDataTTL == 0 {
		info.TxtData = nil
	}
	return info, nil
}

// GetHostAddress looks up the nth AAAA record for hostName in additional.
func (r *BrowseResponse) GetHostAddress(hostName string, index int) (ip6.Address, uint32, error) {
	return r.findHostAddress(sectionAdditional, hostName, index)
}

// ---------------------------------------------------------------------------
// ServiceResponse
// ---------------------------------------------------------------------------

// ServiceResponse is the response to a service instance resolution query.
type ServiceResponse struct {
	Response
}

// GetServiceInfo reads SRV+TXT+AAAA from the answer and additional sections.
func (r *ServiceResponse) GetServiceInfo() (*ServiceInfo, error) {
	info := &ServiceInfo{}

	if err := r.readServiceInfo(sectionAnswer, r.queryName, info); err != nil {
		return nil, err
	}
	if err := r.readTxtRecord(sectionAnswer, r.queryName, info); err != nil {
		return nil, err
	}
	if info.TxtDataTTL == 0 {
		info.TxtData = nil
	}
	return info, nil
}

// GetHostAddress looks up the nth AAAA record for hostName in additional.
func (r *ServiceResponse) GetHostAddress(hostName string, index int) (ip6.Address, uint32, error) {
	return r.findHostAddress(sectionAdditional, hostName, index)
}

// ---------------------------------------------------------------------------
// query (internal)
// ---------------------------------------------------------------------------

// query represents an in-flight DNS query.
type query struct {
	queryType       QueryType
	config          QueryConfig
	messageID       uint16
	name            string // encoded query name (dotted string)
	txCount         uint8
	retransmitTime  time.Time
	addressCallback AddressCallback
	browseCallback  BrowseCallback
	serviceCallback ServiceCallback
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client is a DNS client that sends queries over UDP and processes responses.
type Client struct {
	mu            sync.Mutex
	sender        UDPSender
	afterFunc     AfterFunc
	defaultConfig QueryConfig
	queries       []*query
	timer         Timer
	started       bool
}

// ClientOption is a functional option for NewClient.
type ClientOption func(*Client)

// WithAfterFunc sets a custom timer function (for testing).
func WithAfterFunc(af AfterFunc) ClientOption {
	return func(c *Client) {
		c.afterFunc = af
	}
}

// WithDefaultConfig sets the default query configuration.
func WithDefaultConfig(cfg QueryConfig) ClientOption {
	return func(c *Client) {
		c.defaultConfig = cfg
	}
}

// NewClient creates a new DNS client with the given UDP sender and options.
func NewClient(sender UDPSender, opts ...ClientOption) *Client {
	c := &Client{
		sender:        sender,
		defaultConfig: DefaultQueryConfig(),
		afterFunc:     defaultAfterFunc,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func defaultAfterFunc(d time.Duration, f func()) Timer {
	t := time.AfterFunc(d, f)
	return t
}

// GetDefaultConfig returns the current default query configuration.
func (c *Client) GetDefaultConfig() QueryConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.defaultConfig
}

// SetDefaultConfig updates the default query configuration.
func (c *Client) SetDefaultConfig(cfg QueryConfig) {
	c.mu.Lock()
	defer c.mu.Unlock()
	base := DefaultQueryConfig()
	c.defaultConfig.SetFrom(&cfg, base)
}

// Start prepares the client for use.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.started = true
	return nil
}

// Stop cancels all pending queries (calling callbacks with ErrAbort) and
// stops the client.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stopLocked()
}

func (c *Client) stopLocked() {
	for len(c.queries) > 0 {
		c.finalizeQueryLocked(c.queries[0], errors.ErrAbort)
	}
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	c.started = false
}

// ResolveAddress sends an AAAA query for hostname and calls callback with
// the result.
func (c *Client) ResolveAddress(hostname string, callback AddressCallback, config *QueryConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return errors.ErrInvalidState
	}

	q := &query{
		queryType:       QueryTypeAddress,
		addressCallback: callback,
		name:            hostname,
	}
	q.config.SetFrom(config, c.defaultConfig)

	return c.startQueryLocked(q)
}

// Browse sends a PTR query for serviceName and calls callback with the result.
func (c *Client) Browse(serviceName string, callback BrowseCallback, config *QueryConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return errors.ErrInvalidState
	}

	q := &query{
		queryType:      QueryTypeBrowse,
		browseCallback: callback,
		name:           serviceName,
	}
	q.config.SetFrom(config, c.defaultConfig)

	return c.startQueryLocked(q)
}

// ResolveService sends an SRV+TXT query for the given service instance and
// calls callback with the result.
func (c *Client) ResolveService(instanceLabel, serviceName string, callback ServiceCallback, config *QueryConfig) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.started {
		return errors.ErrInvalidState
	}

	fullName := instanceLabel + "." + serviceName
	q := &query{
		queryType:       QueryTypeServiceSrvTxt,
		serviceCallback: callback,
		name:            fullName,
	}
	q.config.SetFrom(config, c.defaultConfig)

	return c.startQueryLocked(q)
}

// HandleUDPReceive should be called when a UDP DNS response is received.
func (c *Client) HandleUDPReceive(data []byte, peerAddr ip6.Address, peerPort uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.processResponseLocked(data)
}

// HandleTimer should be called when the retransmission timer fires.
// Normally this is called automatically by the afterFunc timer.
func (c *Client) HandleTimer() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.handleTimerLocked()
}

// ---------------------------------------------------------------------------
// Internal methods (caller holds mu)
// ---------------------------------------------------------------------------

func (c *Client) startQueryLocked(q *query) error {
	mid, err := c.generateMessageIDLocked()
	if err != nil {
		return err
	}
	q.messageID = mid

	if err := c.sendQueryLocked(q); err != nil {
		return err
	}

	c.queries = append(c.queries, q)
	c.updateTimerLocked()
	return nil
}

func (c *Client) sendQueryLocked(q *query) error {
	q.txCount++
	q.retransmitTime = time.Now().Add(time.Duration(q.config.ResponseTimeout) * time.Millisecond)

	msg, err := c.buildQueryMessage(q)
	if err != nil {
		return err
	}

	if len(msg) > UDPQueryMaxSize {
		return errors.ErrInvalidArgs
	}

	return c.sender(msg, q.config.ServerAddr, q.config.ServerPort)
}

func (c *Client) buildQueryMessage(q *query) ([]byte, error) {
	var h Header
	h.MessageID = q.messageID
	h.SetType(TypeQuery)
	h.SetOpCode(OpcodeQuery)
	if q.config.RecursionFlag == RecursionDesired {
		h.SetRecursionDesired(true)
	}

	questionCount := uint16(1)
	rrType := c.questionRecordType(q)

	h.QDCount = questionCount

	hdrBytes := h.MarshalBinary()
	buf := make([]byte, 0, UDPQueryMaxSize)
	buf = append(buf, hdrBytes[:]...)

	// Append question: encoded name + Question.
	buf, err := AppendName(buf, q.name)
	if err != nil {
		return nil, err
	}

	qn := Question{Type: rrType, Class: ClassInternet}
	qBytes := qn.MarshalBinary()
	buf = append(buf, qBytes[:]...)

	return buf, nil
}

func (c *Client) questionRecordType(q *query) RRType {
	switch q.queryType {
	case QueryTypeAddress:
		return RRTypeAaaa
	case QueryTypeBrowse:
		return RRTypePtr
	case QueryTypeServiceSrvTxt, QueryTypeServiceSrv:
		return RRTypeSrv
	case QueryTypeServiceTxt:
		return RRTypeTxt
	default:
		return RRTypeAaaa
	}
}

func (c *Client) generateMessageIDLocked() (uint16, error) {
	for attempts := 0; attempts < 100; attempts++ {
		var buf [2]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, errors.ErrFailed
		}
		mid := binary.BigEndian.Uint16(buf[:])
		if mid == 0 {
			continue
		}
		if c.findQueryByIDLocked(mid) == nil {
			return mid, nil
		}
	}
	return 0, errors.ErrFailed
}

func (c *Client) findQueryByIDLocked(id uint16) *query {
	for _, q := range c.queries {
		if q.messageID == id {
			return q
		}
	}
	return nil
}

func (c *Client) removeQueryLocked(q *query) {
	for i, existing := range c.queries {
		if existing == q {
			c.queries = append(c.queries[:i], c.queries[i+1:]...)
			return
		}
	}
}

func (c *Client) processResponseLocked(data []byte) {
	if len(data) < HeaderSize {
		return
	}

	var h Header
	if err := h.UnmarshalBinary(data); err != nil {
		return
	}

	// Must be a standard query response, not truncated.
	if h.GetType() != TypeResponse {
		return
	}
	if h.GetOpCode() != OpcodeQuery {
		return
	}
	if h.IsTruncated() {
		return
	}

	q := c.findQueryByIDLocked(h.MessageID)
	if q == nil {
		return
	}

	// Validate: parse all sections to ensure message is well-formed.
	offset := HeaderSize
	for i := 0; i < int(h.QDCount); i++ {
		var err error
		offset, err = SkipName(data, offset)
		if err != nil {
			return
		}
		offset += QuestionSize
		if offset > len(data) {
			return
		}
	}

	if _, err := ParseRecords(data, offset, int(h.ANCount)); err != nil {
		return
	}

	// Check response code.
	respErr := ResponseCodeToError(h.GetResponseCode())
	if respErr != nil {
		c.finalizeQueryLocked(q, respErr)
		return
	}

	// Build response and finalize.
	resp := &Response{
		data:      data,
		queryName: q.name,
	}
	if err := resp.populateFrom(data); err != nil {
		c.finalizeQueryLocked(q, errors.ErrParse)
		return
	}

	c.finalizeQueryWithResponseLocked(q, nil, resp)
}

func (c *Client) finalizeQueryLocked(q *query, err error) {
	c.removeQueryLocked(q)

	switch q.queryType {
	case QueryTypeAddress:
		if q.addressCallback != nil {
			q.addressCallback(err, nil)
		}
	case QueryTypeBrowse:
		if q.browseCallback != nil {
			q.browseCallback(err, nil)
		}
	case QueryTypeServiceSrvTxt, QueryTypeServiceSrv, QueryTypeServiceTxt:
		if q.serviceCallback != nil {
			q.serviceCallback(err, nil)
		}
	}

	c.updateTimerLocked()
}

func (c *Client) finalizeQueryWithResponseLocked(q *query, err error, resp *Response) {
	c.removeQueryLocked(q)

	switch q.queryType {
	case QueryTypeAddress:
		if q.addressCallback != nil {
			ar := &AddressResponse{Response: *resp}
			q.addressCallback(err, ar)
		}
	case QueryTypeBrowse:
		if q.browseCallback != nil {
			br := &BrowseResponse{Response: *resp}
			q.browseCallback(err, br)
		}
	case QueryTypeServiceSrvTxt, QueryTypeServiceSrv, QueryTypeServiceTxt:
		if q.serviceCallback != nil {
			sr := &ServiceResponse{Response: *resp}
			q.serviceCallback(err, sr)
		}
	}

	c.updateTimerLocked()
}

func (c *Client) handleTimerLocked() {
	now := time.Now()

	// Process queries. We iterate over a copy of the slice since
	// finalizeQueryLocked mutates c.queries.
	queries := make([]*query, len(c.queries))
	copy(queries, c.queries)

	for _, q := range queries {
		// Check if query is still active (may have been removed by a
		// previous finalization in this loop).
		if c.findQueryByIDLocked(q.messageID) == nil {
			continue
		}

		if now.Before(q.retransmitTime) {
			continue
		}

		if q.txCount >= q.config.MaxTxAttempts {
			c.finalizeQueryLocked(q, errors.ErrResponseTimeout)
			continue
		}

		// Retransmit.
		_ = c.sendQueryLocked(q)
	}

	c.updateTimerLocked()
}

func (c *Client) updateTimerLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}

	if len(c.queries) == 0 {
		return
	}

	earliest := c.queries[0].retransmitTime
	for _, q := range c.queries[1:] {
		if q.retransmitTime.Before(earliest) {
			earliest = q.retransmitTime
		}
	}

	delay := time.Until(earliest)
	if delay < 0 {
		delay = 0
	}

	c.timer = c.afterFunc(delay, func() {
		c.HandleTimer()
	})
}
