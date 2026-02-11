// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package dhcp6

import (
	"github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/ip6"
)

// ---------------------------------------------------------------------------
// Client transport interface
// ---------------------------------------------------------------------------

// ClientTransport abstracts the network I/O needed by the DHCPv6 client.
// In production this wraps a UDP socket; in tests a mock is used.
type ClientTransport interface {
	// Send transmits a DHCPv6 message to the given destination.
	Send(payload []byte, dst ip6.Address, dstPort uint16) error
}

// ---------------------------------------------------------------------------
// Timer interface
// ---------------------------------------------------------------------------

// Timer abstracts a retransmission timer. The client calls Start to begin
// a timer and Stop to cancel it. When the timer fires, the implementation
// calls the callback provided at creation time.
type Timer interface {
	Start()
	Stop()
	IsRunning() bool
}

// ---------------------------------------------------------------------------
// Identity Association status
// ---------------------------------------------------------------------------

// IaStatus represents the state of an Identity Association in the client.
type IaStatus uint8

const (
	// IaStatusInvalid means the IA slot is unused.
	IaStatusInvalid IaStatus = iota
	// IaStatusSolicit means the IA needs solicitation.
	IaStatusSolicit
	// IaStatusSoliciting means a Solicit has been sent and we are awaiting
	// a Reply.
	IaStatusSoliciting
	// IaStatusSolicitReplied means a valid Reply has been received.
	IaStatusSolicitReplied
)

// ---------------------------------------------------------------------------
// IdentityAssociation
// ---------------------------------------------------------------------------

// IdentityAssociation represents a single DHCPv6 identity association
// managed by the client. Each IA corresponds to one prefix for which the
// client is requesting an address.
type IdentityAssociation struct {
	// Status is the current state of this IA.
	Status IaStatus

	// Prefix is the network prefix for which an address is being requested.
	Prefix ip6.NetworkPrefix

	// PrefixLength is the length of the prefix in bits (typically 64).
	PrefixLength uint8

	// Address is the assigned IPv6 address (valid when Status == SolicitReplied).
	Address ip6.Address

	// PreferredLifetime from the server reply.
	PreferredLifetime uint32

	// ValidLifetime from the server reply.
	ValidLifetime uint32

	// AgentRloc is the RLOC16 of the DHCPv6 server (agent) for this prefix.
	AgentRloc uint16
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client implements a DHCPv6 client for Thread networks. It sends Solicit
// messages (with Rapid Commit) and processes Reply messages from the server.
type Client struct {
	// transport is the network transport for sending messages.
	transport ClientTransport

	// extAddress is the client's EUI-64 used as the DUID-LL identifier.
	extAddress types.ExtAddress

	// identityAssociations holds one IA per DHCPv6-configured prefix.
	identityAssociations []IdentityAssociation

	// transactionID is the current transaction ID for Solicit messages.
	transactionID TransactionID

	// startTime records when the current solicitation started, for computing
	// the Elapsed Time option (in hundredths of a second).
	startTimeHundredths uint16

	// timer is the retransmission timer (may be nil if not configured).
	timer Timer

	// running indicates whether the client is active.
	running bool
}

// NewClient creates a new DHCPv6 client.
func NewClient(transport ClientTransport, extAddr types.ExtAddress) *Client {
	return &Client{
		transport:  transport,
		extAddress: extAddr,
	}
}

// SetTimer sets the retransmission timer for the client. This must be
// called before Start if retransmission is desired.
func (c *Client) SetTimer(t Timer) {
	c.timer = t
}

// Start activates the client. If there are IAs in the Solicit state, it
// begins solicitation.
func (c *Client) Start() error {
	if c.running {
		return errors.ErrAlready
	}
	c.running = true
	c.processNextIdentityAssociation()
	return nil
}

// Stop deactivates the client and cancels any pending timer.
func (c *Client) Stop() {
	c.running = false
	if c.timer != nil {
		c.timer.Stop()
	}
}

// IsRunning returns true if the client is active.
func (c *Client) IsRunning() bool {
	return c.running
}

// GetIdentityAssociations returns the current identity associations.
func (c *Client) GetIdentityAssociations() []IdentityAssociation {
	return c.identityAssociations
}

// ---------------------------------------------------------------------------
// UpdateAddresses
// ---------------------------------------------------------------------------

// PrefixInfo describes a DHCPv6-managed prefix and the RLOC16 of the server
// (agent) responsible for it.
type PrefixInfo struct {
	Prefix       ip6.NetworkPrefix
	PrefixLength uint8
	AgentRloc    uint16
}

// UpdateAddresses updates the client's identity associations based on the
// current set of DHCPv6-managed prefixes. New prefixes get IAs in the
// Solicit state; removed prefixes have their IAs invalidated.
func (c *Client) UpdateAddresses(prefixes []PrefixInfo) {
	// Mark existing IAs that are no longer in the prefix list as invalid.
	for i := range c.identityAssociations {
		ia := &c.identityAssociations[i]
		if ia.Status == IaStatusInvalid {
			continue
		}
		found := false
		for _, p := range prefixes {
			if ia.Prefix == p.Prefix {
				found = true
				// Update the agent RLOC in case it changed.
				ia.AgentRloc = p.AgentRloc
				break
			}
		}
		if !found {
			ia.Status = IaStatusInvalid
		}
	}

	// Add new prefixes that don't have an IA yet.
	for _, p := range prefixes {
		found := false
		for i := range c.identityAssociations {
			if c.identityAssociations[i].Prefix == p.Prefix &&
				c.identityAssociations[i].Status != IaStatusInvalid {
				found = true
				break
			}
		}
		if !found {
			c.identityAssociations = append(c.identityAssociations, IdentityAssociation{
				Status:       IaStatusSolicit,
				Prefix:       p.Prefix,
				PrefixLength: p.PrefixLength,
				AgentRloc:    p.AgentRloc,
			})
		}
	}

	// Compact: remove trailing invalid entries.
	c.compactIAs()

	// If running, kick off solicitation for any new IAs.
	if c.running {
		c.processNextIdentityAssociation()
	}
}

// compactIAs removes invalid IAs from the end of the slice to save memory.
func (c *Client) compactIAs() {
	n := len(c.identityAssociations)
	for n > 0 && c.identityAssociations[n-1].Status == IaStatusInvalid {
		n--
	}
	c.identityAssociations = c.identityAssociations[:n]
}

// ---------------------------------------------------------------------------
// Solicitation
// ---------------------------------------------------------------------------

// processNextIdentityAssociation finds the next IA needing solicitation and
// sends a Solicit message.
func (c *Client) processNextIdentityAssociation() {
	if !c.running {
		return
	}

	for i := range c.identityAssociations {
		ia := &c.identityAssociations[i]
		if ia.Status == IaStatusSolicit {
			if err := c.solicit(ia); err == nil {
				ia.Status = IaStatusSoliciting
			}
			return
		}
	}
}

// solicit builds and sends a DHCPv6 Solicit message for the given IA.
func (c *Client) solicit(ia *IdentityAssociation) error {
	if c.transport == nil {
		return errors.ErrInvalidState
	}

	// Generate a new transaction ID.
	if err := c.transactionID.GenerateRandom(); err != nil {
		return errors.ErrFailed
	}

	// Build the Solicit message.
	msg, err := c.buildSolicit(ia)
	if err != nil {
		return err
	}

	// Build the destination address: the server's RLOC address.
	// In Thread, the RLOC is derived from the mesh-local prefix + RLOC16.
	// For now we send to the all-DHCP multicast address, as the server
	// listens there. The caller can configure routing as needed.
	dst := AllDHCPRelayAgentsAndServers

	return c.transport.Send(msg, dst, ServerPort)
}

// buildSolicit constructs a Solicit message payload.
func (c *Client) buildSolicit(ia *IdentityAssociation) ([]byte, error) {
	hdr := Header{
		Type:          MsgTypeSolicit,
		TransactionID: c.transactionID,
	}
	hdrBytes, err := hdr.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, 128)
	buf = append(buf, hdrBytes...)

	// Elapsed Time option.
	buf = AppendElapsedTimeOption(buf, c.startTimeHundredths)

	// Client ID option.
	var clientDUID Eui64DUID
	clientDUID.Init(c.extAddress)
	buf = AppendClientIDOption(buf, &clientDUID)

	// IA_NA option (IAID derived from prefix, T1=0, T2=0).
	iaNa := IaNa{
		IAID: iaidFromPrefix(ia.Prefix),
		T1:   0,
		T2:   0,
	}
	buf = AppendIaNaOption(buf, &iaNa)

	// Rapid Commit option.
	buf = AppendRapidCommitOption(buf)

	return buf, nil
}

// iaidFromPrefix derives a 32-bit IAID from a network prefix by using the
// last 4 bytes.
func iaidFromPrefix(prefix ip6.NetworkPrefix) uint32 {
	return uint32(prefix[4])<<24 | uint32(prefix[5])<<16 |
		uint32(prefix[6])<<8 | uint32(prefix[7])
}

// ---------------------------------------------------------------------------
// Receive handling
// ---------------------------------------------------------------------------

// HandleReceive processes an incoming DHCPv6 message. It validates the
// message and updates identity associations as appropriate.
func (c *Client) HandleReceive(payload []byte, messageInfo *ip6.MessageInfo) error {
	if !c.running {
		return errors.ErrInvalidState
	}

	if len(payload) < HeaderSize {
		return errors.ErrParse
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		return err
	}

	// We only process Reply messages.
	if hdr.Type != MsgTypeReply {
		return errors.ErrDrop
	}

	// Verify transaction ID matches.
	if hdr.TransactionID != c.transactionID {
		return errors.ErrDrop
	}

	return c.processReply(payload[HeaderSize:])
}

// processReply processes the options in a Reply message.
func (c *Client) processReply(optionData []byte) error {
	opts, err := ParseOptions(optionData)
	if err != nil {
		return errors.ErrParse
	}

	// Validate required options.

	// Must have Server ID.
	serverIDOpt := FindOption(opts, OptionCodeServerID)
	if serverIDOpt == nil {
		return errors.ErrParse
	}
	var serverDUID Eui64DUID
	if err := serverDUID.UnmarshalBinary(serverIDOpt.Data); err != nil {
		return errors.ErrParse
	}
	if !serverDUID.IsValid() {
		return errors.ErrParse
	}

	// Must have Client ID matching ours.
	clientIDOpt := FindOption(opts, OptionCodeClientID)
	if clientIDOpt == nil {
		return errors.ErrParse
	}
	var clientDUID Eui64DUID
	if err := clientDUID.UnmarshalBinary(clientIDOpt.Data); err != nil {
		return errors.ErrParse
	}
	var expectedDUID Eui64DUID
	expectedDUID.Init(c.extAddress)
	if clientDUID != expectedDUID {
		return errors.ErrDrop
	}

	// Must have Rapid Commit (since we sent Solicit with Rapid Commit).
	if !HasRapidCommit(opts) {
		return errors.ErrDrop
	}

	// Check top-level status code.
	statusCode, err := ReadStatusFrom(optionData)
	if err != nil {
		return errors.ErrParse
	}
	if statusCode != StatusSuccess {
		return errors.ErrFailed
	}

	// Process IA_NA options.
	for i := range opts {
		if opts[i].Header.Code != OptionCodeIaNa {
			continue
		}
		if err := c.processIaNa(opts[i].Data); err != nil {
			continue // skip invalid IA_NA options
		}
	}

	// Look for more IAs to solicit.
	c.processNextIdentityAssociation()

	return nil
}

// processIaNa processes a single IA_NA option from a Reply.
func (c *Client) processIaNa(data []byte) error {
	var iaNa IaNa
	if err := iaNa.UnmarshalBinary(data); err != nil {
		return err
	}

	// Check IA_NA-level status code.
	statusCode, err := ReadStatusFrom(iaNa.SubOptions)
	if err != nil {
		return err
	}
	if statusCode != StatusSuccess {
		return errors.ErrFailed
	}

	// Process IA Address sub-options.
	subOpts, err := ParseOptions(iaNa.SubOptions)
	if err != nil {
		return err
	}

	for i := range subOpts {
		if subOpts[i].Header.Code != OptionCodeIaAddress {
			continue
		}
		var iaAddr IaAddress
		if err := iaAddr.UnmarshalBinary(subOpts[i].Data); err != nil {
			continue
		}
		c.processIaAddress(&iaAddr)
	}

	return nil
}

// processIaAddress matches a received address to an existing IA by
// comparing the network prefix, and updates the IA if found.
func (c *Client) processIaAddress(iaAddr *IaAddress) {
	prefix := iaAddr.Address.GetPrefix()

	for i := range c.identityAssociations {
		ia := &c.identityAssociations[i]
		if ia.Status != IaStatusSoliciting {
			continue
		}
		if ia.Prefix != prefix {
			continue
		}

		ia.Address = iaAddr.Address
		ia.PreferredLifetime = iaAddr.PreferredLifetime
		ia.ValidLifetime = iaAddr.ValidLifetime
		ia.Status = IaStatusSolicitReplied
		return
	}
}
