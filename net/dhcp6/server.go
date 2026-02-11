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
// Server transport interface
// ---------------------------------------------------------------------------

// ServerTransport abstracts the network I/O needed by the DHCPv6 server.
type ServerTransport interface {
	// Send transmits a DHCPv6 message to the given destination.
	Send(payload []byte, dst ip6.Address, dstPort uint16) error
}

// ---------------------------------------------------------------------------
// PrefixAgent
// ---------------------------------------------------------------------------

// PrefixAgent represents a single DHCPv6-managed prefix on the server.
type PrefixAgent struct {
	// Prefix is the network prefix being served.
	Prefix ip6.NetworkPrefix

	// PrefixLength is the length of the prefix in bits.
	PrefixLength uint8

	// Valid indicates whether this prefix agent is active.
	Valid bool
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

// Server implements a DHCPv6 server for Thread networks. It responds to
// Solicit messages (with Rapid Commit) by allocating addresses from the
// managed prefixes using the client's EUI-64 identifier.
type Server struct {
	// transport is the network transport for sending replies.
	transport ServerTransport

	// extAddress is the server's EUI-64 used as the DUID-LL identifier.
	extAddress types.ExtAddress

	// prefixAgents holds the managed prefix agents.
	prefixAgents []PrefixAgent

	// running indicates whether the server is active.
	running bool
}

// NewServer creates a new DHCPv6 server.
func NewServer(transport ServerTransport, extAddr types.ExtAddress) *Server {
	return &Server{
		transport:  transport,
		extAddress: extAddr,
	}
}

// Start activates the server.
func (s *Server) Start() error {
	if s.running {
		return errors.ErrAlready
	}
	s.running = true
	return nil
}

// Stop deactivates the server.
func (s *Server) Stop() {
	s.running = false
}

// IsRunning returns true if the server is active.
func (s *Server) IsRunning() bool {
	return s.running
}

// GetPrefixAgents returns the current prefix agents.
func (s *Server) GetPrefixAgents() []PrefixAgent {
	return s.prefixAgents
}

// ---------------------------------------------------------------------------
// Prefix management
// ---------------------------------------------------------------------------

// AddPrefix adds a prefix for the server to manage. If the prefix already
// exists and is valid, ErrAlready is returned.
func (s *Server) AddPrefix(prefix ip6.NetworkPrefix, prefixLength uint8) error {
	for i := range s.prefixAgents {
		if s.prefixAgents[i].Prefix == prefix {
			if s.prefixAgents[i].Valid {
				return errors.ErrAlready
			}
			// Reactivate an existing but invalid entry.
			s.prefixAgents[i].Valid = true
			s.prefixAgents[i].PrefixLength = prefixLength
			return nil
		}
	}

	s.prefixAgents = append(s.prefixAgents, PrefixAgent{
		Prefix:       prefix,
		PrefixLength: prefixLength,
		Valid:        true,
	})
	return nil
}

// RemovePrefix removes a managed prefix by marking it invalid.
func (s *Server) RemovePrefix(prefix ip6.NetworkPrefix) error {
	for i := range s.prefixAgents {
		if s.prefixAgents[i].Prefix == prefix && s.prefixAgents[i].Valid {
			s.prefixAgents[i].Valid = false
			return nil
		}
	}
	return errors.ErrNotFound
}

// HasPrefix returns true if the server is managing the given prefix.
func (s *Server) HasPrefix(prefix ip6.NetworkPrefix) bool {
	for i := range s.prefixAgents {
		if s.prefixAgents[i].Prefix == prefix && s.prefixAgents[i].Valid {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Receive handling
// ---------------------------------------------------------------------------

// HandleReceive processes an incoming DHCPv6 message. The server only
// handles Solicit messages with Rapid Commit.
func (s *Server) HandleReceive(payload []byte, messageInfo *ip6.MessageInfo) error {
	if !s.running {
		return errors.ErrInvalidState
	}

	if len(payload) < HeaderSize {
		return errors.ErrParse
	}

	var hdr Header
	if err := hdr.UnmarshalBinary(payload); err != nil {
		return err
	}

	// Only process Solicit messages.
	if hdr.Type != MsgTypeSolicit {
		return errors.ErrDrop
	}

	return s.processSolicit(&hdr, payload[HeaderSize:], messageInfo)
}

// processSolicit validates and processes a Solicit message, then sends a Reply.
func (s *Server) processSolicit(hdr *Header, optionData []byte, messageInfo *ip6.MessageInfo) error {
	opts, err := ParseOptions(optionData)
	if err != nil {
		return errors.ErrParse
	}

	// Must have Client ID.
	clientIDOpt := FindOption(opts, OptionCodeClientID)
	if clientIDOpt == nil {
		return errors.ErrParse
	}
	var clientDUID Eui64DUID
	if err := clientDUID.UnmarshalBinary(clientIDOpt.Data); err != nil {
		return errors.ErrParse
	}
	if !clientDUID.IsValid() {
		return errors.ErrParse
	}

	// Must NOT have Server ID (Solicit should not contain one).
	if FindOption(opts, OptionCodeServerID) != nil {
		return errors.ErrDrop
	}

	// Must have Rapid Commit.
	if !HasRapidCommit(opts) {
		return errors.ErrDrop
	}

	// Process IA_NA option.
	iaNaOpt := FindOption(opts, OptionCodeIaNa)
	if iaNaOpt == nil {
		return errors.ErrParse
	}
	var iaNa IaNa
	if err := iaNa.UnmarshalBinary(iaNaOpt.Data); err != nil {
		return errors.ErrParse
	}

	return s.sendReply(hdr, &clientDUID, &iaNa, messageInfo)
}

// sendReply constructs and sends a Reply message.
func (s *Server) sendReply(solicitHdr *Header, clientDUID *Eui64DUID, iaNa *IaNa, messageInfo *ip6.MessageInfo) error {
	if s.transport == nil {
		return errors.ErrInvalidState
	}

	// Build the Reply header with the same transaction ID as the Solicit.
	replyHdr := Header{
		Type:          MsgTypeReply,
		TransactionID: solicitHdr.TransactionID,
	}
	hdrBytes, err := replyHdr.MarshalBinary()
	if err != nil {
		return err
	}

	buf := make([]byte, 0, 256)
	buf = append(buf, hdrBytes...)

	// Server ID option.
	var serverDUID Eui64DUID
	serverDUID.Init(s.extAddress)
	buf = AppendServerIDOption(buf, &serverDUID)

	// Client ID option (echo back).
	buf = AppendClientIDOption(buf, clientDUID)

	// IA_NA option with address sub-options.
	iaNaData := s.buildIaNaReply(iaNa, clientDUID)
	buf = AppendOption(buf, OptionCodeIaNa, iaNaData)

	// Rapid Commit option.
	buf = AppendRapidCommitOption(buf)

	// Send the reply to the client's source address.
	dst := messageInfo.PeerAddr
	return s.transport.Send(buf, dst, ClientPort)
}

// buildIaNaReply constructs the IA_NA option data for the Reply, including
// a status code and IA Address sub-options for each matching prefix.
func (s *Server) buildIaNaReply(iaNa *IaNa, clientDUID *Eui64DUID) []byte {
	// Start with the IA_NA fixed fields.
	replyIaNa := IaNa{
		IAID: iaNa.IAID,
		T1:   0,
		T2:   0,
	}

	// Build sub-options: status code + IA addresses.
	var subOpts []byte
	subOpts = AppendStatusCodeOption(subOpts, StatusSuccess)

	// For each valid prefix, create an IA Address with the address derived
	// from the prefix + client's EUI-64.
	for i := range s.prefixAgents {
		pa := &s.prefixAgents[i]
		if !pa.Valid {
			continue
		}

		addr := MakeAddressFromPrefixEUI64(pa.Prefix, clientDUID.ExtAddress)
		iaAddr := IaAddress{
			Address:           addr,
			PreferredLifetime: InfiniteLifetime,
			ValidLifetime:     InfiniteLifetime,
		}
		subOpts = AppendIaAddressOption(subOpts, &iaAddr)
	}

	replyIaNa.SubOptions = subOpts

	data, _ := replyIaNa.MarshalBinary()
	return data
}
