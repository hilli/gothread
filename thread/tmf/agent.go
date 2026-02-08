// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tmf

import (
	"sync"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"

	goterrors "github.com/hilli/gothread/errors"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// Port is the well-known UDP port for TMF (Thread Management Framework).
const Port uint16 = 61631

// ---------------------------------------------------------------------------
// TMF-specific DSCP ↔ Priority mapping
// ---------------------------------------------------------------------------

// PriorityToDscp maps a message priority to a TMF-specific DSCP value.
// TMF uses local codepoint values (0bxxxx11), not Class Selector values.
//
//	PriorityNet    → DscpTmfNetPriority    (7)
//	PriorityNormal → DscpTmfNormalPriority (15)
//	PriorityLow    → DscpTmfLowPriority    (23)
//
// All other values (including PriorityHigh) map to DscpTmfNetPriority.
func PriorityToDscp(p ip6.Priority) ip6.Dscp {
	switch p {
	case ip6.PriorityNet:
		return ip6.DscpTmfNetPriority
	case ip6.PriorityNormal:
		return ip6.DscpTmfNormalPriority
	case ip6.PriorityLow:
		return ip6.DscpTmfLowPriority
	default:
		return ip6.DscpTmfNetPriority
	}
}

// DscpToPriority maps a DSCP value to a TMF message priority.
// It recognizes the three TMF-specific DSCP values and defaults to
// PriorityNet for unrecognized values.
func DscpToPriority(dscp ip6.Dscp) ip6.Priority {
	switch dscp {
	case ip6.DscpTmfNetPriority:
		return ip6.PriorityNet
	case ip6.DscpTmfNormalPriority:
		return ip6.PriorityNormal
	case ip6.DscpTmfLowPriority:
		return ip6.PriorityLow
	default:
		return ip6.PriorityNet
	}
}

// ---------------------------------------------------------------------------
// TMF addressing filter
// ---------------------------------------------------------------------------

// IsTmfMessage reports whether a message with the given source and destination
// addresses and destination port is a valid TMF message.
//
// Rules (from OpenThread tmf.cpp FilterAgent):
//   - If source is link-local unicast: destination must be link-local unicast
//     or link-local multicast.
//   - Otherwise: source must be mesh-local (ULA prefix fd00::/8) AND
//     destination must be mesh-local, link-local multicast, or realm-local
//     multicast.
func IsTmfMessage(src, dst ip6.Address, dstPort uint16) bool {
	if dstPort != Port {
		return false
	}

	if src.IsLinkLocalUnicast() {
		return dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast()
	}

	// Source must be mesh-local (ULA).
	srcPrefix := src.GetPrefix()
	if !srcPrefix.IsUla() {
		return false
	}

	// Destination must be mesh-local (ULA), link-local multicast, or
	// realm-local multicast.
	if dst.IsLinkLocalMulticast() || dst.IsRealmLocalMulticast() {
		return true
	}

	dstPrefix := dst.GetPrefix()
	return dstPrefix.IsUla()
}

// ---------------------------------------------------------------------------
// Handler type
// ---------------------------------------------------------------------------

// Handler is the callback type for TMF request handlers. It receives the
// URI enum of the matched resource, the CoAP message, and the ip6 message
// info.
type Handler func(uri URI, msg *coap.Message, info ip6.MessageInfo)

// ---------------------------------------------------------------------------
// Agent
// ---------------------------------------------------------------------------

// Agent is a Thread Management Framework agent that wraps a CoAP engine,
// providing URI-based dispatch, TMF addressing validation, and TMF-specific
// DSCP/priority mapping.
//
// This is a Go port of OpenThread's Tmf::Agent (src/core/thread/tmf.hpp).
type Agent struct {
	engine   *coap.Engine
	handlers map[URI]Handler
	mu       sync.Mutex
}

// NewAgent creates a new TMF agent wrapping the given CoAP engine. It
// installs a CoAP interceptor that validates TMF addressing rules.
func NewAgent(engine *coap.Engine) *Agent {
	a := &Agent{
		engine:   engine,
		handlers: make(map[URI]Handler),
	}

	// Install the TMF interceptor on the CoAP engine.
	engine.SetInterceptor(a.intercept)

	// Install the TMF default handler so all requests route through the
	// agent's URI dispatch.
	engine.SetDefaultHandler(a.dispatch)

	return a
}

// RegisterHandler registers a handler for the given TMF URI. If a handler
// is already registered for this URI, it is replaced.
func (a *Agent) RegisterHandler(uri URI, h Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handlers[uri] = h
}

// UnregisterHandler removes the handler for the given TMF URI.
func (a *Agent) UnregisterHandler(uri URI) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.handlers, uri)
}

// GetEngine returns the underlying CoAP engine.
func (a *Agent) GetEngine() *coap.Engine {
	return a.engine
}

// Stop stops the TMF agent and its underlying CoAP engine.
func (a *Agent) Stop() {
	a.engine.Stop()
}

// intercept is the CoAP interceptor that validates TMF addressing rules.
// It converts the coap.MessageInfo to ip6 addresses for filtering.
func (a *Agent) intercept(_ *coap.Message, info coap.MessageInfo) error {
	var src, dst ip6.Address
	copy(src[:], info.LocalAddr[:])
	copy(dst[:], info.PeerAddr[:])

	if !IsTmfMessage(src, dst, info.PeerPort) {
		return goterrors.ErrNotTmf
	}
	return nil
}

// dispatch is the CoAP default handler that routes requests to registered
// TMF handlers by URI path.
func (a *Agent) dispatch(msg *coap.Message, info coap.MessageInfo) {
	// Extract URI path from the CoAP message options.
	uriPath := extractURIPath(msg)
	uri := URIFromPath(uriPath)

	if uri == URIUnknown {
		// Unknown URI — send 4.04 Not Found for CON, ignore for NON.
		if msg.GetType() == coap.TypeConfirmable {
			_ = a.engine.SendHeaderResponse(coap.CodeNotFound, msg, info)
		}
		return
	}

	a.mu.Lock()
	h, ok := a.handlers[uri]
	a.mu.Unlock()

	if !ok {
		// No handler registered — send 4.04 Not Found for CON.
		if msg.GetType() == coap.TypeConfirmable {
			_ = a.engine.SendHeaderResponse(coap.CodeNotFound, msg, info)
		}
		return
	}

	// Convert coap.MessageInfo to ip6.MessageInfo for the handler.
	ip6Info := ip6.MessageInfo{
		SockAddr:      ip6.Address(info.LocalAddr),
		PeerAddr:      ip6.Address(info.PeerAddr),
		PeerPort:      info.PeerPort,
		SockPort:      Port,
		MulticastLoop: info.MulticastLoop,
	}

	h(uri, msg, ip6Info)
}

// extractURIPath extracts the URI path from CoAP message options by
// concatenating all Uri-Path option values with '/'.
func extractURIPath(msg *coap.Message) string {
	var path string
	it := msg.GetOptionIterator()
	first := true
	for {
		num, val, ok := it.Next()
		if !ok {
			break
		}
		if num == coap.OptionURIPath {
			if !first {
				path += "/"
			}
			path += string(val)
			first = false
		}
	}
	return path
}

// ---------------------------------------------------------------------------
// AgentMessageInfo — convenience wrapper
// ---------------------------------------------------------------------------

// AgentMessageInfo is a convenience wrapper around ip6.MessageInfo that
// provides TMF-specific defaults (PeerPort = Port).
type AgentMessageInfo struct {
	ip6.MessageInfo
}

// NewAgentMessageInfo creates a new AgentMessageInfo with PeerPort set to
// the TMF well-known port.
func NewAgentMessageInfo() AgentMessageInfo {
	return AgentMessageInfo{
		MessageInfo: ip6.MessageInfo{
			PeerPort: Port,
		},
	}
}

// SetSockAddrToRLOC sets the local (sock) address to the RLOC address formed
// from the mesh-local prefix and the given RLOC16.
func (mi *AgentMessageInfo) SetSockAddrToRLOC(meshLocalPrefix ip6.NetworkPrefix, rloc16 uint16) {
	mi.SockAddr = rlocAddress(meshLocalPrefix, rloc16)
	mi.SockPort = Port
}

// SetPeerAddrToRLOC sets the peer (remote) address to the RLOC address
// formed from the mesh-local prefix and the given RLOC16.
func (mi *AgentMessageInfo) SetPeerAddrToRLOC(meshLocalPrefix ip6.NetworkPrefix, rloc16 uint16) {
	mi.PeerAddr = rlocAddress(meshLocalPrefix, rloc16)
	mi.PeerPort = Port
}

// rlocAddress constructs an IPv6 address from a mesh-local prefix and RLOC16.
// The IID is set to the RLOC pattern: 0000:00ff:fe00:RLOC16.
func rlocAddress(prefix ip6.NetworkPrefix, rloc16 uint16) ip6.Address {
	var addr ip6.Address
	addr.SetPrefix(prefix)
	iid := ip6.InterfaceIdentifier{0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00}
	iid.SetLocator(rloc16)
	addr.SetIid(iid)
	return addr
}
