// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"sync"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/srp"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

const (
	// SRPServiceCapacity is the maximum number of owned service registrations.
	SRPServiceCapacity = 8
	// SRPNoticeCapacity bounds application outcome delivery.
	SRPNoticeCapacity = 8
)

// SRPConfig explicitly separates the actual transport tuple from advertised
// assigned host addresses. Assignment alone does not establish reachability.
type SRPConfig struct {
	Local, Server        ip6.SockAddr
	HostName, DomainName string
	Addresses            []ip6.Address
	Lease, KeyLease      uint32
}

// SRPNotice owns its nested data. Revision is an immutable transaction admission
// high-water, NOT a per-operation completion promise. On nil Err, Services and
// RemovedServices contain ONLY inputs acknowledged by this actual response.
// Errors are retryable while Notices remains open. Actual granted lease expiry
// is unknown: requested Lease/Registered flags are not lease-liveness telemetry.
type SRPNotice struct {
	Err             error
	Revision        uint64
	State           srp.State
	Host            srp.HostInfo
	Services        []srp.Service
	RemovedServices []srp.Service
}

// SRPBinding exclusively owns a native client/socket/key/timer lifetime. All
// methods except Notices and Err are LOOP-ONLY (external callers use Do).
// Do not mix this binding with the legacy standalone Instance.SrpClient().
type SRPBinding struct {
	inst       *Instance
	client     *srp.Client
	config     SRPConfig
	socket     udp.Socket
	notices    chan SRPNotice
	closed     bool
	revision   uint64
	selected   []srp.Service
	txRevision uint64
	txID       uint16
	route      srpRouteSnapshot
	sendErr    error
	entropyErr error
	timer      *srpLoopTimer
	queuedRX   int
	terminalMu sync.Mutex
	terminal   error
}

type srpRouteSnapshot struct {
	local, peer types.ExtAddress
	localRLOC   uint16
	nextRLOC    uint16
	pan         types.PanID
	prefix      [8]byte
	networkKey  key.NetworkKey
	child       bool
	parent      udpParentRoute
}

// StartSRP qualifies configuration before socket/credential side effects,
// durably loads/creates the signing identity, and starts the bound client.
// Nil is LOCAL admission, not server acknowledgement. Requires Settings and
// qualified Entropy, up/attached Thread, and the public SendUDP route contract.
//
//nolint:gocritic // Value-based admission is the public owned-input contract.
func (inst *Instance) StartSRP(config SRPConfig) (*SRPBinding, error) {
	if inst.srpBinding != nil || inst.srpClient.IsRunning() ||
		inst.platSettings == nil || inst.entropy == nil {
		return nil, goterrors.ErrInvalidState
	}
	config.Addresses = append([]ip6.Address(nil), config.Addresses...)
	if config.DomainName == "" {
		config.DomainName = srp.DefaultDomainName
	}
	if err := dns.ValidateLabel(config.HostName); err != nil {
		return nil, err
	}
	if err := dns.ValidateName(config.DomainName); err != nil {
		return nil, err
	}
	if err := dns.ValidateName(config.HostName + "." + config.DomainName); err != nil {
		return nil, err
	}
	if len(config.Addresses) == 0 {
		return nil, goterrors.ErrInvalidArgs
	}
	if len(config.Addresses) > 4 {
		return nil, goterrors.ErrNoBufs
	}
	if config.Local.Port == 0 || inst.udpManager.IsPortReserved(config.Local.Port) ||
		config.Local.Port == mle.UDPPort ||
		config.Local.Port == 53 || config.Local.Port == 123 ||
		config.Local.Port == 546 || config.Local.Port == 547 || config.Local.Port == 5683 {
		return nil, goterrors.ErrInvalidArgs
	}
	if inst.udpManager.IsPortInUse(config.Local.Port) || config.Local.Port == inst.srpServer.GetPort() {
		return nil, goterrors.ErrAlready
	}
	b := &SRPBinding{inst: inst, config: config, notices: make(chan SRPNotice, SRPNoticeCapacity)}
	route, err := b.captureRoute()
	if err != nil {
		return nil, err
	}
	b.route = route
	keyPair, err := inst.loadSRPKey()
	if err != nil {
		return nil, err
	}
	var seed [32]byte
	if err := inst.entropy.Fill(seed[:]); err != nil {
		return nil, err
	}
	random := rand.New(rand.NewChaCha8(seed))
	bindingIO := srpBindingIO{binding: b}
	b.client = srp.NewClient(bindingIO, srp.WithKeyPair(keyPair), srp.WithEntropy(bindingIO),
		srp.WithAfterFunc(b.afterFunc), srp.WithSingleServiceUpdates(),
		srp.WithRandUint32(func(max uint32) uint32 {
			if max == 0 {
				return 0
			}
			return random.Uint32N(max)
		}))
	if err := b.client.SetDomainName(config.DomainName); err != nil && !errors.Is(err, goterrors.ErrAlready) {
		return nil, err
	}
	if err := b.client.SetHostName(config.HostName); err != nil {
		return nil, err
	}
	if err := b.client.SetHostAddresses(config.Addresses); err != nil {
		return nil, err
	}
	if config.Lease != 0 {
		b.client.SetLeaseInterval(config.Lease)
	}
	if config.KeyLease != 0 {
		b.client.SetKeyLeaseInterval(config.KeyLease)
	}
	if err := inst.udpManager.Open(&b.socket, udp.NetifThreadInternal, b.receive); err != nil {
		return nil, err
	}
	if err := inst.udpManager.Bind(&b.socket, config.Local); err != nil {
		_ = inst.udpManager.Close(&b.socket)
		return nil, err
	}
	if err := inst.udpManager.Connect(&b.socket, config.Server); err != nil {
		_ = inst.udpManager.Close(&b.socket)
		return nil, err
	}
	b.client.SetCallback(b.onOutcome)
	inst.srpBinding = b
	if err := b.client.Start(config.Server); err != nil {
		b.close(err)
		return nil, err
	}
	return b, nil
}

func (b *SRPBinding) messageInfo() ip6.MessageInfo {
	return ip6.MessageInfo{
		SockAddr: b.config.Local.Address, SockPort: b.config.Local.Port,
		PeerAddr: b.config.Server.Address, PeerPort: b.config.Server.Port,
	}
}

func (b *SRPBinding) captureRoute() (srpRouteSnapshot, error) {
	var snapshot srpRouteSnapshot
	for _, address := range b.config.Addresses {
		found := false
		for _, assigned := range b.inst.netif.GetUnicastAddresses() {
			if assigned.Valid && assigned.Address == address && !address.IsLinkLocal() &&
				udpUnicastAddress(address) && !address.IsMulticast() && !address.IsLoopback() {
				found = true
				break
			}
		}
		if !found {
			return snapshot, goterrors.ErrInvalidSourceAddress
		}
	}
	msg, err := b.inst.prepareUDPMessage(nil, b.messageInfo())
	if err != nil {
		return snapshot, err
	}
	snapshot = srpRouteSnapshot{
		local: b.inst.GetExtAddress(), peer: msg.Metadata.DstExtAddr,
		localRLOC: b.inst.rloc16, nextRLOC: msg.MeshDest, pan: b.inst.mac.GetPanID(),
		prefix: b.inst.meshLocalPrefix, networkKey: b.inst.keyManager.GetNetworkKey(),
		child: b.inst.mleService.Mle().IsChild(),
	}
	if msg.ValidateFrame != nil {
		snapshot.parent, err = b.inst.currentUDPParentRoute(b.messageInfo())
	}
	return snapshot, err
}

func (b *SRPBinding) validate() error {
	if b.closed || b.inst.srpBinding != b {
		return goterrors.ErrInvalidState
	}
	current, err := b.captureRoute()
	if err != nil {
		return err
	}
	if current != b.route {
		return goterrors.ErrNoRoute
	}
	return nil
}

type srpBindingIO struct{ binding *SRPBinding }

// Read supplies only the configured platform entropy to SIG(0).
func (adapter srpBindingIO) Read(data []byte) (int, error) {
	b := adapter.binding
	n, err := (platformEntropyReader{b.inst.entropy}).Read(data)
	if err != nil {
		b.entropyErr = err
	}
	return n, err
}

// Send runs unlocked by Client, but on the Instance loop. Its immutable
// transaction selection is captured before public UDP admission or callbacks.
func (adapter srpBindingIO) Send(data []byte, destination ip6.SockAddr) error {
	b := adapter.binding
	if err := b.validate(); err != nil {
		b.sendErr = err
		return err
	}
	if destination != b.config.Server {
		b.sendErr = goterrors.ErrInvalidArgs
		return b.sendErr
	}
	b.txRevision = b.revision
	b.txID = binary.BigEndian.Uint16(data[:2])
	b.selected = b.selected[:0]
	for _, service := range b.client.GetServices() {
		switch service.State {
		case srp.ItemStateAdding, srp.ItemStateRefreshing, srp.ItemStateRemoving:
			b.selected = append(b.selected, cloneSRPService(*service))
		}
	}
	b.sendErr = b.inst.SendUDP(data, b.messageInfo())
	return b.sendErr
}

func (b *SRPBinding) receive(data []byte, info *ip6.MessageInfo) {
	if info.SockAddr != b.config.Local.Address || info.SockPort != b.config.Local.Port ||
		info.PeerAddr != b.config.Server.Address || info.PeerPort != b.config.Server.Port ||
		b.closed || b.client.GetState() != srp.StateUpdating {
		b.rejectResponse(goterrors.ErrDrop)
		return
	}
	if len(data) > 1232 {
		b.rejectResponse(goterrors.ErrNoBufs)
		return
	}
	var header dns.Header
	if err := header.UnmarshalBinary(data); err != nil {
		b.rejectResponse(err)
		return
	}
	if header.GetType() != dns.TypeResponse || header.GetOpCode() != dns.OpcodeUpdate || header.MessageID != b.txID {
		b.rejectResponse(goterrors.ErrDrop)
		return
	}
	// Native RX dispatch can still hold Mac.mu. Defer qualified parsing and
	// outcome work to the same loop, without recursive Do or blocking PostTask.
	// Own borrowed radio bytes and cap both retained payloads and admissions.
	if b.queuedRX >= SRPNoticeCapacity {
		b.close(goterrors.ErrNoBufs)
		return
	}
	payload := append([]byte(nil), data...)
	b.queuedRX++
	select {
	case b.inst.taskCh <- func() {
		b.queuedRX--
		if !b.closed && b.inst.srpBinding == b {
			b.processResponse(payload)
		}
	}:
	default:
		b.queuedRX--
		b.close(goterrors.ErrNoBufs)
	}
}

func (b *SRPBinding) processResponse(data []byte) {
	if err := b.validate(); err != nil {
		b.close(err)
		return
	}
	// Client owns message-ID/opcode/length/lease validation; it borrows bytes
	// only synchronously. Invalid replies cannot cancel the owned deadline.
	b.client.HandleResponse(data)
}

func (b *SRPBinding) rejectResponse(err error) {
	if b.inst.logger != nil {
		b.inst.logger.Log(platform.LogLevelWarn, platform.LogRegionSRP, "bound SRP response rejected: "+err.Error())
	}
}

//nolint:gocritic // Deliberately detach the complete service value before nested copies.
func cloneSRPService(service srp.Service) srp.Service {
	service.SubTypeLabels = append([]string(nil), service.SubTypeLabels...)
	entries := make([]dns.TxtEntry, len(service.TxtEntries))
	for i, entry := range service.TxtEntries {
		entries[i] = entry
		if entry.Value != nil {
			entries[i].Value = append([]byte{}, entry.Value...)
		}
	}
	service.TxtEntries = entries
	return service
}

func (b *SRPBinding) onOutcome(err error, host *srp.HostInfo, services, removed []*srp.Service) {
	if b.closed {
		return
	}
	if err == goterrors.ErrFailed && b.sendErr != nil {
		err = b.sendErr
	}
	notice := SRPNotice{Err: err, Revision: b.txRevision, State: b.client.GetState(), Host: *host}
	notice.Host.Addresses = append([]ip6.Address(nil), host.Addresses...)
	if err == nil {
		// Copy only immutable inputs selected before this actual send.
		for _, input := range b.selected {
			isRemoved := input.State == srp.ItemStateRemoving
			input.State = srp.ItemStateRegistered
			if isRemoved {
				input.State = srp.ItemStateRemoved
				notice.RemovedServices = append(notice.RemovedServices, cloneSRPService(input))
			} else {
				notice.Services = append(notice.Services, cloneSRPService(input))
			}
		}
	} else {
		for _, service := range services {
			notice.Services = append(notice.Services, cloneSRPService(*service))
		}
	}
	_ = removed // Success subset comes from transaction inputs, never retained states.
	if b.publishNotice(&notice) == nil && err != nil && notice.State == srp.StateUpdated {
		b.close(err) // The existing consecutive-local-send budget ended.
	}
}

func (b *SRPBinding) publishNotice(notice *SRPNotice) error {
	select {
	case b.notices <- *notice:
		return nil
	default:
		b.close(goterrors.ErrNoBufs)
		return goterrors.ErrNoBufs
	}
}

type srpLoopTimer struct {
	active bool
	cancel func()
	fire   func()
}

func (t *srpLoopTimer) Stop() bool {
	active := t.active
	t.active = false
	t.cancel()
	return active
}

func (b *SRPBinding) afterFunc(delay time.Duration, fn func()) srp.Timer {
	timer := &srpLoopTimer{active: true}
	timer.fire = func() {
		if !timer.active || b.closed || b.inst.srpBinding != b {
			return
		}
		timer.active = false
		if err := b.validate(); err != nil {
			b.close(err)
			return
		}
		fn()
		if b.entropyErr != nil {
			b.close(b.entropyErr)
		}
	}
	timer.cancel = b.inst.timers.scheduleWithCancel(delay, timer.fire)
	b.timer = timer
	return timer
}

// Notices is a bounded owned-result queue for reads OUTSIDE the Instance loop.
// On closure ALWAYS inspect Err, even after an earlier nil-error ACK.
func (b *SRPBinding) Notices() <-chan SRPNotice { return b.notices }

// Err is concurrency-safe terminal status; retryable attempt errors arrive only
// through Notices. Nil after local Stop does NOT mean remote unregistration.
func (b *SRPBinding) Err() error {
	b.terminalMu.Lock()
	defer b.terminalMu.Unlock()
	return b.terminal
}

func (b *SRPBinding) close(err error) {
	if b.closed {
		return
	}
	b.closed = true
	b.client.Stop()
	_ = b.inst.udpManager.Close(&b.socket)
	if b.inst.srpBinding == b {
		b.inst.srpBinding = nil
	}
	b.terminalMu.Lock()
	b.terminal = err
	b.terminalMu.Unlock()
	close(b.notices)
}

// Stop releases local resources; it is NOT a server withdrawal ACK. To remove
// remote records, withdraw and await the matching removal notice first.
func (b *SRPBinding) Stop() error {
	b.close(nil)
	return nil
}

// Pause cancels outstanding attempt work but retains local port and ownership.
// It publishes StatePaused, nil Err, and empty service ACK subsets: explicit
// nonterminal health invalidation, never a registration/withdrawal ACK.
func (b *SRPBinding) Pause() error {
	if err := b.validate(); err != nil {
		return err
	}
	if b.client.GetState() == srp.StatePaused {
		return nil
	}
	b.client.Pause()
	notice := SRPNotice{State: srp.StatePaused, Revision: b.revision, Host: b.client.GetHostInfo()}
	return b.publishNotice(&notice)
}

// Resume revalidates the original tuple/route before resuming retryable work.
func (b *SRPBinding) Resume() error {
	if err := b.validate(); err != nil {
		if !b.closed {
			b.close(err)
		}
		return err
	}
	if b.client.GetState() != srp.StatePaused {
		return nil
	}
	// Standalone Pause intentionally retains Registered states. This binding's
	// consumer has invalidated health, so require a fresh actual ACK for each
	// retained registration rather than silently blessing those old states.
	for _, service := range b.client.GetServices() {
		if service.State != srp.ItemStateRegistered {
			continue
		}
		input := cloneSRPService(*service)
		if err := b.client.ClearService(service); err != nil {
			b.close(err)
			return err
		}
		if err := b.client.AddService(&input); err != nil {
			b.close(err)
			return err
		}
	}
	b.client.Resume()
	return nil
}

// UpsertService admits a deep-owned replacement under (Name,InstanceName).
// Returned revision is a high-water, not an individual completion promise.
//
//nolint:gocritic // Preserve the agreed value-based owned-input API.
func (b *SRPBinding) UpsertService(service srp.Service) (uint64, error) {
	if err := b.validateMutation(); err != nil {
		return 0, err
	}
	switch b.client.GetHostInfo().State {
	case srp.ItemStateToRemove, srp.ItemStateRemoving, srp.ItemStateRemoved:
		return 0, goterrors.ErrInvalidState
	}
	if err := dns.ValidateLabel(service.InstanceName); err != nil {
		return 0, err
	}
	if err := dns.ValidateName(service.Name); err != nil {
		return 0, err
	}
	// Instance labels can legally contain dots. Check the actual encoded
	// complete name rather than splitting that label into textual components.
	instanceName, err := dns.AppendLabel(nil, service.InstanceName)
	if err != nil {
		return 0, err
	}
	serviceName, err := dns.AppendName(nil, service.Name+"."+b.config.DomainName)
	if err != nil {
		return 0, err
	}
	if len(instanceName)+len(serviceName) > dns.MaxNameSize {
		return 0, goterrors.ErrInvalidArgs
	}
	if service.Port == 0 || service.Name == "" || service.Name == "." {
		return 0, goterrors.ErrInvalidArgs
	}
	if len(service.SubTypeLabels) > 5 {
		return 0, goterrors.ErrNoBufs
	}
	for _, label := range service.SubTypeLabels {
		if err := dns.ValidateLabel(label); err != nil {
			return 0, err
		}
		if len(label)+1+5+len(serviceName) > dns.MaxNameSize {
			return 0, goterrors.ErrInvalidArgs
		}
	}
	txtBound := 0
	for _, entry := range service.TxtEntries {
		txtBound += len(entry.Key) + len(entry.Value) + 2
		if txtBound > 1024 {
			return 0, goterrors.ErrNoBufs
		}
	}
	txt, err := dns.AppendTxtEntries(nil, service.TxtEntries)
	if err != nil {
		return 0, err
	}
	if len(txt) > 512 {
		return 0, goterrors.ErrNoBufs
	}
	if !dns.VerifyTxtData(txt, true) {
		return 0, goterrors.ErrInvalidArgs
	}
	size, err := b.client.ServiceUpdateSize(service)
	if err != nil {
		return 0, err
	}
	if size > 1232 {
		return 0, goterrors.ErrNoBufs
	}
	services := b.client.GetServices()
	var replaced *srp.Service
	for _, current := range services {
		if current.Name == service.Name && current.InstanceName == service.InstanceName {
			replaced = current
			break
		}
	}
	if replaced == nil && len(services) >= SRPServiceCapacity {
		return 0, goterrors.ErrNoBufs
	}
	copyService := cloneSRPService(service)
	if replaced != nil {
		if err := b.client.ClearService(replaced); err != nil {
			return 0, err
		}
	}
	if err := b.client.AddService(&copyService); err != nil {
		return 0, err
	}
	b.revision++
	return b.revision, nil
}

func (b *SRPBinding) validateMutation() error {
	if err := b.validate(); err != nil {
		b.close(err)
		return err
	}
	if b.client.GetState() == srp.StateUpdating {
		return goterrors.ErrInvalidState
	}
	return nil
}

// WithdrawService retains retryable pending removal until a real removal ACK.
func (b *SRPBinding) WithdrawService(name, instanceName string) (uint64, error) {
	if err := b.validateMutation(); err != nil {
		return 0, err
	}
	for _, service := range b.client.GetServices() {
		if service.Name != name || service.InstanceName != instanceName {
			continue
		}
		if service.State == srp.ItemStateToRemove {
			return b.revision, nil
		}
		if err := b.client.RemoveService(service); err != nil {
			return 0, err
		}
		b.revision++
		return b.revision, nil
	}
	return 0, goterrors.ErrNotFound
}

// WithdrawHost requests remote removal without deleting the local signing key.
func (b *SRPBinding) WithdrawHost(removeKeyLease bool) (uint64, error) {
	if err := b.validateMutation(); err != nil {
		return 0, err
	}
	if err := b.client.RemoveHostAndServices(removeKeyLease, true); err != nil {
		return 0, err
	}
	b.revision++
	return b.revision, nil
}
