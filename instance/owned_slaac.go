// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"errors"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/slaac"
	"github.com/hilli/gothread/thread/netdata"
)

type ownedSlaacSource struct {
	address             ip6.Address
	generation          uint64
	assigned, preferred bool
}

// These are ownership/proof records for the existing manager's four slots,
// not another address allocator, external pool or packet buffer.
type ownedSlaacState struct {
	sources  [slaac.DefaultMaxAddresses]ownedSlaacSource
	revision uint64
	updating bool
	err      error
}

type ownedSlaacUpdate uint8

const (
	ownedSlaacAcceptedData ownedSlaacUpdate = iota
	ownedSlaacInvalidatedData
)

func (state *ownedSlaacState) advance() (uint64, error) {
	if state.err != nil {
		return 0, state.err
	}
	if state.revision == ^uint64(0) {
		state.err = goterrors.ErrNoBufs
		return 0, state.err
	}
	state.revision++
	return state.revision, nil
}

func ownedSlaacPrefixes(data []byte, meshPrefix [8]byte) ([]slaac.Prefix, error) {
	if err := validateOwnedNetworkData(data, 0); err != nil {
		return nil, err
	}
	var prefixes []slaac.Prefix
	for _, top := range netdata.ParseTLVs(data) {
		if top.Type != netdata.TLVTypePrefix {
			continue
		}
		prefix, err := netdata.ParsePrefixValue(top.Value, top.Stable)
		if err != nil {
			return nil, err
		}
		for _, sub := range netdata.ParseTLVs(prefix.SubTLVsData) {
			if sub.Type != netdata.TLVTypeBorderRouter {
				continue
			}
			for offset := 0; offset < len(sub.Value); offset += netdata.BorderRouterEntrySize {
				entry, err := netdata.ParseBorderRouterEntry(sub.Value[offset:])
				if err != nil {
					return nil, err
				}
				if !entry.OnMesh {
					continue
				}
				if entry.RLOC16 >= 0xfc00 || entry.RLOC16&0x0200 != 0 {
					return nil, goterrors.ErrParse
				}
				if entry.DHCP || entry.Configure || entry.Dp || prefix.DomainID != 0 {
					return nil, goterrors.ErrNotCapable
				}
				if !entry.SLAAC {
					continue
				}
				address := ip6.Address(prefix.Prefix.GetBytes())
				if prefix.Prefix.GetLength() != 64 || !udpUnicastAddress(address) || address.IsLinkLocal() ||
					address.GetPrefix() == ip6.NetworkPrefix(meshPrefix) {
					return nil, goterrors.ErrNotCapable
				}
				flags := slaac.FlagOnMesh | slaac.FlagSlaac
				if entry.Preferred {
					flags |= slaac.FlagPreferred
				}
				if entry.DefaultRoute {
					flags |= slaac.FlagDefaultRoute
				}
				found := false
				for i := range prefixes {
					if prefixes[i].Prefix == prefix.Prefix.GetBytes() {
						prefixes[i].Flags |= flags
						found = true
						break
					}
				}
				if !found {
					if len(prefixes) == slaac.DefaultMaxAddresses {
						return nil, goterrors.ErrNoBufs
					}
					prefixes = append(prefixes, slaac.Prefix{Prefix: prefix.Prefix.GetBytes(), Length: 64, Flags: flags})
				}
			}
		}
	}
	return prefixes, nil
}

func (inst *Instance) ownsSlaacNetif(source *ownedSlaacSource) bool {
	if !source.assigned || inst.netif.IsUnicastAddressExternal(source.address) {
		return false
	}
	for _, current := range inst.netif.GetUnicastAddresses() {
		if current.Address == source.address {
			return current.Origin == ip6.OriginSLAAC && current.Valid && !current.RLOC && !current.MeshLocal &&
				current.PrefixLength == 64 && current.Preferred == source.preferred
		}
	}
	return false
}

func (inst *Instance) retireOwnedSlaac(source *ownedSlaacSource, state *ownedSlaacState) error {
	owned := inst.ownsSlaacNetif(source)
	source.assigned = false
	_, err := state.advance()
	if owned {
		inst.netif.RemoveUnicastAddress(&ip6.UnicastAddress{Address: source.address})
	}
	return err
}

// Called only after authenticated owned parent processing and durable adoption,
// never by the generic public leader/NetData/SLAAC setters.
func (inst *Instance) syncOwnedSlaac(prefixes []slaac.Prefix, origin ownedSlaacUpdate) error {
	attachment := inst.ownedAttachment
	if attachment == nil {
		return goterrors.ErrInvalidState
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return err
	}
	if err := inst.SecurityError(); err != nil {
		return err
	}
	if err := inst.PersistenceError(); err != nil {
		return err
	}
	if inst.rloc16 != attachment.rloc || uint16(inst.subMac.GetShortAddress()) != attachment.rloc ||
		inst.mac.GetPanChannelSnapshot() != attachment.channel || !inst.hasOwnedRLOCAddress() {
		return goterrors.ErrInvalidState
	}
	if inst.slaacManager == nil || !inst.slaacManager.IsEnabled() {
		return goterrors.ErrInvalidState
	}
	if attachment.slaac == nil {
		attachment.slaac = &ownedSlaacState{}
		inst.slaacManager.Disable()
		inst.slaacManager.Enable()
	}
	state := attachment.slaac
	if state.err != nil {
		return state.err
	}
	if err := inst.slaacManager.UpdateChecked(prefixes); err != nil {
		return err
	}
	generated := inst.slaacManager.GetAddresses()
	state.updating = true
	defer func() { state.updating = false }()
	for i := range state.sources {
		source := &state.sources[i]
		if !source.assigned {
			continue
		}
		retained := false
		for _, address := range generated {
			if address.Address != source.address {
				continue
			}
			for _, prefix := range prefixes {
				if address.Address.GetPrefix() == ip6.Address(prefix.Prefix).GetPrefix() &&
					source.preferred == prefix.HasFlag(slaac.FlagPreferred) && inst.ownsSlaacNetif(source) {
					retained = true
				}
			}
		}
		if !retained {
			proof := ownedSourceProof{attachment: attachment, source: source.address, generation: source.generation}
			present, preferred := false, false
			for _, prefix := range prefixes {
				if source.address.GetPrefix() == ip6.Address(prefix.Prefix).GetPrefix() {
					present, preferred = true, prefix.HasFlag(slaac.FlagPreferred)
				}
			}
			switch {
			case origin == ownedSlaacInvalidatedData:
				inst.failSourceLifetime(proof, ThreadSourceNetworkDataInvalidated, goterrors.ErrInvalidState)
			case inst.ownsSlaacNetif(source) && !present:
				inst.retireSourceLifetime(proof, ThreadSourceAuthenticatedWithdrawal)
			case inst.ownsSlaacNetif(source) && source.preferred && !preferred:
				inst.retireSourceLifetime(proof, ThreadSourceAuthenticatedDeprecation)
			default:
				inst.failSourceLifetime(proof, ThreadSourceIdentityInvalid, goterrors.ErrInvalidSourceAddress)
			}
			if err := inst.retireOwnedSlaac(source, state); err != nil {
				return err
			}
		}
	}
	for _, candidate := range generated {
		for candidate.Address.IsRoutingLocator() || candidate.Address.IsIidReserved() ||
			inst.netif.HasUnicastAddress(candidate.Address) && !inst.isRecordedOwnedSlaac(candidate.Address) {
			if err := inst.slaacManager.SignalDADFailure(candidate.Prefix.Prefix, candidate.Prefix.Length); err != nil {
				return err
			}
			var found bool
			candidate, found = inst.slaacManager.FindAddress(candidate.Prefix.Prefix, candidate.Prefix.Length)
			if !found {
				return goterrors.ErrFailed
			}
		}
		if inst.isRecordedOwnedSlaac(candidate.Address) {
			continue
		}
		slot := -1
		for i := range state.sources {
			if !state.sources[i].assigned {
				slot = i
				break
			}
		}
		if slot < 0 {
			return goterrors.ErrNoBufs
		}
		preferred := false
		for _, prefix := range prefixes {
			if candidate.Address.GetPrefix() == ip6.Address(prefix.Prefix).GetPrefix() {
				preferred = prefix.HasFlag(slaac.FlagPreferred)
				break
			}
		}
		if err := inst.SecurityError(); err != nil {
			return err
		}
		if err := inst.PersistenceError(); err != nil {
			return err
		}
		generation, err := state.advance()
		if err != nil {
			return err
		}
		record := &state.sources[slot]
		*record = ownedSlaacSource{address: candidate.Address, generation: generation, assigned: true, preferred: preferred}
		var address ip6.UnicastAddress
		address.InitAsSLAACOrigin(64, preferred)
		address.Address = candidate.Address
		inst.netif.AddUnicastAddress(&address)
		if !inst.ownsSlaacNetif(record) {
			return goterrors.ErrInvalidState
		}
	}
	return nil
}

func (inst *Instance) isRecordedOwnedSlaac(address ip6.Address) bool {
	attachment := inst.ownedAttachment
	if attachment == nil || attachment.slaac == nil {
		return false
	}
	for i := range attachment.slaac.sources {
		if attachment.slaac.sources[i].address == address && inst.ownsSlaacNetif(&attachment.slaac.sources[i]) {
			return true
		}
	}
	return false
}

func (inst *Instance) releaseOwnedSlaac() {
	attachment := inst.ownedAttachment
	if attachment == nil || attachment.slaac == nil {
		return
	}
	state := attachment.slaac
	state.updating = true
	for i := range state.sources {
		if state.sources[i].assigned {
			if err := inst.retireOwnedSlaac(&state.sources[i], state); err != nil && !errors.Is(err, goterrors.ErrNotFound) {
				inst.logOwnedControlError(err)
			}
		}
	}
	state.updating = false
	inst.slaacManager.Disable()
	if inst.ifConfigUp {
		inst.slaacManager.Enable()
	}
}
