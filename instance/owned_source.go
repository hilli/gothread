// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
)

type ownedSourceProof struct {
	attachment *ownedThreadAttachment
	source     ip6.Address
	generation uint64
}

// Pure current-assignment/owned-tuple check. Health and purpose-specific
// authorization remain with callers; no public Netif flag creates this proof.
func (inst *Instance) currentOwnedSource(source ip6.Address) (ownedSourceProof, error) {
	var proof ownedSourceProof
	attachment := inst.ownedAttachment
	if attachment == nil || !udpUnicastAddress(source) || source.IsLinkLocal() ||
		source.IsRoutingLocator() || source.IsIidReserved() {
		return proof, goterrors.ErrInvalidSourceAddress
	}
	if !inst.ifConfigUp || !inst.threadEnabled || inst.threadEpoch != attachment.epoch ||
		inst.rloc16 != attachment.rloc || uint16(inst.subMac.GetShortAddress()) != attachment.rloc ||
		inst.mac.GetPanChannelSnapshot() != attachment.channel || !inst.hasOwnedRLOCAddress() {
		return proof, goterrors.ErrInvalidState
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return proof, err
	}
	if source.GetPrefix() == ip6.NetworkPrefix(attachment.prefix) {
		for _, admitted := range attachment.addresses {
			if admitted != source {
				continue
			}
			for _, address := range inst.netif.GetUnicastAddresses() {
				if address.Address == source && address.Valid && !address.RLOC {
					return ownedSourceProof{attachment: attachment, source: source}, nil
				}
			}
		}
	}
	if state := attachment.slaac; state != nil && state.err != nil {
		return proof, state.err
	}
	if state := attachment.slaac; state != nil &&
		inst.slaacManager != nil && inst.slaacManager.IsEnabled() && !inst.mleService.Mle().NeedsNewNetworkData() {
		for i := range state.sources {
			record := &state.sources[i]
			if record.address == source && record.preferred && inst.ownsSlaacNetif(record) {
				return ownedSourceProof{attachment: attachment, source: source, generation: record.generation}, nil
			}
		}
	}
	return proof, goterrors.ErrInvalidSourceAddress
}

func (inst *Instance) ownedSourceRevision() uint64 {
	if inst.ownedAttachment != nil && inst.ownedAttachment.slaac != nil {
		return inst.ownedAttachment.slaac.revision
	}
	return 0
}
