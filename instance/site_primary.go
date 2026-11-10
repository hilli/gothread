// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"encoding/binary"

	"github.com/hilli/gothread/backbone"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

type ownedPrimaryBBR struct {
	config                       netdata.BackboneRouterConfig
	serviceID                    uint8
	serviceALOC, unicast, source ip6.Address
	controlSource                ip6.Address
	parentExt                    [8]byte
	parentRLOC                   uint16
	epoch                        uint64
}

func meshLocator(prefix [8]byte, locator uint16) ip6.Address {
	var address ip6.Address
	copy(address[:8], prefix[:])
	address[11], address[12] = 0xff, 0xfe
	binary.BigEndian.PutUint16(address[14:16], locator)
	return address
}

// Selection uses only the full Network Data accepted from the actual parent.
// Public BbrLeader setters alone are not authorization for this native route.
func (inst *Instance) currentOwnedPrimaryBBR() (ownedPrimaryBBR, error) {
	var selected ownedPrimaryBBR
	attachment := inst.ownedAttachment
	if attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild || attachment.parentVersion < 3 {
		return selected, goterrors.ErrNotCapable
	}
	if err := inst.validateOwnedProfile(); err != nil {
		return selected, err
	}
	if err := inst.SecurityError(); err != nil {
		return selected, err
	}
	if err := inst.PersistenceError(); err != nil {
		return selected, err
	}
	if !inst.ifConfigUp || !inst.threadEnabled || !inst.hasOwnedRLOCAddress() || inst.mac.GetPanChannelSnapshot() != attachment.channel {
		return selected, goterrors.ErrInvalidState
	}
	if err := validateOwnedNetworkData(attachment.networkData, 0); err != nil {
		return selected, err
	}
	leaderID := inst.mleService.Mle().GetLeaderData().LeaderRouterID
	if leaderID >= 63 {
		return selected, goterrors.ErrParse
	}
	config, err := netdata.FindBackboneRouterPrimary(attachment.networkData, uint16(leaderID)<<10)
	if err != nil {
		return selected, err
	}
	if config.RLOC16 >= 0xfc00 || config.RLOC16&0x03ff != 0 ||
		config.MlrTimeout < backbone.MinMlrTimeout || config.MlrTimeout > backbone.MaxMlrTimeout {
		return selected, goterrors.ErrParse
	}
	if config.RLOC16 != attachment.parentRLOC {
		router := inst.routerTable.FindRouterByRLOC16(config.RLOC16)
		if router == nil || router.Cost == 0 || uint16(router.NextHop) != attachment.parentRLOC>>10 {
			return selected, goterrors.ErrNoRoute
		}
	}
	found := false
	for _, tlv := range netdata.ParseTLVs(attachment.networkData) {
		if tlv.Type != netdata.TLVTypeService {
			continue
		}
		service, err := netdata.ParseServiceValue(tlv.Value, tlv.Stable)
		if err != nil {
			return selected, err
		}
		if service.EnterpriseNumber != netdata.ThreadEnterpriseNumber || len(service.ServiceData) != 1 ||
			service.ServiceData[0] != netdata.ServiceNumberBackboneRouter {
			continue
		}
		if service.ServiceID > 15 {
			return selected, goterrors.ErrParse
		}
		for _, sub := range netdata.ParseTLVs(service.SubTLVsData) {
			if sub.Type != netdata.TLVTypeServer {
				continue
			}
			server, err := netdata.ParseServerValue(sub.Value)
			if err != nil {
				return selected, err
			}
			if server.Server16 != config.RLOC16 {
				continue
			}
			if len(server.ServerData) != 7 || server.ServerData[0] != config.SequenceNumber ||
				binary.BigEndian.Uint16(server.ServerData[1:3]) != config.ReregistrationDelay ||
				binary.BigEndian.Uint32(server.ServerData[3:7]) != config.MlrTimeout {
				return selected, goterrors.ErrParse
			}
			if found && selected.serviceID != service.ServiceID {
				return selected, goterrors.ErrParse
			}
			selected.serviceID = service.ServiceID
			found = true
		}
	}
	if !found {
		return selected, goterrors.ErrNotFound
	}
	for _, address := range attachment.addresses {
		if address.GetPrefix() == ip6.NetworkPrefix(attachment.prefix) && !address.IsIidReserved() && inst.hasNonLinkLocalUDPSource(address) {
			selected.source = address
			break
		}
	}
	if selected.source.IsUnspecified() {
		return selected, goterrors.ErrInvalidSourceAddress
	}
	prefix := ip6.NewPrefix([16]byte(meshLocator(attachment.prefix, 0)), 64)
	selected.config = config
	selected.serviceALOC = netdata.GetServiceAloc(prefix, selected.serviceID)
	selected.unicast = meshLocator(attachment.prefix, config.RLOC16)
	selected.controlSource = meshLocator(attachment.prefix, attachment.rloc)
	selected.parentExt = [8]byte(attachment.parentExt)
	selected.parentRLOC = attachment.parentRLOC
	selected.epoch = inst.threadEpoch
	return selected, nil
}

// This exact Primary-only reserved locator route does not relax SendUDP's
// general application guards or authorize the local node to forward packets.
func (inst *Instance) sendPrimaryMlrDatagram(payload []byte, proof *ownedPrimaryBBR) error {
	expected := *proof
	if attachment := inst.ownedAttachment; attachment == nil || inst.mac.GetPanChannel() != attachment.channel {
		return goterrors.ErrInvalidState
	}
	current, err := inst.currentOwnedPrimaryBBR()
	if err != nil {
		return err
	}
	if current != expected {
		return goterrors.ErrNoRoute
	}
	if len(payload) > 1232 {
		return goterrors.ErrNoBufs
	}
	message := inst.newUDPMessage(payload, ip6.MessageInfo{
		SockAddr: expected.controlSource, PeerAddr: expected.unicast, SockPort: backbone.BackboneUDPPort, PeerPort: backbone.BackboneUDPPort, HopLimit: 64,
	})
	message.MeshDest = expected.parentRLOC
	message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
	message.Metadata.DstExtAddr = expected.parentExt
	message.ValidateFrame = func() error {
		current, err := inst.currentOwnedPrimaryBBR()
		if err != nil {
			return err
		}
		if current != expected || inst.mleService.Mle().Role() != mle.RoleChild {
			return goterrors.ErrNoRoute
		}
		return nil
	}
	return inst.sendViaForwarder(message)
}
