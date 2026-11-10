// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

func validateOwnedNetworkData(data []byte, depth int) error {
	if len(data) > 254 || depth > 1 {
		return goterrors.ErrParse
	}
	for offset := 0; offset < len(data); {
		kind, stable, length, err := netdata.ParseTLVHeader(data[offset:])
		if err != nil {
			return err
		}
		end := offset + netdata.TLVHeaderSize + int(length)
		if end > len(data) {
			return goterrors.ErrParse
		}
		value := data[offset+netdata.TLVHeaderSize : end]
		switch kind {
		case netdata.TLVTypeService:
			service, err := netdata.ParseServiceValue(value, stable)
			if err != nil {
				return err
			}
			if err := validateOwnedNetworkData(service.SubTLVsData, depth+1); err != nil {
				return err
			}
		case netdata.TLVTypePrefix:
			prefix, err := netdata.ParsePrefixValue(value, stable)
			if err != nil {
				return err
			}
			if err := validateOwnedNetworkData(prefix.SubTLVsData, depth+1); err != nil {
				return err
			}
		case netdata.TLVTypeServer:
			if _, err := netdata.ParseServerValue(value); err != nil {
				return err
			}
		case netdata.TLVTypeHasRoute:
			if len(value)%3 != 0 {
				return goterrors.ErrParse
			}
		case netdata.TLVTypeBorderRouter:
			if len(value)%4 != 0 {
				return goterrors.ErrParse
			}
		case netdata.TLVTypeContext:
			if _, err := netdata.ParseContextValue(value); err != nil {
				return err
			}
		}
		offset = end
	}
	return nil
}

func validateOwnedChildRoute(raw []byte, parent uint16) error {
	_, mask, entries, err := mle.ReadRoute64TLV(raw)
	if err != nil {
		return err
	}
	if mask.Contains(63) || int(mask.GetAllocatedCount()) != len(entries) ||
		!mask.Contains(uint8(parent>>10)) {
		return goterrors.ErrParse
	}
	return nil
}

func (inst *Instance) applyOwnedChildRoute(raw []byte, parent uint16) error {
	if err := validateOwnedChildRoute(raw, parent); err != nil {
		return err
	}
	sequence, mask, entries, err := mle.ReadRoute64TLV(raw)
	if err != nil {
		return err
	}
	inst.UpdateRouterIDSet(sequence, mask, uint32(inst.timers.nowTime().UnixMilli()))
	inst.UpdateRouterOnFtdChild(sequence, mask, entries, uint8(parent>>10))
	return nil
}

func (inst *Instance) validateOwnedProfile() error {
	var profile ThreadAttachProfile
	switch {
	case inst.threadAttach != nil:
		profile = inst.threadAttach.profile
	case inst.ownedAttachment != nil:
		profile = inst.ownedAttachment.profile
	default:
		return nil
	}
	m := inst.mleService.Mle()
	mode := m.GetDeviceMode()
	if !mode.IsRxOnWhenIdle() || !inst.subMac.GetRxOnWhenIdle() || m.IsRouterEligible() ||
		(m.Role() != mle.RoleDetached && m.Role() != mle.RoleChild) {
		return goterrors.ErrNotCapable
	}
	switch profile {
	case ThreadAttachAwakeMTD:
		if !mode.IsMinimalEndDevice() {
			return goterrors.ErrNotCapable
		}
	case ThreadAttachAwakeFTDChild:
		if !mode.IsFullThreadDevice() || !mode.IsFullNetworkData() {
			return goterrors.ErrNotCapable
		}
	default:
		return goterrors.ErrNotCapable
	}
	if inst.ownedAttachment != nil && !m.IsChild() {
		return goterrors.ErrDetached
	}
	if attachment := inst.ownedAttachment; attachment != nil {
		parent := m.GetParent()
		if attachment.epoch != inst.threadEpoch || inst.subMac.GetExtAddress() != attachment.identity ||
			inst.subMac.GetPanID() != uint16(attachment.pan) || inst.meshLocalPrefix != attachment.prefix ||
			inst.keyManager.GetNetworkKey() != attachment.networkKey || m.RLOC16() != attachment.rloc ||
			!parent.IsStateValid() || parent.MacAddr != attachment.parentExt || parent.RLOC16 != attachment.parentRLOC {
			return goterrors.ErrInvalidState
		}
	}
	return nil
}

func (inst *Instance) wireOwnedNetworkDataHandlers() {
	dispatcher := inst.mleService.Dispatcher()
	for _, entry := range []struct {
		command mle.Command
		handler mle.CommandHandler
	}{
		{mle.CommandDataResponse, inst.mleService.ChildHandlers.HandleDataResponse},
		{mle.CommandChildUpdateResponse, inst.mleService.ChildHandlers.HandleChildUpdateResponse},
	} {
		handler := entry.handler
		dispatcher.RegisterHandler(entry.command, func(info *mle.RxInfo) error {
			attachment := inst.ownedAttachment
			if attachment == nil {
				return handler(info)
			}
			if err := inst.validateOwnedProfile(); err != nil {
				return err
			}
			if !info.IsSecured || info.SrcAddr != attachment.parentExt ||
				info.SrcIP != linkLocalAddress(attachment.parentExt) ||
				info.DstIP != inst.GetLinkLocalAddress() {
				return goterrors.ErrDrop
			}
			networkData, hasData := mle.FindTLV(info.TLVs, mle.TLVNetworkData)
			if hasData {
				if err := validateOwnedNetworkData(networkData, 0); err != nil {
					return err
				}
				if attachment.profile == ThreadAttachAwakeFTDChild {
					if _, present := mle.FindTLV(info.TLVs, mle.TLVLeaderData); !present {
						return goterrors.ErrParse
					}
					if _, err := ownedSlaacPrefixes(networkData, attachment.prefix); err != nil {
						return err
					}
				}
			}
			route, hasRoute := mle.FindTLV(info.TLVs, mle.TLVRoute64)
			if hasRoute && attachment.profile == ThreadAttachAwakeFTDChild {
				if err := validateOwnedChildRoute(route, attachment.parentRLOC); err != nil {
					return err
				}
			}
			if err := handler(info); err != nil {
				return err
			}
			if err := inst.SecurityError(); err != nil {
				return err
			}
			if attachment.profile == ThreadAttachAwakeFTDChild &&
				(hasData || inst.mleService.Mle().NeedsNewNetworkData()) {
				if info.KeySequence > inst.keyManager.GetCurrentKeySequence() {
					inst.SetCurrentKeySequence(info.KeySequence, key.ForceUpdate|key.ResetGuardTimer)
				}
				if err := inst.PersistenceError(); err != nil {
					inst.failThreadAttach(err)
					return err
				}
				if inst.mleService.Mle().NeedsNewNetworkData() {
					// The existing child handler has not accepted this leader's
					// data yet. Retire old sources without minting from that frame.
					if err := inst.syncOwnedSlaac(nil, ownedSlaacInvalidatedData); err != nil {
						inst.failThreadAttach(err)
						return err
					}
					return goterrors.ErrInvalidState
				}
			}
			if slot := expectedMLESlot(info.Command); slot >= 0 {
				inst.retireExpectedMLE(inst.expectedMLE[slot])
			}
			if hasData {
				attachment.networkData = append(attachment.networkData[:0], networkData...)
				attachment.networkDataVersion = inst.mleService.Mle().GetLeaderData().DataVersion
				if attachment.profile == ThreadAttachAwakeFTDChild {
					prefixes, err := ownedSlaacPrefixes(networkData, attachment.prefix)
					if err != nil {
						return err
					}
					if err := inst.syncOwnedSlaac(prefixes, ownedSlaacAcceptedData); err != nil {
						inst.failThreadAttach(err)
						return err
					}
				}
				inst.notifier.signal(EventThreadNetDataChanged)
			}
			if hasRoute && attachment.profile == ThreadAttachAwakeFTDChild {
				return inst.applyOwnedChildRoute(route, attachment.parentRLOC)
			}
			return nil
		})
	}
}
