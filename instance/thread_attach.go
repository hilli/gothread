// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/link"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// ThreadAttachProfile explicitly selects a bounded owned software role contract.
type ThreadAttachProfile uint8

const (
	// ThreadAttachAwakeMTD preserves the original owned minimal-device profile.
	ThreadAttachAwakeMTD ThreadAttachProfile = iota
	// ThreadAttachAwakeFTDChild explicitly selects an always-awake full-data
	// child with RouterEligible=false, not router/leader or native readiness.
	ThreadAttachAwakeFTDChild
)

// ThreadAttachConfig selects an explicit profile rather than guessed mode bits.
type ThreadAttachConfig struct {
	Timeout time.Duration
	Profile ThreadAttachProfile
}

// ThreadAttachResult owns one terminal observation, not an upstream reachability proof.
type ThreadAttachResult struct {
	Err                  error
	Role                 mle.DeviceRole
	RLOC16, ParentRLOC16 uint16
	ParentExtAddress     types.ExtAddress
	ParentVersion        uint16
	Addresses            []ip6.UnicastAddress
	Profile              ThreadAttachProfile
	NetworkData          []byte
	NetworkDataVersion   uint8
	KeySequence          uint32
}

// ThreadAttachAttempt owns one bounded attach operation. Cancel is LOOP-ONLY;
// external callers use Do. Read Result outside the loop without another Do.
type ThreadAttachAttempt struct {
	inst                          *Instance
	attachment                    *ownedThreadAttachment
	result                        chan ThreadAttachResult
	done                          bool
	cancelDeadline                func()
	epoch                         uint64
	networkKey                    [16]byte
	prefix                        [8]byte
	identity                      types.ExtAddress
	pan                           types.PanID
	addresses                     []ip6.Address
	parentAuthenticated           bool
	parentExt                     types.ExtAddress
	parentRLOC                    uint16
	parentVersion                 uint16
	parentCounter, parentSequence uint32
	profile                       ThreadAttachProfile
	channel                       uint8
	deadlineAt                    time.Time
}

type ownedThreadAttachment struct {
	slaac                           *ownedSlaacState
	epoch                           uint64
	networkKey                      [16]byte
	pan                             types.PanID
	channel                         uint8
	identity                        types.ExtAddress
	parentExt                       types.ExtAddress
	rloc, parentRLOC, parentVersion uint16
	prefix                          [8]byte
	addresses                       []ip6.Address
	profile                         ThreadAttachProfile
	networkData                     []byte
	networkDataVersion              uint8
}

// BeginThreadAttach admits a real always-awake MTD attachment. Requires an up
// interface, durable Settings, qualified Entropy, complete active dataset and
// a caller-owned valid non-RLOC mesh-local EID assignment. It never generates
// an EID/OMR, restores a Settings snapshot, or equates ThreadStart with success.
func (inst *Instance) BeginThreadAttach(timeout time.Duration) (*ThreadAttachAttempt, error) {
	return inst.BeginThreadAttachWithConfig(ThreadAttachConfig{Timeout: timeout, Profile: ThreadAttachAwakeMTD})
}

// BeginThreadAttachWithConfig admits an explicitly selected owned profile.
// FTD-child is opt-in and uses the same checked attach engine as MTD; neither
// admission nor a Child result establishes BBR, EID return-path or native readiness.
func (inst *Instance) BeginThreadAttachWithConfig(config ThreadAttachConfig) (*ThreadAttachAttempt, error) {
	if inst.nativeDiscovery != nil {
		return nil, goterrors.ErrBusy
	}
	return inst.beginThreadAttach(config)
}

// Both public profiles share these prerequisites and the actual wire engine.
func (inst *Instance) beginThreadAttach(config ThreadAttachConfig) (*ThreadAttachAttempt, error) {
	if err := inst.requireNativeSecurity(); err != nil {
		return nil, err
	}
	if config.Timeout <= 0 {
		return nil, goterrors.ErrInvalidArgs
	}
	if _, err := config.Profile.Resources(); err != nil {
		return nil, err
	}
	if !inst.IsRunning() || !inst.ifConfigUp || inst.threadEnabled || inst.threadAttach != nil ||
		inst.platSettings == nil || inst.entropy == nil || inst.platRadio == nil ||
		!inst.mac.IsEnabled() || inst.subMac.GetTransmitFrame() == nil ||
		inst.mleService.Mle().Role() != mle.RoleDisabled {
		return nil, goterrors.ErrInvalidState
	}
	if err := inst.PersistenceError(); err != nil {
		return nil, err
	}
	if inst.subMac.IsTransmittingOrScanning() {
		return nil, goterrors.ErrBusy
	}
	mode := inst.mleService.Mle().GetDeviceMode()
	if !inst.subMac.GetRxOnWhenIdle() || (config.Profile == ThreadAttachAwakeMTD && !mode.IsMinimalEndDevice()) {
		return nil, goterrors.ErrNotCapable
	}
	dataset, err := inst.activeDataset.Read()
	if err != nil {
		return nil, err
	}
	if err := inst.ValidateOperationalDataset(dataset.Bytes(), meshcop.DatasetActive); err != nil {
		return nil, err
	}
	info := dataset.ConvertToInfo()
	identity := inst.GetExtAddress()
	if identity == (types.ExtAddress{}) || identity.IsGroup() {
		return nil, goterrors.ErrSecurity
	}
	var addresses []ip6.Address
	hasEID := false
	for _, assigned := range inst.netif.GetUnicastAddresses() {
		if !assigned.Valid || assigned.Address.IsLinkLocal() || !udpUnicastAddress(assigned.Address) ||
			assigned.RLOC || assigned.Address.IsRoutingLocator() || assigned.Address.IsIidReserved() {
			continue
		}
		if len(addresses) == 8 {
			return nil, goterrors.ErrNoBufs
		}
		addresses = append(addresses, assigned.Address)
		if assigned.Address.GetPrefix() == ip6.NetworkPrefix(info.MeshLocalPrefix) {
			hasEID = true
		}
	}
	if !hasEID {
		return nil, goterrors.ErrInvalidSourceAddress
	}
	var challenge mle.Challenge
	if _, err := (nativeEntropyReader{inst: inst}).Read(challenge[:]); err != nil {
		return nil, err
	}
	attempt := &ThreadAttachAttempt{
		inst: inst, result: make(chan ThreadAttachResult, 1),
		networkKey: info.NetworkKey, prefix: info.MeshLocalPrefix,
		identity: identity, pan: types.PanID(info.PanID), addresses: addresses,
		profile: config.Profile,
		channel: uint8(info.Channel),
	}
	if err := inst.SecurityError(); err != nil {
		return nil, err
	}
	if config.Profile == ThreadAttachAwakeFTDChild {
		inst.mleService.Mle().SetDeviceMode(mle.NewDeviceMode(mle.ModeRxOnWhenIdle | mle.ModeFullThreadDevice | mle.ModeFullNetworkData))
	}
	inst.mleService.Mle().SetRouterEligible(false)
	inst.threadAttach = attempt
	registration := addresses
	if config.Profile == ThreadAttachAwakeFTDChild {
		registration = nil // FTD children consume full Network Data; they do not use MTD address registration.
	}
	if err := inst.mleService.Attacher.SetAddressRegistration(registration); err != nil {
		inst.threadAttach = nil
		return nil, err
	}
	if err := inst.startThread(&challenge); err != nil {
		inst.threadAttach = nil
		_ = inst.mleService.Attacher.SetAddressRegistration(nil)
		return nil, err
	}
	attempt.epoch = inst.threadEpoch
	attempt.deadlineAt = inst.timers.nowTime().Add(config.Timeout)
	attempt.cancelDeadline = inst.timers.scheduleWithCancel(config.Timeout, func() {
		if inst.threadAttach == attempt && !attempt.done && inst.threadEpoch == attempt.epoch {
			if err := inst.SecurityError(); err != nil {
				inst.failThreadAttach(err)
			} else {
				inst.failThreadAttach(context.DeadlineExceeded)
			}
		}
	})
	return attempt, nil
}

// Result contains exactly one owned terminal result, then closes. The bounded
// channel never blocks the Instance even if the caller abandons the operation.
func (attempt *ThreadAttachAttempt) Result() <-chan ThreadAttachResult { return attempt.result }

// Cancel explicitly cancels a still-pending attach. Cancelling a Do context
// after admission does not call this method. A completed attempt is unchanged.
func (attempt *ThreadAttachAttempt) Cancel() error {
	if !attempt.done && attempt.inst.threadAttach == attempt {
		attempt.inst.failThreadAttach(context.Canceled)
	}
	return nil
}

func (inst *Instance) finishThreadAttach(result *ThreadAttachResult) {
	attempt := inst.threadAttach
	if attempt == nil || attempt.done {
		return
	}
	attempt.done = true
	if attempt.cancelDeadline != nil {
		attempt.cancelDeadline()
	}
	inst.threadAttach = nil
	result.Profile = attempt.profile
	result.KeySequence = inst.keyManager.GetCurrentKeySequence()
	if result.Err == nil {
		result.Err = inst.SecurityError()
	}
	if result.Err == nil && result.Role == mle.RoleChild && inst.ownedAttachment != nil &&
		inst.ownedAttachment.epoch == attempt.epoch && inst.ownedAttachment.profile == attempt.profile {
		attempt.attachment = inst.ownedAttachment
	}
	result.Addresses = append([]ip6.UnicastAddress(nil), result.Addresses...)
	result.NetworkData = append([]byte(nil), result.NetworkData...)
	attempt.result <- *result
	close(attempt.result)
	_ = inst.mleService.Attacher.SetAddressRegistration(nil)
}

func (inst *Instance) failThreadAttach(cause error) {
	inst.failSourceLifetimes(inst.ownedAttachment, ThreadSourceBackendFailure, cause)
	inst.finishThreadAttach(&ThreadAttachResult{Err: cause, Role: inst.mleService.Mle().Role()})
	if inst.threadEnabled {
		_ = inst.ThreadStop()
	}
}

func (inst *Instance) wireOwnedAttachHandlers() {
	dispatcher := inst.mleService.Dispatcher()
	if err := dispatcher.SetInitialAttachKeyCandidatePolicy(inst.allowOwnedInitialKeyCandidate); err != nil {
		inst.restoreErr = errors.Join(inst.restoreErr, err)
	}
	if err := dispatcher.SetOwnedAttachReceiveValidator(inst.validateOwnedAttachMessage); err != nil {
		inst.restoreErr = errors.Join(inst.restoreErr, err)
	}
	dispatcher.RegisterHandler(mle.CommandParentResponse, func(info *mle.RxInfo) error {
		attempt := inst.threadAttach
		if attempt == nil {
			return inst.mleService.Attacher.HandleParentResponse(info)
		}
		if err := inst.SecurityError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if err := inst.PersistenceError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if !info.IsSecured || info.SrcAddr == (types.ExtAddress{}) || info.SrcAddr.IsGroup() ||
			info.SrcAddr == attempt.identity || info.SrcIP != linkLocalAddress(info.SrcAddr) ||
			info.DstIP != inst.GetLinkLocalAddress() || inst.threadEpoch != attempt.epoch ||
			inst.GetExtAddress() != attempt.identity || inst.mac.GetPanID() != attempt.pan ||
			inst.mac.GetPanChannel() != attempt.channel || inst.meshLocalPrefix != attempt.prefix ||
			inst.keyManager.GetNetworkKey() != attempt.networkKey {
			return goterrors.ErrDrop
		}
		if inst.mleService.Mle().GetAttachState() != mle.AttachStateParentRequest {
			return goterrors.ErrDrop
		}
		sourceValue, present := mle.FindTLV(info.TLVs, mle.TLVSourceAddress)
		router, parseErr := mle.ReadSourceAddressTLV(sourceValue)
		if !present || parseErr != nil || router >= 0xfc00 || router&0x03ff != 0 {
			return goterrors.ErrDrop
		}
		versionValue, present := mle.FindTLV(info.TLVs, mle.TLVVersion)
		version, parseErr := mle.ReadVersionTLV(versionValue)
		if !present || parseErr != nil || version == 0 {
			return goterrors.ErrDrop
		}
		if err := inst.mleService.Attacher.HandleParentResponse(info); err != nil {
			return err
		}
		candidate, exists := inst.mleService.Attacher.GetCandidate()
		if !exists || candidate.MacAddr != info.SrcAddr || candidate.RLOC16 >= 0xfc00 ||
			candidate.RLOC16&0x03ff != 0 || candidate.Version == 0 {
			return goterrors.ErrDrop
		}
		if attempt.profile == ThreadAttachAwakeFTDChild && version < 3 {
			inst.failThreadAttach(goterrors.ErrNotCapable)
			return goterrors.ErrNotCapable
		}
		// A full-sequence candidate becomes protocol identity only after
		// authenticated decryption, matching fresh challenge and parsed parent.
		// Persist before any Child ID TX; global reserved bounds never reset.
		if info.KeySequence > inst.keyManager.GetCurrentKeySequence() {
			inst.SetCurrentKeySequence(info.KeySequence, key.ForceUpdate|key.ResetGuardTimer)
			if err := inst.PersistenceError(); err != nil {
				inst.failThreadAttach(err)
				return err
			}
			if inst.keyManager.GetCurrentKeySequence() != info.KeySequence {
				inst.failThreadAttach(goterrors.ErrInvalidState)
				return goterrors.ErrInvalidState
			}
		}
		// Authenticated ParentResponse selected a router SourceAddress. Router
		// role implies FTD/always-on; Version comes from its actual Version TLV.
		candidate.Mode = mle.NewDeviceMode(mle.ModeRxOnWhenIdle | mle.ModeFullThreadDevice | mle.ModeFullNetworkData)
		attempt.parentAuthenticated = true
		attempt.parentExt, attempt.parentRLOC, attempt.parentVersion = candidate.MacAddr, candidate.RLOC16, candidate.Version
		attempt.parentCounter, attempt.parentSequence = info.FrameCounter, info.KeySequence
		return nil
	})
	dispatcher.RegisterHandler(mle.CommandChildIDResponse, func(info *mle.RxInfo) error {
		attempt := inst.threadAttach
		if attempt == nil {
			return inst.mleService.Attacher.HandleChildIDResponse(info)
		}

		if err := inst.SecurityError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if err := inst.PersistenceError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if !attempt.parentAuthenticated || !info.IsSecured || info.SrcAddr != attempt.parentExt ||
			info.SrcIP != linkLocalAddress(attempt.parentExt) || info.DstIP != inst.GetLinkLocalAddress() ||
			info.KeySequence != attempt.parentSequence || info.FrameCounter <= attempt.parentCounter ||
			inst.threadEpoch != attempt.epoch || inst.GetExtAddress() != attempt.identity ||
			inst.meshLocalPrefix != attempt.prefix || inst.keyManager.GetNetworkKey() != attempt.networkKey ||
			inst.mac.GetPanID() != attempt.pan || !inst.ifConfigUp || inst.validateOwnedProfile() != nil {
			return goterrors.ErrDrop
		}
		value, ok := mle.FindTLV(info.TLVs, mle.TLVSourceAddress)
		source, err := mle.ReadSourceAddressTLV(value)
		if !ok || err != nil || source != attempt.parentRLOC {
			return goterrors.ErrDrop
		}
		value, ok = mle.FindTLV(info.TLVs, mle.TLVAddress16)
		rloc, err := mle.ReadAddress16TLV(value)
		if !ok || err != nil || !mle.IsChildRLOC16(rloc) || rloc&0x0200 != 0 || rloc >= 0xfc00 {
			return goterrors.ErrDrop
		}
		for _, address := range attempt.addresses {
			valid := false
			for _, assigned := range inst.netif.GetUnicastAddresses() {
				if assigned.Address == address && assigned.Valid && !assigned.RLOC {
					valid = true
					break
				}
			}
			if !valid {
				return goterrors.ErrInvalidSourceAddress
			}
		}
		networkData, ok := mle.FindTLV(info.TLVs, mle.TLVNetworkData)
		if !ok {
			return goterrors.ErrParse
		}
		if err := validateOwnedNetworkData(networkData, 0); err != nil {
			return err
		}
		if attempt.profile == ThreadAttachAwakeFTDChild {
			if _, err := ownedSlaacPrefixes(networkData, attempt.prefix); err != nil {
				return err
			}
			if route, exists := mle.FindTLV(info.TLVs, mle.TLVRoute64); exists {
				if err := validateOwnedChildRoute(route, attempt.parentRLOC); err != nil {
					return err
				}
			}
		}
		if err := inst.mleService.Attacher.HandleChildIDResponse(info); err != nil {
			return err
		}
		if err := inst.SecurityError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if attempt.profile == ThreadAttachAwakeFTDChild {
			if route, exists := mle.FindTLV(info.TLVs, mle.TLVRoute64); exists {
				if err := inst.applyOwnedChildRoute(route, attempt.parentRLOC); err != nil {
					return err
				}
			}
		}
		parent := inst.mleService.Mle().GetParent()
		parent.Counters.MleFrameCounter = info.FrameCounter
		parent.KeySequence = info.KeySequence
		// These assignments come only from the actual authenticated response.
		inst.SetRLOC16(rloc)
		inst.mac.SetShortAddress(types.ShortAddress(rloc))
		inst.mac.SetParentShortAddress(types.ShortAddress(attempt.parentRLOC))
		var address ip6.UnicastAddress
		address.InitAsThreadOriginMeshLocal()
		address.Address, address.RLOC = inst.GetMeshLocalAddress(), true
		inst.netif.AddUnicastAddress(&address)
		inst.ownedAttachment = &ownedThreadAttachment{
			epoch: attempt.epoch, networkKey: attempt.networkKey, pan: attempt.pan, channel: attempt.channel,
			identity: attempt.identity, parentExt: attempt.parentExt,
			rloc: rloc, parentRLOC: attempt.parentRLOC, parentVersion: attempt.parentVersion,
			prefix: attempt.prefix, addresses: append([]ip6.Address(nil), attempt.addresses...),
			profile: attempt.profile, networkData: append([]byte(nil), networkData...),
			networkDataVersion: inst.mleService.Mle().GetLeaderData().DataVersion,
		}
		if err := inst.syncOwnedParentRouter(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		if attempt.profile == ThreadAttachAwakeFTDChild {
			prefixes, err := ownedSlaacPrefixes(networkData, attempt.prefix)
			if err != nil {
				inst.failThreadAttach(err)
				return err
			}
			// This authenticated CID accepted complete data for the new episode;
			// an earlier episode's retrieval request cannot fence its sources.
			inst.mleService.Mle().SetRetrieveNewNetworkData(false)
			if err := inst.syncOwnedSlaac(prefixes, ownedSlaacAcceptedData); err != nil {
				inst.failThreadAttach(err)
				return err
			}
			control, err := newOwnedTMFControl(inst)
			if err != nil {
				inst.failThreadAttach(err)
				return err
			}
			inst.ownedTMF = control
		}
		inst.notifier.signal(EventThreadRlocAdded | EventIPv6AddressAdded)
		addresses := make([]ip6.UnicastAddress, 0, len(attempt.addresses)+1)
		for _, selected := range attempt.addresses {
			for _, assigned := range inst.netif.GetUnicastAddresses() {
				if assigned.Address == selected && assigned.Valid && !assigned.RLOC {
					addresses = append(addresses, assigned)
					break
				}
			}
		}
		addresses = append(addresses, address)
		if state := inst.ownedAttachment.slaac; state != nil {
			for i := range state.sources {
				record := &state.sources[i]
				if !inst.ownsSlaacNetif(record) {
					continue
				}
				for _, assigned := range inst.netif.GetUnicastAddresses() {
					if assigned.Address == record.address {
						addresses = append(addresses, assigned)
						break
					}
				}
			}
		}
		if err := inst.SecurityError(); err != nil {
			inst.failThreadAttach(err)
			return err
		}
		inst.finishThreadAttach(&ThreadAttachResult{
			Role: mle.RoleChild, RLOC16: rloc, ParentRLOC16: attempt.parentRLOC,
			ParentExtAddress: attempt.parentExt, ParentVersion: attempt.parentVersion,
			Addresses: addresses,
			Profile:   attempt.profile, NetworkData: networkData,
			NetworkDataVersion: inst.mleService.Mle().GetLeaderData().DataVersion,
		})
		return nil
	})
}

func (inst *Instance) releaseOwnedAttachment() {
	if inst.ownedAttachment != nil {
		inst.failSourceLifetimes(inst.ownedAttachment, ThreadSourceStopped, goterrors.ErrInvalidState)
	}
	if inst.siteGroups != nil {
		inst.siteGroups.stop(goterrors.ErrAbort)
		inst.siteGroups = nil
	}
	if inst.ownedTMF != nil {
		inst.ownedTMF.stop(goterrors.ErrAbort)
		inst.ownedTMF = nil
	}
	inst.releaseOwnedSlaac()
	for _, expected := range inst.expectedMLE {
		inst.retireExpectedMLE(expected)
	}
	inst.releaseOwnedControlPeers()
	if inst.ownedAttachment == nil {
		return
	}
	for _, address := range append([]ip6.UnicastAddress(nil), inst.netif.GetUnicastAddresses()...) {
		if address.Origin == ip6.OriginThread && address.RLOC {
			inst.netif.RemoveUnicastAddress(&address)
		}
	}
	inst.ownedAttachment = nil
	inst.SetRLOC16(mle.InvalidRLOC16)
	inst.mac.SetShortAddress(types.ShortAddress(mle.InvalidRLOC16))
	inst.notifier.signal(EventThreadRlocRemoved | EventIPv6AddressRemoved)
}

func (inst *Instance) handleMLEReceive(payload []byte, metadata ip6.MessageInfo) {
	if inst.SecurityError() != nil {
		return
	}
	if err := inst.validateOwnedProfile(); err != nil {
		inst.failThreadAttach(err)
		return
	}
	var identity types.ExtAddress
	var margin uint8
	if metadata.LinkInfo != nil {
		identity = metadata.LinkInfo.SrcExtAddr
		margin = link.ComputeLinkMargin(inst.subMac.GetNoiseFloor(), metadata.LinkInfo.RSSI)
	}
	err := inst.mleService.HandleReceive(payload, identity, metadata.PeerAddr, metadata.SockAddr, margin)
	if err != nil {
		if inst.logger != nil && !errors.Is(err, goterrors.ErrDrop) {
			inst.logger.Log(platform.LogLevelWarn, platform.LogRegionMLE, "MLE receive rejected: "+err.Error())
		}
		return
	}
	if inst.ownedAttachment != nil {
		if err := inst.PersistenceError(); err != nil {
			inst.failThreadAttach(err)
			return
		}
	}
	if inst.ownedAttachment != nil && unsecuredDiscoveryPayload(payload) {
		return // Stateless discovery cannot drive parent observation or follow-on security work.
	}
	if err := inst.observeAuthenticatedParent(payload, identity); err != nil {
		inst.failThreadAttach(err)
		return
	}
	inst.scheduleAttachTimer()
	if m := inst.mleService.Mle(); m.IsDataRequestPending() && m.IsChild() {
		m.SetDataRequestPending(false)
		if err := inst.mleService.ChildHandlers.SendDataRequest(); err != nil && inst.logger != nil {
			inst.logger.Log(platform.LogLevelWarn, platform.LogRegionMLE, "MLE data request failed: "+err.Error())
		}
	}
}

func (inst *Instance) queueOwnedMLE(payload []byte, metadata *ip6.MessageInfo) {
	if len(payload) > 1232 || metadata.HopLimit != mle.ControlHopLimit {
		return
	}
	if inst.pendingOwnedMLE >= 2 {
		inst.deferMLEAdmissionFailure()
		return
	}
	owned, info := append([]byte(nil), payload...), *metadata
	if metadata.LinkInfo != nil {
		linkInfo := *metadata.LinkInfo
		info.LinkInfo = &linkInfo
	}
	epoch := inst.threadEpoch
	stop := inst.stopCh
	nativeLink := inst.receivedMLELink
	var quarantine *initialMLEFragment
	if candidate := inst.initialMLEFragment; candidate != nil && candidate.complete && !candidate.queued &&
		info.PeerAddr == linkLocalAddress(types.ExtAddress(candidate.key.Scope.Source)) &&
		info.SockAddr == linkLocalAddress(types.ExtAddress(candidate.key.Scope.Destination)) {
		quarantine = candidate
		candidate.queued = true
	}
	inst.pendingOwnedMLE++
	if !inst.postRadioMaintenance(func() {
		inst.pendingOwnedMLE--
		if quarantine != nil {
			defer func() {
				if inst.initialMLEFragment == quarantine {
					inst.retireInitialMLEFragment()
				}
			}()
			if inst.initialMLEFragment != quarantine || quarantine.state != inst.mleService.Mle().GetAttachState() ||
				!inst.timers.nowTime().Before(quarantine.until) {
				return
			}
		}
		select {
		case <-stop:
			return
		default:
		}
		if inst.threadEnabled && inst.threadEpoch == epoch {
			inst.activeMLEFragment = quarantine
			inst.activeMLELink = nativeLink
			inst.handleMLEReceive(owned, info)
			inst.activeMLEFragment = nil
			inst.activeMLELink = nativeMLELink{}
		}
	}) {
		inst.pendingOwnedMLE--
		if quarantine != nil {
			inst.retireInitialMLEFragment()
		}
		inst.deferMLEAdmissionFailure()
	}
}

func (inst *Instance) deferMLEAdmissionFailure() {
	if inst.mleAdmissionFailed {
		return
	}
	inst.mleAdmissionFailed = true
	epoch := inst.threadEpoch
	inst.deferRadioMaintenance(func() {
		inst.mleAdmissionFailed = false
		if inst.threadEpoch == epoch {
			inst.failThreadAttach(goterrors.ErrNoBufs)
		}
	})
}

func (inst *Instance) sendOwnedMLE(payload []byte, destination ip6.Address) error {
	if err := inst.validateOwnedProfile(); err != nil {
		return err
	}
	if !inst.ifConfigUp || !inst.threadEnabled || inst.mac == nil || !inst.mac.IsEnabled() {
		return goterrors.ErrInvalidState
	}
	info := ip6.MessageInfo{
		SockAddr: inst.GetLinkLocalAddress(), SockPort: mle.UDPPort,
		PeerAddr: destination, PeerPort: mle.UDPPort, HopLimit: mle.ControlHopLimit,
	}
	message := inst.newUDPMessage(payload, info)
	// Reference MLE uses no outer MAC security for ordinary control traffic:
	// its own EncMIC32/full key-source header authenticates bootstrap. Announce
	// is the explicit link-secured exception; never infer a full sequence from
	// an outer seven-bit MAC key index.
	wire, err := mle.ParseMessage(payload)
	if err != nil || wire.SecuritySuite != mle.SecuritySuiteEncMic32 ||
		wire.SecHeader.KeySource != inst.keyManager.GetCurrentKeySequence() {
		return goterrors.ErrParse
	}
	plain, err := wire.DecryptPayload(inst.keyManager.GetCurrentMleKey(), inst.GetExtAddress(), info.SockAddr, destination, wire.SecHeader.Marshal())
	if err != nil || len(plain) == 0 {
		return goterrors.ErrSecurity
	}
	if mle.Command(plain[0]) == mle.CommandAnnounce {
		return goterrors.ErrNotCapable // Requires the distinct reference MAC mode2 key/source/counter path.
	}
	records, err := mle.ParseTLVs(plain[1:])
	if err != nil {
		return err
	}
	message.Metadata.SecurityEnabled = false
	message.Metadata.Security = mesh.SecurityMaterial{}
	message.Metadata.UseSrcShort = false
	message.Metadata.UseDstShort = true
	message.MeshDest = 0xffff
	var controlPeer *ownedControlPeer
	var peerGeneration uint64
	if destination == ip6.MulticastLinkLocalAllRouters {
		message.AckRequired = false
	} else {
		var parent types.ExtAddress
		var rloc uint16
		if attempt := inst.threadAttach; attempt != nil && attempt.parentAuthenticated {
			parent, rloc = attempt.parentExt, attempt.parentRLOC
		} else if attachment := inst.ownedAttachment; attachment != nil {
			parent, rloc = attachment.parentExt, attachment.parentRLOC
		}
		if parent == (types.ExtAddress{}) || destination != linkLocalAddress(parent) {
			for _, peer := range inst.ownedControlPeers {
				if peer == nil || peer.epoch != inst.threadEpoch || destination != linkLocalAddress(peer.router.MacAddr) {
					continue
				}
				command := mle.Command(plain[0])
				if command == mle.CommandLinkRequest && peer.admitting ||
					command == mle.CommandLinkAccept && peer.awaiting && peer.router.IsStateValid() {
					controlPeer, peerGeneration = peer, peer.generation
					parent, rloc = peer.router.MacAddr, peer.router.RLOC16
				}
				break
			}
			if controlPeer == nil {
				return goterrors.ErrNoRoute
			}
		}
		message.MeshDest = rloc
		message.Metadata.UseDstShort = false
		message.Metadata.DstExtAddr = parent
	}
	epoch, identity, stop := inst.threadEpoch, inst.GetExtAddress(), inst.stopCh
	pan, networkKey := inst.subMac.GetPanID(), inst.keyManager.GetNetworkKey()
	message.ValidateFrame = func() error {
		if err := inst.SecurityError(); err != nil {
			return err
		}
		if err := inst.validateOwnedProfile(); err != nil {
			return err
		}
		select {
		case <-stop:
			return goterrors.ErrAbort
		default:
		}
		if inst.threadEpoch != epoch || !inst.threadEnabled || !inst.ifConfigUp ||
			inst.subMac.GetExtAddress() != identity || inst.subMac.GetPanID() != pan ||
			inst.keyManager.GetNetworkKey() != networkKey {
			return goterrors.ErrAbort
		}
		if controlPeer != nil && (inst.ownedPeerByRLOC(controlPeer.router.RLOC16) != controlPeer || controlPeer.generation != peerGeneration) {
			return goterrors.ErrAbort
		}
		return nil
	}
	message.Priority = uint8(mesh.PriorityNet)
	if err := inst.sendViaForwarder(message); err != nil {
		return err
	}
	inst.armExpectedMLE(mle.Command(plain[0]), records)
	if controlPeer != nil && mle.Command(plain[0]) == mle.CommandLinkRequest {
		inst.armOwnedLinkResponse(controlPeer)
	}
	return nil
}

func (inst *Instance) handleOwnedAddressChange(info ip6.AddressInfo, event ip6.AddressEvent) {
	if event == ip6.AddressAdded {
		inst.notifier.signal(EventIPv6AddressAdded)
		return
	}
	inst.notifier.signal(EventIPv6AddressRemoved)
	attachment, epoch := inst.ownedAttachment, inst.threadEpoch
	if attachment == nil {
		return
	}
	if state := attachment.slaac; state != nil && !state.updating {
		for i := range state.sources {
			record := &state.sources[i]
			if record.assigned && record.address == info.Address {
				inst.failSourceLifetime(ownedSourceProof{attachment: attachment, source: record.address, generation: record.generation},
					ThreadSourceManualRemoval, goterrors.ErrInvalidSourceAddress)
				record.assigned = false
				if _, err := state.advance(); err != nil {
					inst.logOwnedControlError(err)
				}
				break
			}
		}
	}
	for _, address := range attachment.addresses {
		if address != info.Address {
			continue
		}
		inst.deferRadioMaintenance(func() {
			if inst.ownedAttachment == attachment && inst.threadEpoch == epoch && inst.threadEnabled {
				_ = inst.ThreadStop()
			}
		})
		break
	}
}
