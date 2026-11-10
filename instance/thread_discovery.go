// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"context"
	"errors"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/mac"
	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/meshcop"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/discover"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

// ThreadDiscoveryConfig controls discovery only, never selection/attachment.
type ThreadDiscoveryConfig struct {
	ChannelMask uint32
	// Nil scans all PANs; a pointer also permits an explicit PAN0 filter.
	PanID           *uint16
	JoinerFlag      bool
	ChannelDuration time.Duration
	Timeout         time.Duration
}

// ThreadDiscoveryAttempt is loop-owned. Read Result outside the loop; Cancel
// and RetryCleanup are loop-only. CleanupStopped is the serialized stopped-only
// exception. A terminal error need not release ownership.
type ThreadDiscoveryAttempt struct {
	inst   *Instance
	owner  *nativeDiscovery
	id     uint64
	done   bool
	result chan discover.ScanOutcome
}

// Result contains exactly one owned terminal outcome and then closes.
func (attempt *ThreadDiscoveryAttempt) Result() <-chan discover.ScanOutcome { return attempt.result }

// Cancel requests loop-owned cancellation. Read Result for cleanup failure.
func (attempt *ThreadDiscoveryAttempt) Cancel() error {
	if attempt == nil || attempt.inst == nil {
		return goterrors.ErrInvalidArgs
	}
	if attempt.done {
		return nil
	}
	attempt.inst.discoveryScanner.Cancel(attempt.id, context.Canceled)
	return nil
}

// RetryCleanup explicitly retries retained cleanup without another terminal.
func (attempt *ThreadDiscoveryAttempt) RetryCleanup() error {
	if attempt == nil || attempt.inst == nil {
		return goterrors.ErrInvalidArgs
	}
	return attempt.inst.discoveryScanner.RetryCleanup(attempt.id)
}

// CleanupStopped restores only this retained discovery radio owner after Stop
// has completed. It starts no event loop and never bypasses normal Start/Do
// health/persistence gates. Unlike RetryCleanup, call it outside the loop.
func (attempt *ThreadDiscoveryAttempt) CleanupStopped() error {
	if attempt == nil || attempt.inst == nil || attempt.owner == nil {
		return goterrors.ErrInvalidArgs
	}
	inst := attempt.inst
	inst.runningMu.Lock()
	if inst.discoveryCleanupOnly {
		inst.runningMu.Unlock()
		return goterrors.ErrBusy
	}
	if inst.running || inst.stopping {
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	select {
	case <-inst.doneCh:
	default:
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	owner := attempt.owner
	if !attempt.done || inst.nativeDiscovery != owner || owner.id != attempt.id || !owner.terminal || owner.lease == nil {
		inst.runningMu.Unlock()
		return goterrors.ErrInvalidState
	}
	inst.discoveryCleanupOnly = true
	inst.runningMu.Unlock()
	defer func() {
		inst.runningMu.Lock()
		inst.discoveryCleanupOnly = false
		inst.runningMu.Unlock()
	}()
	// No queued task, timer, notifier, arbitrary operation or health check is
	// executed here. Failed latches remain failed after actual radio cleanup.
	return inst.discoveryScanner.RetryCleanup(attempt.id)
}

type nativeDiscovery struct {
	inst           *Instance
	id             uint64
	lease          *mac.DiscoveryRadioLease
	identity       types.ExtAddress
	homePAN        uint16
	homeChannel    uint8
	homeState      submac.State
	epoch          uint64
	channel        uint16
	pan            uint16
	ticket         uint64
	submissionID   uint64
	transmitting   bool
	sending        bool
	restoring      bool
	terminal       bool
	pendingRX      int
	cancelDeadline func()
	timeout        time.Duration
}

// BeginThreadDiscovery is LOOP-ONLY. A consumer admits once with Instance.Do
// and awaits Result outside the loop. Nil means admitted, not scan success.
func (inst *Instance) BeginThreadDiscovery(config ThreadDiscoveryConfig) (*ThreadDiscoveryAttempt, error) {
	if inst.discoveryScanner == nil {
		return nil, goterrors.ErrNotCapable
	}
	if inst.nativeDiscovery != nil || inst.discoveryScanner.IsScanning() {
		return nil, goterrors.ErrBusy
	}
	mask, duration, timeout, err := inst.discoveryConfig(config)
	if err != nil {
		return nil, err
	}
	if err := inst.discoveryAdmission(); err != nil {
		return nil, err
	}
	attempt := &ThreadDiscoveryAttempt{inst: inst, result: make(chan discover.ScanOutcome, 1)}
	owner := &nativeDiscovery{inst: inst, timeout: timeout,
		identity: inst.subMac.GetExtAddress(), homePAN: inst.subMac.GetPanID(),
		homeChannel: inst.mac.GetPanChannelSnapshot(), epoch: inst.threadEpoch}
	attempt.owner = owner
	inst.nativeDiscovery = owner
	discover.WithScanDuration(uint32(duration / time.Millisecond))(inst.discoveryScanner)
	pan := uint16(discover.PanIDBroadcast)
	if config.PanID != nil {
		pan = *config.PanID
	}
	id, startErr := inst.discoveryScanner.DiscoverBounded(mask, pan, config.JoinerFlag, nil, func(outcome discover.ScanOutcome) {
		attempt.id, attempt.done = outcome.ID, true
		attempt.result <- outcome
		close(attempt.result)
	})
	if id == 0 {
		inst.nativeDiscovery = nil
		return nil, startErr
	}
	attempt.id, owner.id = id, id
	// An admitted synchronous send failure is already an explicit outcome.
	return attempt, nil
}

func (inst *Instance) discoveryConfig(config ThreadDiscoveryConfig) (mask uint32, duration, timeout time.Duration, err error) {
	if inst.platRadio == nil {
		return 0, 0, 0, goterrors.ErrNotCapable
	}
	supported := inst.platRadio.GetSupportedChannelMask() & 0x07fff800
	if supported == 0 {
		return 0, 0, 0, goterrors.ErrNotCapable
	}
	mask = config.ChannelMask
	if mask == 0 {
		mask = supported
	}
	if mask == 0 || mask&^supported != 0 {
		return 0, 0, 0, goterrors.ErrInvalidArgs
	}
	duration = config.ChannelDuration
	if duration == 0 {
		duration = time.Duration(discover.DefaultScanDuration) * time.Millisecond
	}
	if duration < time.Millisecond || duration > time.Second || duration%time.Millisecond != 0 {
		return 0, 0, 0, goterrors.ErrInvalidArgs
	}
	timeout = config.Timeout
	if timeout == 0 {
		timeout = 17 * time.Second
	}
	if timeout <= 0 || timeout > 20*time.Second {
		return 0, 0, 0, goterrors.ErrInvalidArgs
	}
	return mask, duration, timeout, nil
}

func (inst *Instance) discoveryAdmission() error {
	inst.runningMu.Lock()
	running := inst.running && !inst.stopping
	inst.runningMu.Unlock()
	if inst.threadAttach != nil {
		return goterrors.ErrBusy
	}
	if !running || !inst.ifConfigUp || inst.mac == nil || !inst.mac.IsEnabled() || inst.subMac == nil ||
		inst.platRadio == nil || !inst.platRadio.IsEnabled() {
		return goterrors.ErrInvalidState
	}
	if inst.mleService == nil || inst.mleService.DiscoveryHandler == nil {
		return goterrors.ErrNotCapable
	}
	if err := inst.SecurityError(); err != nil {
		return err
	}
	identity := inst.subMac.GetExtAddress()
	if identity == (types.ExtAddress{}) || identity.IsGroup() {
		return goterrors.ErrInvalidState
	}
	return nil
}

func (owner *nativeDiscovery) validate() error {
	if owner.inst.nativeDiscovery != owner || owner.terminal || owner.restoring ||
		owner.inst.threadEpoch != owner.epoch || owner.inst.subMac.GetExtAddress() != owner.identity ||
		owner.inst.subMac.GetPanID() != owner.homePAN || owner.inst.mac.GetPanChannelSnapshot() != owner.homeChannel {
		return goterrors.ErrAbort
	}
	return owner.inst.discoveryAdmission()
}

func (inst *Instance) startDiscoveryChannel(channel, pan uint16, joiner bool) error {
	owner := inst.nativeDiscovery
	if owner == nil {
		// Legacy Scanner consumers receive the same real backend, not a no-op.
		if err := inst.discoveryAdmission(); err != nil {
			return err
		}
		owner = &nativeDiscovery{inst: inst, timeout: 17 * time.Second, identity: inst.subMac.GetExtAddress(),
			homePAN: inst.subMac.GetPanID(), homeChannel: inst.mac.GetPanChannelSnapshot(), epoch: inst.threadEpoch}
		inst.nativeDiscovery = owner
	}
	owner.id = inst.discoveryScanner.Identity()
	if err := owner.validate(); err != nil {
		return err
	}
	if channel < 11 || channel > 26 || inst.platRadio.GetSupportedChannelMask()&(1<<channel) == 0 {
		return goterrors.ErrInvalidArgs
	}
	if owner.transmitting {
		return goterrors.ErrBusy
	}
	if owner.lease == nil {
		state := inst.subMac.GetState()
		if state == submac.StateReceive && inst.platRadio.GetState() != radio.StateReceive ||
			state == submac.StateSleep && inst.platRadio.GetState() != radio.StateSleep {
			return goterrors.ErrInvalidState
		}
		lease, err := inst.mac.AcquireDiscoveryRadio()
		if err != nil {
			return err
		}
		owner.lease = lease
		owner.homeState = state
		owner.cancelDeadline = inst.timers.scheduleWithCancel(owner.timeout, func() {
			if inst.nativeDiscovery == owner {
				inst.discoveryScanner.Fail(owner.id, context.DeadlineExceeded)
			}
		})
	}
	owner.channel, owner.pan = channel, pan
	owner.ticket++
	inst.platRadio.SetPanID(pan) // Radio's legacy void setter contract; not physical readback.
	if err := inst.subMac.Receive(uint8(channel)); err != nil {
		return err
	}
	owner.sending = true
	defer func() { owner.sending = false }()
	return inst.mleService.DiscoveryHandler.SendDiscoveryRequest(joiner)
}

// Only the live sender invocation may enter this private plaintext seam.
func (inst *Instance) sendDiscoveryMLE(payload []byte, destination ip6.Address) error {
	owner := inst.nativeDiscovery
	if owner == nil || !owner.sending || owner.lease == nil || owner.transmitting || destination != mle.LinkLocalAllNodesMulticast {
		return goterrors.ErrInvalidState
	}
	if err := owner.validate(); err != nil {
		return err
	}
	wire, err := mle.ParseMessage(payload)
	if err != nil || wire.SecuritySuite != mle.SecuritySuiteNone || len(wire.Payload) == 0 ||
		mle.Command(wire.Payload[0]) != mle.CommandDiscoveryRequest {
		return goterrors.ErrParse
	}
	records, err := mle.ParseTLVs(wire.Payload[1:])
	if err != nil || len(records) != 1 || records[0].Type != mle.TLVDiscovery {
		return goterrors.ErrParse
	}
	request, err := mle.ReadDiscoveryTLV(records[0].Value)
	if err != nil || len(request) != 4 || request[0] != byte(meshcop.TLVDiscoveryRequest) || request[1] != 2 ||
		request[2]&0xf0 != byte(mle.ThreadVersion)<<4 || request[2]&7 != 0 || request[3] != 0 {
		return goterrors.ErrParse
	}
	metadata := mesh.BuildUDPMetadata(inst.GetLinkLocalAddress(), destination, mle.UDPPort, mle.UDPPort, mle.ControlHopLimit)
	metadata.SrcExtAddr = owner.identity
	metadata.UseSrcShort, metadata.UseDstShort = false, true
	metadata.PanId = owner.pan
	message := mesh.NewTxMessageWithMetadata(payload, 0xffff, 0xfffe, metadata)
	message.AckRequired = false
	packet, err := mesh.BuildTxFrame(message, inst.macSeqNum)
	if err != nil {
		return err
	}
	frame := inst.subMac.GetTransmitFrame()
	if frame == nil {
		return goterrors.ErrNotCapable
	}
	frame.PSDU, frame.Channel = packet, uint8(owner.channel)
	frame.TxInfo = &radio.TxInfo{RxChannelAfterTx: uint8(owner.channel)}
	inst.macSeqNum++
	ticket := owner.ticket
	owner.transmitting, owner.submissionID = true, 0
	err = inst.subMac.Send(submac.TxRequest{Channel: uint8(owner.channel), CsmaCaEnabled: true,
		MaxCsmaBackoffs: 4, CheckReceiveAfterTx: true, BeforeTransmit: func() error {
			if owner.ticket != ticket {
				return goterrors.ErrAbort
			}
			return owner.validate()
		}})
	if err != nil {
		owner.transmitting = false
	}
	return err
}

// This private wrapper observes the actual owned Radio.Transmit snapshot, not
// a mutable GetTransmitBuffer identity. All other Radio methods are unchanged.
type discoveryRadioBridge struct {
	radio.Radio
	inst *Instance
}

func (bridge *discoveryRadioBridge) Receive(channel uint8) error {
	var err error
	if scope := bridge.inst.radioRestore; scope != nil {
		if !bridge.inst.validRadioRestore(scope) || scope.owner.state != submac.StateReceive ||
			channel != scope.owner.channel {
			return goterrors.ErrInvalidState
		}
		err = scope.restorer.RestoreReceive(channel)
	} else {
		err = bridge.Radio.Receive(channel)
	}
	if err != nil {
		return err
	}
	if owner := bridge.inst.nativeDiscovery; (owner != nil && owner.lease != nil || bridge.inst.radioRestore != nil) &&
		bridge.GetState() != radio.StateReceive {
		return goterrors.ErrInvalidState
	}
	return nil
}
func (bridge *discoveryRadioBridge) Sleep() error {
	var err error
	if scope := bridge.inst.radioRestore; scope != nil {
		if !bridge.inst.validRadioRestore(scope) || scope.owner.state != submac.StateSleep {
			return goterrors.ErrInvalidState
		}
		err = scope.restorer.RestoreSleep()
	} else {
		err = bridge.Radio.Sleep()
	}
	if err != nil {
		return err
	}
	if owner := bridge.inst.nativeDiscovery; (owner != nil && owner.lease != nil || bridge.inst.radioRestore != nil) &&
		bridge.GetState() != radio.StateSleep {
		return goterrors.ErrInvalidState
	}
	return nil
}
func (bridge *discoveryRadioBridge) Transmit(frame *radio.Frame) error {
	if owner := bridge.inst.nativeDiscovery; owner != nil && owner.transmitting && owner.lease != nil {
		if frame == nil || frame.TxInfo == nil || frame.TxInfo.SubmissionID == 0 {
			return goterrors.ErrInvalidState
		}
		owner.submissionID = frame.TxInfo.SubmissionID
	}
	return bridge.Radio.Transmit(frame)
}

func (inst *Instance) discoveryTransmitDone(frame, _ *radio.Frame, cause error) bool {
	owner := inst.nativeDiscovery
	if owner == nil || !owner.transmitting {
		return false
	}
	// A pre-radio validator failure has no SubmissionID. The live unsubmitted
	// operation owns that error; accepted radio completions require exact ID.
	submission, ticket := owner.submissionID, owner.ticket
	if submission != 0 && (frame == nil || frame.TxInfo == nil || frame.TxInfo.SubmissionID != submission ||
		!inst.subMac.IsCurrentTransmitCompletion(frame)) {
		return true
	}
	if submission == 0 && cause == nil {
		return true
	}
	inst.deferRadioMaintenance(func() {
		if inst.nativeDiscovery != owner || owner.ticket != ticket || owner.submissionID != submission {
			return
		}
		owner.transmitting = false
		if owner.terminal {
			// Cancellation already reported retained in-flight ownership. Do
			// not invent a second terminal or silently discard its late error.
			if cause != nil {
				inst.logOwnedControlError(cause)
			}
			return
		}
		if cause != nil {
			inst.discoveryScanner.Fail(owner.id, cause)
		}
	})
	return true
}

func (inst *Instance) finishDiscovery(id uint64) error {
	owner := inst.nativeDiscovery
	if owner == nil {
		return nil
	}
	if owner.id != id {
		return goterrors.ErrInvalidState
	}
	owner.terminal, owner.restoring = true, true
	defer func() { owner.restoring = false }()
	if owner.cancelDeadline != nil {
		owner.cancelDeadline()
		owner.cancelDeadline = nil
	}
	if owner.lease == nil {
		inst.nativeDiscovery = nil
		return nil
	}
	if owner.transmitting || inst.subMac.IsTransmittingOrScanning() {
		return goterrors.ErrBusy
	}
	if inst.radioOwner.prepared && inst.radioOwner.discovery == owner {
		if scope := inst.radioRestore; scope == nil || !inst.validRadioRestore(scope) {
			return goterrors.ErrBusy
		}
	} else {
		inst.platRadio.SetPanID(owner.homePAN)
	}
	if owner.lease != nil {
		var err error
		if inst.discoveryCleanupOnly {
			err = owner.lease.RestoreStopped()
		} else {
			err = owner.lease.Restore()
		}
		if err != nil {
			return err
		}
		owner.lease = nil
	}
	inst.nativeDiscovery = nil
	return nil
}

func (inst *Instance) cancelDiscovery(cause error) error {
	if owner := inst.nativeDiscovery; owner != nil {
		inst.discoveryScanner.Cancel(owner.id, cause)
		if inst.nativeDiscovery != nil {
			return errors.Join(cause, inst.discoveryScanner.Err())
		}
	}
	return nil
}
