// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hilli/gothread/backbone"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/bbr"
	"github.com/hilli/gothread/thread/mlr"
	"github.com/hilli/gothread/thread/tmf"
)

const maxOwnedSiteGroups = ip6.MaxReservedExternalMulticastAddresses

type ownedMlrBatch struct {
	proof          ownedPrimaryBBR
	addresses      [][16]byte
	token          [8]byte
	mid            uint16
	midSet         bool
	cancelDeadline func()
	leaseBase      time.Time
}

type ownedMlrClient struct {
	inst                   *Instance
	leader                 *backbone.Leader
	manager                *bbr.MlrManager
	engine                 *coap.Engine
	pending, receiving     *ownedMlrBatch
	cancelRetry            func()
	stopped                bool
	lastErr                error
	accepted               func([][16]byte, time.Time)
	invalidated            func()
	primary                ownedPrimaryBBR
	hasPrimary             bool
	pendingRx              bool
	mlrPaused              bool
	ownNotifications       [maxOwnedAddressNotifications]*ownedAddressNotification
	ownQueries             [maxOwnedQueryHistory]ownedQueryIdentity
	queryNext              int
	ownsRouterSubscription bool
	cancelControlTick      func()
	mpl                    *ip6.Mpl
	ownInput               *ownedQueryInput
}

func newOwnedMlrClient(inst *Instance) (*ownedMlrClient, error) {
	if inst.ownedTMF == nil || inst.ownedTMF.stopped {
		return nil, goterrors.ErrInvalidState
	}
	inst.ownedTMF.mlrPaused = false
	return inst.ownedTMF, nil
}

func (client *ownedMlrClient) updateLeader(proof *ownedPrimaryBBR) {
	client.leader.SetServiceID(proof.serviceID)
	client.leader.UpdatePrimary(&backbone.Config{Server16: proof.config.RLOC16, SequenceNumber: proof.config.SequenceNumber,
		ReregistrationDelay: proof.config.ReregistrationDelay, MlrTimeout: proof.config.MlrTimeout})
}

func (client *ownedMlrClient) send(data []byte, info coap.MessageInfo) error {
	if handled, err := client.sendOwnAddress(data, info); handled {
		return err
	}
	batch := client.pending
	if batch == nil {
		batch = client.receiving
	}
	if batch == nil || client.stopped {
		return goterrors.ErrAbort
	}
	if info.PeerAddr != [16]byte(batch.proof.unicast) || info.LocalAddr != [16]byte(batch.proof.controlSource) ||
		info.PeerPort != backbone.BackboneUDPPort {
		return goterrors.ErrNoRoute
	}
	message, err := coap.ParseMessage(data)
	if err != nil {
		return err
	}
	if message.GetCode() == coap.CodePost {
		if !bytes.Equal(message.GetToken(), batch.token[:]) {
			return goterrors.ErrDrop
		}
		if batch.midSet && message.GetMessageID() != batch.mid {
			return goterrors.ErrDrop
		}
		batch.mid, batch.midSet = message.GetMessageID(), true
	} else if message.GetType() != coap.TypeAck || message.GetCode() != coap.CodeEmpty || client.receiving != batch {
		return goterrors.ErrDrop
	}
	return client.inst.sendPrimaryMlrDatagram(data, &batch.proof)
}

func (client *ownedMlrClient) start() error {
	if client.stopped || client.mlrPaused {
		return goterrors.ErrInvalidState
	}
	if client.pending != nil {
		return goterrors.ErrBusy
	}
	proof, err := client.inst.currentOwnedPrimaryBBR()
	if err != nil {
		client.lastErr = err
		if client.hasPrimary {
			client.hasPrimary = false
			client.manager.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)
			if client.invalidated != nil {
				client.invalidated()
			}
		}
		return err
	}
	client.updateLeader(&proof)
	if client.hasPrimary && client.primary != proof {
		client.manager.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)
		if client.invalidated != nil {
			client.invalidated()
		}
	}
	client.primary, client.hasPrimary = proof, true
	if !client.manager.HasAddressesToRegister() {
		return nil
	}
	batch := &ownedMlrBatch{proof: proof}
	if _, err := io.ReadFull(nativeEntropyReader{client.inst}, batch.token[:]); err != nil {
		client.lastErr = err
		return err
	}
	batch.addresses = client.manager.UpdateRegistration()
	if len(batch.addresses) == 0 {
		return nil
	}
	if len(batch.addresses) > mlr.MaxAddresses {
		return client.preparationFailed(goterrors.ErrNoBufs)
	}
	message := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)
	if err := message.SetToken(batch.token[:]); err != nil {
		return client.preparationFailed(err)
	}
	if err := message.AppendURIPathOptions(tmf.UriPathMlr); err != nil {
		return client.preparationFailed(err)
	}
	payload := []byte{byte(tmf.ThreadTLVIPv6Addresses), byte(16 * len(batch.addresses))}
	for _, address := range batch.addresses {
		payload = append(payload, address[:]...)
	}
	if err := message.AppendPayloadMarker(); err != nil {
		return client.preparationFailed(err)
	}
	if err := message.AppendPayload(payload); err != nil {
		return client.preparationFailed(err)
	}
	// No Commissioner Session or Timeout TLV: only default-lease own MLR.
	client.pending = batch
	batch.leaseBase = client.inst.timers.nowTime()
	batch.cancelDeadline = client.inst.timers.scheduleWithCancel(2*time.Minute, func() { client.fail(batch, goterrors.ErrResponseTimeout) })
	info := coap.MessageInfo{PeerAddr: [16]byte(proof.unicast), LocalAddr: [16]byte(proof.controlSource), PeerPort: backbone.BackboneUDPPort}
	err = client.engine.SendMessage(message, info, nil, func(response *coap.Message, peer coap.MessageInfo, err error) {
		client.complete(batch, response, peer, err)
	})
	if err != nil {
		client.fail(batch, err)
	}
	return err
}

func (client *ownedMlrClient) fail(batch *ownedMlrBatch, cause error) {
	if client.pending != batch {
		return
	}
	client.pending = nil
	if batch.cancelDeadline != nil {
		batch.cancelDeadline()
	}
	client.lastErr = cause
	client.manager.HandleMlrResponse(bbr.MlrStatusGeneralFailure, nil)
	peer := coap.MessageInfo{PeerAddr: [16]byte(batch.proof.unicast), LocalAddr: [16]byte(batch.proof.controlSource), PeerPort: backbone.BackboneUDPPort}
	if err := client.engine.AbortRequest(batch.token[:], peer); err != nil && !errors.Is(err, goterrors.ErrNotFound) {
		client.inst.logOwnedControlError(err)
	}
	if !client.stopped && !client.mlrPaused {
		delay := time.Duration(batch.proof.config.ReregistrationDelay) * time.Second
		if delay < time.Second {
			delay = time.Second
		}
		if client.cancelRetry != nil {
			client.cancelRetry()
		}
		client.cancelRetry = client.inst.timers.scheduleWithCancel(delay, func() {
			client.cancelRetry = nil
			if err := client.start(); err != nil && !errors.Is(err, goterrors.ErrBusy) {
				client.inst.logOwnedControlError(err)
			}
		})
	}
}

func parseOwnedMlrResponse(payload []byte, pending [][16]byte) (status uint8, failed [][16]byte, err error) {
	hasStatus, hasFailed := false, false
	for offset := 0; offset < len(payload); {
		if len(payload)-offset < 2 {
			return 0, nil, goterrors.ErrParse
		}
		kind, length := payload[offset], int(payload[offset+1])
		offset += 2
		if length > len(payload)-offset {
			return 0, nil, goterrors.ErrParse
		}
		value := payload[offset : offset+length]
		offset += length
		switch kind {
		case byte(tmf.ThreadTLVStatus):
			if hasStatus || length != 1 {
				return 0, nil, goterrors.ErrParse
			}
			status, hasStatus = value[0], true
		case byte(tmf.ThreadTLVIPv6Addresses):
			if hasFailed || length == 0 || length%16 != 0 || length > 16*mlr.MaxAddresses {
				return 0, nil, goterrors.ErrParse
			}
			hasFailed = true
			for i := 0; i < length; i += 16 {
				var address [16]byte
				copy(address[:], value[i:i+16])
				known := false
				for _, candidate := range pending {
					if candidate == address {
						known = true
						break
					}
				}
				if !known {
					return 0, nil, goterrors.ErrParse
				}
				for _, duplicate := range failed {
					if duplicate == address {
						return 0, nil, goterrors.ErrParse
					}
				}
				failed = append(failed, address)
			}
		default:
			return 0, nil, goterrors.ErrParse
		}
	}
	if !hasStatus {
		return 0, nil, goterrors.ErrParse
	}
	switch status {
	case 0, 2, 3, 4, 5, 6:
	default:
		return 0, nil, goterrors.ErrParse
	}
	return status, failed, nil
}

func (client *ownedMlrClient) complete(batch *ownedMlrBatch, message *coap.Message, info coap.MessageInfo, cause error) {
	if client.pending != batch || client.stopped {
		return
	}
	if cause != nil {
		client.fail(batch, cause)
		return
	}
	if message == nil || message.GetCode() != coap.CodeChanged || !bytes.Equal(message.GetToken(), batch.token[:]) ||
		info.PeerAddr != [16]byte(batch.proof.unicast) || info.LocalAddr != [16]byte(batch.proof.controlSource) || info.PeerPort != backbone.BackboneUDPPort {
		client.fail(batch, goterrors.ErrParse)
		return
	}
	current, err := client.inst.currentOwnedPrimaryBBR()
	if err != nil {
		client.fail(batch, err)
		return
	}
	if current != batch.proof {
		client.fail(batch, goterrors.ErrNoRoute)
		return
	}
	status, failed, err := parseOwnedMlrResponse(message.GetPayload(), batch.addresses)
	if err != nil {
		client.fail(batch, err)
		return
	}
	client.pending = nil
	if batch.cancelDeadline != nil {
		batch.cancelDeadline()
	}
	client.manager.HandleMlrResponse(status, failed)
	if status == bbr.MlrStatusNotPrimary {
		client.manager.HandleBackboneRouterPrimaryUpdate(backbone.LeaderStateToTriggerRereg)
		client.hasPrimary = false
		if client.invalidated != nil {
			client.invalidated()
		}
	}
	client.lastErr = nil
	if status != bbr.MlrStatusSuccess {
		client.lastErr = fmt.Errorf("instance: MLR status %d", status)
	}
	if client.accepted != nil {
		var accepted [][16]byte
		registered := client.manager.GetRegisteredAddresses()
		for _, address := range batch.addresses {
			rejected := status != bbr.MlrStatusSuccess && len(failed) == 0
			for _, failure := range failed {
				if failure == address {
					rejected = true
					break
				}
			}
			currentlyRegistered := false
			for _, current := range registered {
				if current == address {
					currentlyRegistered = true
					break
				}
			}
			if !rejected && currentlyRegistered {
				accepted = append(accepted, address)
			}
		}
		client.accepted(accepted, batch.leaseBase.Add(time.Duration(batch.proof.config.MlrTimeout)*time.Second))
	}
	delay := time.Duration(0)
	if status != bbr.MlrStatusSuccess {
		delay = time.Duration(batch.proof.config.ReregistrationDelay) * time.Second
		if delay < time.Second {
			delay = time.Second
		}
	}
	if client.cancelRetry != nil {
		client.cancelRetry()
	}
	client.cancelRetry = client.inst.timers.scheduleWithCancel(delay, func() {
		client.cancelRetry = nil
		if !client.stopped {
			if err := client.start(); err != nil {
				client.inst.logOwnedControlError(err)
			}
		}
	})
}

// Called before the broad TMF receiver. A matching but unauthenticated packet is
// consumed/dropped, never handed to a second engine as a success-shaped fallback.
func (client *ownedMlrClient) receive(data []byte, info *ip6.MessageInfo) bool {
	if client.receiveOwnAddress(data, info) {
		return true
	}
	batch := client.pending
	if batch == nil {
		return false
	}
	message, err := coap.ParseMessage(data)
	if err != nil {
		return false
	}
	matches := bytes.Equal(message.GetToken(), batch.token[:]) ||
		message.GetType() == coap.TypeAck && message.GetMessageID() == batch.mid
	if !matches {
		return false
	}
	link := client.inst.receivedMLELink
	if client.inst.ownedAttachment == nil {
		return true
	}
	if !link.valid || !link.scope.Secured || !link.localUnicast ||
		link.scope.Source != batch.proof.parentExt || link.scope.PanID != uint16(client.inst.ownedAttachment.pan) ||
		link.scope.Channel != client.inst.ownedAttachment.channel ||
		info.PeerAddr != batch.proof.unicast || info.SockAddr != batch.proof.controlSource ||
		info.PeerPort != backbone.BackboneUDPPort || info.SockPort != backbone.BackboneUDPPort {
		client.inst.forwarder.RecordReceiveError(false)
		return true
	}
	if len(data) > 260 || client.pendingRx {
		client.inst.forwarder.RecordReceiveError(false)
		return true
	}
	owned := append([]byte(nil), data...)
	peer := coap.MessageInfo{PeerAddr: [16]byte(info.PeerAddr), LocalAddr: [16]byte(info.SockAddr), PeerPort: info.PeerPort}
	epoch := client.inst.threadEpoch
	client.pendingRx = true
	if !client.inst.postRadioMaintenance(func() {
		client.pendingRx = false
		if client.stopped || client.pending != batch || client.inst.threadEpoch != epoch {
			return
		}
		if err := client.inst.SecurityError(); err != nil {
			client.fail(batch, err)
			return
		}
		if err := client.inst.PersistenceError(); err != nil {
			client.fail(batch, err)
			return
		}
		client.receiving = batch
		client.engine.Receive(owned, peer)
		client.receiving = nil
	}) {
		client.pendingRx = false
		client.inst.forwarder.RecordReceiveError(false)
		client.inst.deferRadioMaintenance(func() { client.fail(batch, goterrors.ErrNoBufs) })
	}
	return true
}

func (client *ownedMlrClient) stop(cause error) {
	client.stopped = true
	client.stopMlr(cause)
	client.stopOwnAddresses(cause)
	if client.cancelControlTick != nil {
		client.cancelControlTick()
		client.cancelControlTick = nil
	}
	if client.ownsRouterSubscription {
		client.inst.netif.UnsubscribeAllRoutersMulticast()
		client.ownsRouterSubscription = false
	}
	client.engine.ClearAllRequestsAndResponses()
}

func (client *ownedMlrClient) stopMlr(cause error) {
	client.mlrPaused = true
	if client.cancelRetry != nil {
		client.cancelRetry()
		client.cancelRetry = nil
	}
	if batch := client.pending; batch != nil {
		client.fail(batch, cause)
	}
	client.accepted, client.invalidated = nil, nil
}
