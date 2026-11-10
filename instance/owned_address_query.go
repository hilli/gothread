// Copyright (c) 2026, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package instance

import (
	"bytes"
	"errors"
	"io"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/tmf"
)

// Together with the one MLR request, at most eight native controls are pending.
const maxOwnedAddressNotifications = 7
const maxOwnedQueryHistory = 8

type ownedQueryIdentity struct {
	peer, target ip6.Address
	mid          uint16
	token        [8]byte
	tokenLength  uint8
	until        time.Time
	valid        bool
}

type ownedQueryInput struct {
	messageInfo ip6.MessageInfo
	link        nativeMLELink
	epoch       uint64
	proof       ownedAddressProof
}

type ownedAddressNotification struct {
	proof          ownedAddressProof
	token          [8]byte
	mid            uint16
	midSet         bool
	slot           int
	cancelDeadline func()
}

func ownAddressQueryURI(message *coap.Message) bool {
	iterator := message.GetOptionIterator()
	parts := 0
	for {
		number, value, ok := iterator.Next()
		if !ok {
			break
		}
		if number != coap.OptionURIPath {
			continue
		}
		switch parts {
		case 0:
			if string(value) != "a" {
				return false
			}
		case 1:
			if string(value) != "aq" {
				return false
			}
		default:
			continue
		}
		parts++
	}
	return parts >= 2
}

func ownAddressTarget(message *coap.Message) (ip6.Address, error) {
	var target ip6.Address
	if message.GetType() != coap.TypeNonConfirmable || message.GetCode() != coap.CodePost || !ownAddressQueryURI(message) {
		return target, goterrors.ErrParse
	}
	iterator := message.GetOptionIterator()
	count := 0
	for {
		number, _, ok := iterator.Next()
		if !ok {
			break
		}
		if number != coap.OptionURIPath {
			return target, goterrors.ErrParse
		}
		count++
	}
	if count != 2 {
		return target, goterrors.ErrParse
	}
	payload := message.GetPayload()
	if len(payload) != 18 || payload[0] != byte(tmf.ThreadTLVTargetEID) || payload[1] != 16 {
		return target, goterrors.ErrParse
	}
	copy(target[:], payload[2:])
	return target, nil
}

func (client *ownedMlrClient) validOwnLink(input *ownedQueryInput, unicast bool) bool {
	attachment, link := client.inst.ownedAttachment, input.link
	if client.stopped || attachment == nil || attachment.profile != ThreadAttachAwakeFTDChild ||
		input.epoch != client.inst.threadEpoch || !link.valid || !link.scope.Secured ||
		link.scope.PanID != uint16(attachment.pan) || link.scope.Channel != attachment.channel ||
		input.messageInfo.PeerPort != tmf.Port || input.messageInfo.SockPort != tmf.Port ||
		input.messageInfo.HopLimit == 0 {
		return false
	}
	knownHop := link.scope.Source == [8]byte(attachment.parentExt)
	if !knownHop {
		for _, peer := range client.inst.ownedControlPeers {
			if peer != nil && peer.router.IsStateValid() && link.scope.Source == [8]byte(peer.router.MacAddr) {
				knownHop = true
				break
			}
		}
	}
	if !knownHop {
		return false
	}
	if unicast {
		return link.localUnicast && input.messageInfo.SockAddr == meshLocator(attachment.prefix, attachment.rloc)
	}
	return link.realmQueryMPL && input.messageInfo.SockAddr == ip6.MulticastRealmLocalAllRouters &&
		(link.localUnicast || link.broadcast) && client.inst.netif.IsMulticastSubscribed(ip6.MulticastRealmLocalAllRouters) &&
		tmf.IsTmfMessage(input.messageInfo.PeerAddr, input.messageInfo.SockAddr, tmf.Port)
}

func (client *ownedMlrClient) receiveOwnAddress(data []byte, info *ip6.MessageInfo) bool {
	if client.stopped {
		return false
	}
	message, err := coap.ParseMessage(data)
	if err != nil {
		return false
	}
	isQuery := ownAddressQueryURI(message)
	var notification *ownedAddressNotification
	if !isQuery {
		if message.GetType() != coap.TypeAck && message.GetType() != coap.TypeReset {
			return false
		}
		for _, pending := range client.ownNotifications {
			if pending != nil && pending.midSet && pending.mid == message.GetMessageID() {
				notification = pending
				break
			}
		}
		if notification == nil {
			return false
		}
	}
	input := ownedQueryInput{messageInfo: *info, link: client.inst.receivedMLELink, epoch: client.inst.threadEpoch}
	if !client.validOwnLink(&input, !isQuery) {
		client.inst.forwarder.RecordReceiveError(false)
		return true
	}
	if isQuery {
		target, err := ownAddressTarget(message)
		if err != nil {
			client.inst.forwarder.RecordReceiveError(false)
			return true
		}
		proof, err := client.inst.currentOwnedAddressProof(target, info.PeerAddr)
		if err != nil {
			client.inst.forwarder.RecordReceiveError(false)
			return true
		}
		input.proof = proof
	} else {
		if info.PeerAddr != notification.proof.peer || info.SockAddr != notification.proof.source ||
			message.GetCode() != coap.CodeEmpty || len(data) != coap.HeaderSize {
			client.inst.forwarder.RecordReceiveError(false)
			return true
		}
		if current, err := client.inst.currentOwnedAddressProof(notification.proof.target, notification.proof.peer); err != nil || current != notification.proof {
			client.inst.forwarder.RecordReceiveError(false)
			return true
		}
	}
	if len(data) > 260 || client.pendingRx {
		client.inst.forwarder.RecordReceiveError(false)
		return true
	}
	owned := append([]byte(nil), data...)
	receivedType := message.GetType()
	client.pendingRx = true
	if !client.inst.postRadioMaintenance(func() {
		client.pendingRx = false
		if !client.validOwnLink(&input, !isQuery) {
			return
		}
		if isQuery {
			current, err := client.inst.currentOwnedAddressProof(input.proof.target, input.proof.peer)
			if err != nil || current != input.proof {
				client.inst.forwarder.RecordReceiveError(false)
				return
			}
			client.ownInput = &input
			client.engine.Receive(owned, coap.MessageInfo{PeerAddr: [16]byte(input.messageInfo.PeerAddr),
				LocalAddr: [16]byte(input.messageInfo.SockAddr), PeerPort: tmf.Port})
			client.ownInput = nil
		} else {
			if client.ownNotifications[notification.slot] != notification {
				return
			}
			current, err := client.inst.currentOwnedAddressProof(notification.proof.target, notification.proof.peer)
			if err != nil || current != notification.proof {
				client.finishOwnAddress(notification, goterrors.ErrAbort)
				return
			}
			client.engine.Receive(owned, coap.MessageInfo{PeerAddr: [16]byte(notification.proof.peer),
				LocalAddr: [16]byte(notification.proof.source), PeerPort: tmf.Port})
			if receivedType == coap.TypeReset {
				client.finishOwnAddress(notification, goterrors.ErrAbort)
			} else {
				client.finishOwnAddress(notification, nil)
			}
		}
	}) {
		client.pendingRx = false
		client.inst.forwarder.RecordReceiveError(false)
	}
	return true
}

func (client *ownedMlrClient) handleOwnAddressQuery(message *coap.Message, info coap.MessageInfo) {
	input := client.ownInput
	if input == nil || !client.validOwnLink(input, false) {
		return
	}
	target, err := ownAddressTarget(message)
	if err != nil {
		client.inst.forwarder.RecordReceiveError(false)
		return
	}
	proof := input.proof
	current, err := client.inst.currentOwnedAddressProof(target, input.messageInfo.PeerAddr)
	if err != nil || current != proof {
		client.inst.forwarder.RecordReceiveError(false)
		return
	}
	now := client.inst.timers.nowTime()
	identity := ownedQueryIdentity{peer: proof.peer, target: target, mid: message.GetMessageID(), tokenLength: uint8(len(message.GetToken())), valid: true}
	copy(identity.token[:], message.GetToken())
	for _, seen := range &client.ownQueries {
		if seen.valid && now.Before(seen.until) && seen.peer == identity.peer && seen.target == identity.target && seen.mid == identity.mid &&
			seen.tokenLength == identity.tokenLength && seen.token == identity.token {
			return
		}
	}
	slot := -1
	for i, pending := range client.ownNotifications {
		if pending == nil {
			slot = i
			break
		}
	}
	if slot < 0 {
		client.inst.forwarder.RecordReceiveError(false)
		return
	}
	notification := &ownedAddressNotification{proof: proof, slot: slot}
	if _, err := io.ReadFull(nativeEntropyReader{client.inst}, notification.token[:]); err != nil {
		client.inst.logOwnedControlError(err)
		return
	}
	response := coap.NewMessage(coap.TypeConfirmable, coap.CodePost, 0)
	if err := response.SetToken(notification.token[:]); err != nil {
		client.inst.logOwnedControlError(err)
		return
	}
	if err := response.AppendURIPathOptions(tmf.UriPathAddressNotify); err != nil {
		client.inst.logOwnedControlError(err)
		return
	}
	payload := []byte{byte(tmf.ThreadTLVTargetEID), 16}
	payload = append(payload, proof.target[:]...)
	iid := proof.meshEID.GetIid()
	payload = append(payload, byte(tmf.ThreadTLVMeshLocalEID), 8)
	payload = append(payload, iid[:]...)
	payload = append(payload, byte(tmf.ThreadTLVRLOC16), 2, byte(proof.attachment.rloc>>8), byte(proof.attachment.rloc))
	if err := response.AppendPayloadMarker(); err != nil {
		client.inst.logOwnedControlError(err)
		return
	}
	if err := response.AppendPayload(payload); err != nil {
		client.inst.logOwnedControlError(err)
		return
	}
	client.ownNotifications[slot] = notification
	wait := coap.DefaultTxParameters().CalculateMaxTransmitWait()
	notification.cancelDeadline = client.inst.timers.scheduleWithCancel(wait, func() { client.finishOwnAddress(notification, goterrors.ErrResponseTimeout) })
	peer := coap.MessageInfo{PeerAddr: [16]byte(proof.peer), LocalAddr: [16]byte(proof.source), PeerPort: tmf.Port}
	// This protocol notification needs the actual empty transport ACK, not a
	// fabricated application success or a second separate response.
	if err := client.engine.SendMessageAwaitAck(response, peer, nil, func(_ *coap.Message, _ coap.MessageInfo, err error) {
		client.finishOwnAddress(notification, err)
	}); err != nil {
		client.finishOwnAddress(notification, err)
		return
	}
	identity.until = now.Add(coap.DefaultTxParameters().CalculateExchangeLifetime())
	client.ownQueries[client.queryNext] = identity
	client.queryNext = (client.queryNext + 1) % len(client.ownQueries)
}

func (client *ownedMlrClient) sendOwnAddress(data []byte, info coap.MessageInfo) (bool, error) {
	message, err := coap.ParseMessage(data)
	if err != nil {
		return false, nil
	}
	for _, notification := range client.ownNotifications {
		if notification == nil || !bytes.Equal(message.GetToken(), notification.token[:]) {
			continue
		}
		if client.stopped || message.GetType() != coap.TypeConfirmable || message.GetCode() != coap.CodePost ||
			info.PeerAddr != [16]byte(notification.proof.peer) || info.LocalAddr != [16]byte(notification.proof.source) || info.PeerPort != tmf.Port {
			return true, goterrors.ErrDrop
		}
		if notification.midSet && notification.mid != message.GetMessageID() {
			return true, goterrors.ErrDrop
		}
		notification.mid, notification.midSet = message.GetMessageID(), true
		err := client.inst.sendOwnedAddressNotification(data, &notification.proof)
		if err != nil {
			client.finishOwnAddress(notification, err)
		}
		return true, err
	}
	return false, nil
}

func (client *ownedMlrClient) finishOwnAddress(notification *ownedAddressNotification, cause error) {
	if client.ownNotifications[notification.slot] != notification {
		return
	}
	client.ownNotifications[notification.slot] = nil
	if notification.cancelDeadline != nil {
		notification.cancelDeadline()
	}
	peer := coap.MessageInfo{PeerAddr: [16]byte(notification.proof.peer), LocalAddr: [16]byte(notification.proof.source), PeerPort: tmf.Port}
	if err := client.engine.AbortRequest(notification.token[:], peer); err != nil && !errors.Is(err, goterrors.ErrNotFound) {
		client.inst.logOwnedControlError(err)
	}
	if cause != nil {
		client.inst.logOwnedControlError(cause)
	}
}

func (client *ownedMlrClient) stopOwnAddresses(cause error) {
	for _, notification := range client.ownNotifications {
		if notification != nil {
			client.finishOwnAddress(notification, cause)
		}
	}
	client.ownQueries = [maxOwnedQueryHistory]ownedQueryIdentity{}
}
