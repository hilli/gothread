package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	csettings "github.com/hilli/gothread/common/settings"
	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

var modelOwnedPrefix = ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 1}

func ownedPrefixWire(preferred bool) []byte {
	border := netdata.AppendBorderRouterEntry(nil, netdata.BorderRouterEntry{
		RLOC16: 0x0800, OnMesh: true, SLAAC: true, Preferred: preferred,
	})
	sub := netdata.AppendTLV(nil, netdata.TLVTypeBorderRouter, true, border)
	value := netdata.AppendPrefixValue(nil, netdata.PrefixTLVInfo{
		Prefix: ip6.NewPrefix([16]byte(modelOwnedPrefix), 64), SubTLVsData: sub,
	})
	return netdata.AppendTLV(nil, netdata.TLVTypePrefix, true, value)
}

func actualOwnedSlaacAddress(t *testing.T, fixture *ownedAttachFixture) ip6.Address {
	t.Helper()
	var found ip6.Address
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, address := range fixture.node.inst.netif.GetUnicastAddresses() {
			if address.Origin == ip6.OriginSLAAC && address.Valid && address.Preferred &&
				address.PrefixLength == 64 && address.Address.GetPrefix() == modelOwnedPrefix.GetPrefix() {
				if fixture.node.inst.netif.IsUnicastAddressExternal(address.Address) {
					return fmt.Errorf("generated source stole an external caller slot")
				}
				found = address.Address
			}
		}
		if found.IsUnspecified() {
			return fmt.Errorf("authenticated prefix produced no actual assigned SLAAC source")
		}
		return nil
	})
	return found
}

func sendOwnedPrefixUpdate(t *testing.T, fixture *ownedAttachFixture, parent *fragmentEndpoint, data []byte, version uint8, counter uint32, request bool) {
	t.Helper()
	if request {
		mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
		command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
		if command != mle.CommandDataRequest {
			t.Fatal("no actual request before authenticated prefix update")
		}
	}
	message := mle.NewMessage(mle.CommandDataResponse)
	message.AppendSourceAddressTLV(0x0800)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: version})
	message.AppendNetworkDataTLV(data)
	// A small known-parent response also exercises the existing unsolicited
	// nonfragmented update path, without new resolver or reassembly exceptions.
	sendParentAttachMessage(t, parent, fixture, message, counter)
}

func TestOwnedSlaacActualPublicPrefixAssignsSourceAndPreservesWireIdentities(t *testing.T) {
	data := append(publicFTDPrimaryData(), ownedPrefixWire(true)...)
	fixture, parent, result := publicFTDWireFixture(t, data)
	source := actualOwnedSlaacAddress(t, fixture)
	inResult := false
	for _, address := range result.Addresses {
		if address.Address == source && address.Origin == ip6.OriginSLAAC {
			inResult = true
		}
	}
	if !inResult {
		t.Fatal("actual public result omitted its generated assigned source")
	}
	var member *MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		info, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || info.Source != source || info.Role != mle.RoleChild {
			return fmt.Errorf("actual minted OMR candidate not observed: %v", err)
		}
		member, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	request := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	destination := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x23}
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.SendUDP(bytes.Repeat([]byte{0x51}, 1232), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	unicast := captureSitePacket(t, fixture.node, func(context *mesh.FrameContext) {
		if context.SrcExtAddr != fragmentSource || context.DstExtAddr != udpPeerExt || !context.SecurityEnabled {
			t.Error("OMR1232 did not retain actual secured parent MAC handoff")
		}
	})
	if len(unicast) != 1280 || !bytes.Equal(unicast[8:24], source[:]) ||
		!bytes.Equal(unicast[24:40], destination[:]) || !bytes.Equal(unicast[48:], bytes.Repeat([]byte{0x51}, 1232)) {
		t.Fatal("actual OMR1232 handoff changed source/final IPv6 tuple or payload")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		return member.SendUDP(bytes.Repeat([]byte{0x52}, 1184), ip6.MessageInfo{
			SockAddr: source, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540,
		})
	})
	group := captureSitePacket(t, fixture.node)
	control := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
	if len(group) != 1280 || !bytes.Equal(group[8:24], control[:]) ||
		!bytes.Equal(group[56:72], source[:]) || !bytes.Equal(group[96:], bytes.Repeat([]byte{0x52}, 1184)) {
		t.Fatal("actual group confused canonical outer RLOC with inner owned OMR source")
	}
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, source, 0x7a01, 1, nil), true)
	packet := captureSitePacket(t, fixture.node)
	notification, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	target, iid, rloc := ownNotificationPayload(t, notification)
	if notification.GetType() != coap.TypeConfirmable || notification.GetCode() != coap.CodePost ||
		target != source || iid != [8]byte(fixture.eid.GetIid()) || rloc != 0x0801 ||
		!bytes.Equal(packet[8:24], control[:]) || !bytes.Equal(packet[24:40], origin[:]) {
		t.Fatal("own OMR query fabricated Target/MLIID/RLOC or changed query-origin route")
	}
	sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
			if pending != nil {
				return fmt.Errorf("actual own OMR CONACK retained pending notification")
			}
		}
		return nil
	})
}

func TestOwnedSlaacActualWithdrawReaddDeprecationAndUnchangedRefresh(t *testing.T) {
	data := append(publicFTDPrimaryData(), ownedPrefixWire(true)...)
	fixture, parent, _ := publicFTDWireFixture(t, data)
	source := actualOwnedSlaacAddress(t, fixture)
	var old ThreadAttachmentObservation
	var member *MulticastMembership
	caller := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 3, 15: 0x44}
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		old, err = fixture.attempt.ObserveAttachment(source)
		if err != nil {
			return err
		}
		if err := fixture.node.inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
			Address: caller, PrefixLength: 64, Origin: ip6.OriginManual, Valid: true, Preferred: true,
		}); err != nil {
			return err
		}
		member, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	request := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	sendOwnedPrefixUpdate(t, fixture, parent, data, 1, 70, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current != old || member.Status().State != MulticastReady {
			return fmt.Errorf("unchanged prefix/Primary refresh rotated source or interrupted real lease")
		}
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, publicFTDPrimaryData(), 2, 71, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if inst.netif.HasUnicastAddress(source) || !inst.netif.IsUnicastAddressExternal(caller) {
			return fmt.Errorf("withdrawal retained minted address or stole caller-owned address")
		}
		if _, err := fixture.attempt.ObserveAttachment(source); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("withdrawn source still observed: %v", err)
		}
		if member.Status().State != MulticastReady {
			return fmt.Errorf("source withdrawal gratuitously destroyed unrelated MLR lease")
		}
		return nil
	})
	sendOwnedPrefixUpdate(t, fixture, parent, data, 3, 72, true)
	if actualOwnedSlaacAddress(t, fixture) != source {
		t.Fatal("same persisted IID/prefix did not recreate same model address")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current.Epoch != old.Epoch || current == old {
			return fmt.Errorf("same-address readdition reused source proof or rotated ThreadEpoch")
		}
		return nil
	})
	deprecated := append(publicFTDPrimaryData(), ownedPrefixWire(false)...)
	sendOwnedPrefixUpdate(t, fixture, parent, deprecated, 4, 73, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.netif.HasUnicastAddress(source) {
			return fmt.Errorf("deprecation pretended to withdraw valid local assignment")
		}
		if _, err := fixture.attempt.ObserveAttachment(source); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("deprecated source remained a new-send/observation authority")
		}
		return fixture.node.inst.ThreadStop()
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.netif.HasUnicastAddress(source) || !fixture.node.inst.netif.IsUnicastAddressExternal(caller) {
			return fmt.Errorf("Stop did not remove only its own SLAAC assignment")
		}
		return nil
	})
}

func TestOwnedSlaacPersistedSecretRepeatsIIDAcrossFreshPublicInstances(t *testing.T) {
	store := simulation.NewSimSettings()
	data := ownedPrefixWire(true)
	first, _, _ := publicFTDWireFixture(t, data, store)
	address := actualOwnedSlaacAddress(t, first)
	secret, err := store.Get(platform.SettingsKey(csettings.KeySlaacIidSecretKey), 0)
	if err != nil || len(secret) != 32 {
		t.Fatal("actual RFC7217 secret was not persisted")
	}
	secret = append([]byte(nil), secret...)
	first.node.inst.Stop()
	second, _, _ := publicFTDWireFixture(t, data, store)
	if current := actualOwnedSlaacAddress(t, second); current != address {
		t.Fatal("same actual persisted RFC7217 identity/EUI/prefix changed across model restart")
	}
	restored, err := store.Get(platform.SettingsKey(csettings.KeySlaacIidSecretKey), 0)
	if err != nil || !bytes.Equal(secret, restored) {
		t.Fatal("model restart replaced the persisted IID identity")
	}
}

func TestOwnedSlaacActualParentKeyRotationKeepsSourceAndReadyMembership(t *testing.T) {
	data := append(publicFTDPrimaryData(), ownedPrefixWire(true)...)
	fixture, parent, _ := publicFTDWireFixture(t, data)
	source := actualOwnedSlaacAddress(t, fixture)
	var old ThreadAttachmentObservation
	var member *MulticastMembership
	var before phase2AdmissionCounters
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		old, err = fixture.attempt.ObserveAttachment(source)
		if err != nil {
			return err
		}
		member, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	request := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error { before = phase2AdmissionSnapshot(fixture.node.inst); return nil })
	for _, frame := range phase2ParentRotationFrames(t, fixture, parent) {
		deliverNativeFrame(t, fixture.node, frame)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		current, err := fixture.attempt.ObserveAttachment(source)
		after := phase2AdmissionSnapshot(inst)
		if err != nil || current != old || inst.keyManager.GetCurrentKeySequence() != 1 ||
			inst.mleService.Mle().GetParent().KeySequence != 1 || member.Status().State != MulticastReady ||
			after.mac < before.mac || after.mle < before.mle || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("real parent key rotation interrupted owned OMR identity/lease or reset counters")
		}
		return nil
	})
}
