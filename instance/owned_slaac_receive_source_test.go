package instance

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
)

func TestOwnedSlaacActualUnicastReturnDeliveryRequiresCurrentAssignment(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, ownedPrefixWire(true))
	local := actualOwnedSlaacAddress(t, fixture)
	peer := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x76}
	socket := &udp.Socket{}
	var received []string
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if err := inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, info *ip6.MessageInfo) {
			received = append(received, string(payload))
			if info.SockAddr != local || info.PeerAddr != peer || info.SockPort != 5540 ||
				info.PeerPort != 5540 || info.LinkInfo == nil || info.LinkInfo.SrcExtAddr != udpPeerExt {
				t.Error("actual OMR return changed IPv6/UDP/last-hop tuple")
			}
		}); err != nil {
			return err
		}
		return inst.udpManager.Bind(socket, ip6.SockAddr{Port: 5540})
	})
	send := func(secured bool, payload string) {
		t.Helper()
		header := ip6.NewHeader(peer, local, ip6.ProtoUDP, 64, uint16(8+len(payload)))
		raw := header.Bytes()
		packet := append([]byte(nil), raw[:]...)
		udpHeader := fixtureUDPHeader(peer, local, 5540, 5540, []byte(payload))
		packet = append(packet, udpHeader[:]...)
		packet = append(packet, []byte(payload)...)
		sendOwnQueryPacket(t, parent, fixture, packet, secured)
	}
	send(false, "not-link-authenticated")
	send(true, "actual-current-source")
	sendOwnedPrefixUpdate(t, fixture, parent, nil, 1, 70, true)
	send(true, "withdrawn-local-destination")
	sendOwnedPrefixUpdate(t, fixture, parent, ownedPrefixWire(false), 2, 71, true)
	send(true, "deprecated-local-destination")
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(received) != 1 || received[0] != "actual-current-source" {
			return fmt.Errorf("unsecured/absent/deprecated local assignment reached actual socket")
		}
		return nil
	})
}

func TestOwnedSlaacQueuedGroupReceiveCannotCrossAuthenticatedSourceGeneration(t *testing.T) {
	data := append(publicFTDPrimaryData(), ownedPrefixWire(true)...)
	fixture, parent, _ := publicFTDWireFixture(t, data)
	local := actualOwnedSlaacAddress(t, fixture)
	socket := &udp.Socket{}
	var received []string
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if err := inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, _ *ip6.MessageInfo) {
			received = append(received, string(payload))
		}); err != nil {
			return err
		}
		if err := inst.udpManager.Bind(socket, ip6.SockAddr{Port: 5540}); err != nil {
			return err
		}
		_, err := inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	request := phase2LeaseRequest(t, fixture, 1)
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	withdraw := captureParentAttachMessage(t, parent, fixture, ownedPrefixResponse(publicFTDPrimaryData(), 1), 70, nil)
	readd := captureParentAttachMessage(t, parent, fixture, ownedPrefixResponse(data, 2), 71, nil)
	stale := captureOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 1, "old-source-generation"), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		deliverPhase2RawFrames(fixture, withdraw)
		deliverPhase2RawFrames(fixture, readd)
		deliverPhase2RawFrames(fixture, stale)
		if fixture.node.inst.pendingOwnedMLE != 2 || fixture.node.inst.siteGroups.pendingRx != 1 {
			return fmt.Errorf("actual parent updates/group did not queue before source-generation fence")
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if _, err := fixture.attempt.ObserveAttachment(local); err != nil {
			return err
		}
		if len(received) != 0 {
			return fmt.Errorf("old queued group callback acquired replacement source authority")
		}
		return nil
	})
	sendOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 2, "fresh-source-generation"), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(received) != 1 || received[0] != "fresh-source-generation" {
			return fmt.Errorf("fresh group admission after authenticated readdition did not reach actual socket")
		}
		return nil
	})
}
