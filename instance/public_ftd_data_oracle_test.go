package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
)

func TestPublicFTDChildActualNonparentAndOwnAddressControl(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, nil)
	peer := newFragmentEndpoint(t, controlPeerExt, fragmentSource, 0x0c00, 0x0801, simulation.NewSimSettings())
	challenge := startOwnedControlRequest(t, fixture, peer)
	sendParentAttachMessage(t, peer, fixture, controlLinkAccept(challenge, true), 71)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	response, _ := mle.FindTLV(records, mle.TLVResponse)
	if command != mle.CommandLinkAccept || !bytes.Equal(response, []byte{8, 7, 6, 5, 4, 3, 2, 1}) {
		t.Fatal("public attachment did not use the real nonparent AcceptAndRequest reply path")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		record := inst.ownedPeerByAddress(controlPeerExt)
		if record == nil || !record.router.IsStateValid() || inst.mleService.Mle().IsRouterEligible() ||
			!inst.mleService.Mle().IsChild() {
			return fmt.Errorf("public control reply fabricated role or lacked authenticated peer")
		}
		if err := inst.SendUDP([]byte("not-a-data-route"), ip6.MessageInfo{
			SockAddr: inst.GetLinkLocalAddress(), PeerAddr: linkLocalAddress(controlPeerExt), SockPort: 5540, PeerPort: 5540,
		}); !errors.Is(err, goterrors.ErrNoRoute) {
			return fmt.Errorf("public child control link granted an app data route: %v", err)
		}
		return nil
	})
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7901, 1, nil), true)
	packet := captureSitePacket(t, fixture.node)
	notification, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	target, iid, rloc := ownNotificationPayload(t, notification)
	local := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
	if notification.GetType() != coap.TypeConfirmable || notification.GetCode() != coap.CodePost ||
		target != fixture.eid || iid != [8]byte(fixture.eid.GetIid()) || rloc != 0x0801 ||
		!bytes.Equal(packet[8:24], local[:]) || !bytes.Equal(packet[24:40], origin[:]) {
		t.Fatal("public attach own-query notification lost actual identity/query-origin/control tuple")
	}
	sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
			if pending != nil {
				return fmt.Errorf("actual ACK after public attachment retained own control")
			}
		}
		return nil
	})
}

func TestPublicFTDChildActual80MlrGroupAndUnicastPaths(t *testing.T) {
	fixture, parent, result := publicFTDWireFixture(t, publicFTDPrimaryData())
	if len(result.NetworkData) == 0 {
		t.Fatal("public attachment did not retain actual full Network Data")
	}
	var handles []*MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := byte(1); i <= 80; i++ {
			handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(i))
			if err != nil {
				return err
			}
			if handle.Status().State != MulticastPending ||
				!fixture.node.inst.netif.IsMulticastAddressExternal(siteTestAddress(i)) {
				return fmt.Errorf("public group join lacked actual external filter or invented remote readiness")
			}
			handles = append(handles, handle)
		}
		if handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(81)); handle != nil || !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("public group capacity exceeded80: %v", err)
		}
		return nil
	})
	for _, count := range []int{15, 15, 15, 15, 15, 5} {
		request := phase2LeaseRequest(t, fixture, count)
		sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		for _, handle := range handles {
			if status := handle.Status(); status.State != MulticastReady || status.Err != nil || status.RemoteLeaseUnknown {
				return fmt.Errorf("public MLR reference did not require its actual accepted lease")
			}
		}
		before := phase2AdmissionSnapshot(inst)
		sequence := inst.siteGroups.mpl.GetSequence()
		info := ip6.MessageInfo{SockAddr: fixture.eid, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540}
		if err := handles[0].SendUDP(make([]byte, 1185), info); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("public1185 threshold: %v", err)
		}
		if phase2AdmissionSnapshot(inst) != before || inst.siteGroups.mpl.GetSequence() != sequence ||
			len(fixture.node.driver.captures) != 0 || inst.forwarder.GetBufferUsage().TxBytes != 0 {
			return fmt.Errorf("oversized public group consumed nonce/sequence/counter/queue effects")
		}
		return handles[0].SendUDP(bytes.Repeat([]byte{0x73}, 1184), info)
	})
	group := captureSitePacket(t, fixture.node)
	if len(group) != 1280 || !bytes.Equal(group[40:48], []byte{41, 0, 0x6d, 4, 0x40, 0, 8, 1}) ||
		!validNativeUDP(group[48:]) || !bytes.Equal(group[96:], bytes.Repeat([]byte{0x73}, 1184)) {
		t.Fatal("public1184 group did not use its actual96-byte MPL/tunnel/UDP wrapper")
	}
	destination := fixture.eid
	destination[15] ^= 0x40
	mustSRPLoop(t, fixture.node.inst, func() error {
		return fixture.node.inst.SendUDP(bytes.Repeat([]byte{0x74}, 1232), ip6.MessageInfo{
			SockAddr: fixture.eid, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	unicast := captureSitePacket(t, fixture.node)
	if len(unicast) != 1280 || unicast[6] != ip6.ProtoUDP || unicast[7] != 64 ||
		!bytes.Equal(unicast[8:24], fixture.eid[:]) || !bytes.Equal(unicast[24:40], destination[:]) ||
		!bytes.Equal(unicast[48:], bytes.Repeat([]byte{0x74}, 1232)) {
		t.Fatal("public FT D unicast changed app EID/final peer/1232 payload")
	}
	socket := &udp.Socket{}
	received := 0
	var retained []byte
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if err := inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, info *ip6.MessageInfo) {
			received++
			retained = payload
			if info.SockAddr != siteTestAddress(1) || info.PeerPort != 5540 || info.SockPort != 5540 ||
				info.LinkInfo == nil || info.LinkInfo.SrcExtAddr != udpPeerExt {
				t.Error("public joined receive lost actual destination/ports/last-hop metadata")
			}
		}); err != nil {
			return err
		}
		return inst.udpManager.Bind(socket, ip6.SockAddr{Port: 5540})
	})
	sendOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 1, "public-owned-payload"), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if received != 1 || string(retained) != "public-owned-payload" {
			return fmt.Errorf("public attachment did not deliver the normal owned UDP group payload")
		}
		return handles[0].Leave()
	})
	sendOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 2, "locally-left"), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if received != 1 || fixture.node.inst.netif.IsMulticastSubscribed(siteTestAddress(1)) {
			return fmt.Errorf("public last local reference retained RX permission")
		}
		for _, handle := range handles[1:] {
			if err := handle.Leave(); err != nil {
				return err
			}
		}
		if fixture.node.inst.siteGroups != nil {
			return fmt.Errorf("public last Leave retained MLR renewal owner")
		}
		return fixture.node.inst.udpManager.Close(socket)
	})
}
