package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/tmf"
)

func TestDormantFTDUnicastKeepsAppEIDAnd1232Boundary(t *testing.T) {
	fixture, _ := siteNativeFixture(t)
	destination := fixture.eid
	destination[15] ^= 0x40
	info := ip6.MessageInfo{SockAddr: fixture.eid, PeerAddr: destination, SockPort: 5540, PeerPort: 5540}
	payload := bytes.Repeat([]byte{0x63}, 1232)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := inst.keyManager.GetMacFrameCounter()
		if err := inst.SendUDP(make([]byte, 1233), info); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("unicast1233 boundary: %v", err)
		}
		for _, bad := range []ip6.MessageInfo{
			{SockAddr: fixture.eid, PeerAddr: meshLocator(inst.meshLocalPrefix, 0x0c00), SockPort: 5540, PeerPort: 5540},
			{SockAddr: fixture.eid, PeerAddr: ip6.Address{0x20, 1, 15: 1}, SockPort: 5540, PeerPort: 5540},
			{SockAddr: meshLocator(inst.meshLocalPrefix, 0x0801), PeerAddr: destination, SockPort: 5540, PeerPort: 5540},
		} {
			if err := inst.SendUDP([]byte("forbidden"), bad); err == nil {
				return fmt.Errorf("FTD fallback relaxed reserved/offmesh/source guard")
			}
		}
		if inst.keyManager.GetMacFrameCounter() != before || inst.forwarder.GetBufferUsage().TxBytes != 0 {
			return fmt.Errorf("rejected unicast consumed admission")
		}
		return inst.SendUDP(payload, info)
	})
	packet := captureSitePacket(t, fixture.node, func(frame *mesh.FrameContext) {
		if frame.DstExtAddr != [8]byte(udpPeerExt) {
			t.Error("FTD app EID was not handed to actual parent")
		}
	})
	if len(packet) != 1280 || packet[7] != 64 || !bytes.Equal(packet[8:24], fixture.eid[:]) ||
		!bytes.Equal(packet[24:40], destination[:]) || !bytes.Equal(packet[48:], payload) {
		t.Fatal("FTD unicast changed final tuple/payload or1232 MTU")
	}
}

func TestDormantOwnAddressACKRequiresExactTupleMIDAndEmptyWire(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7501, 1, nil), true)
	packet := captureSitePacket(t, fixture.node)
	notification, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"peer", "port", "mid", "payload", "token", "nonempty", "type"} {
		t.Run(kind, func(t *testing.T) {
			peer, destination := origin, meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
			port, mid := uint16(tmf.Port), notification.GetMessageID()
			if kind == "peer" {
				peer = meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800)
			}
			if kind == "port" {
				port++
			}
			if kind == "mid" {
				mid++
			}
			ack := coap.NewMessage(coap.TypeAck, coap.CodeEmpty, mid)
			switch kind {
			case "payload":
				if err := ack.AppendPayloadMarker(); err != nil {
					t.Fatal(err)
				}
				if err := ack.AppendPayload([]byte{1}); err != nil {
					t.Fatal(err)
				}
			case "token":
				if err := ack.SetToken([]byte{1}); err != nil {
					t.Fatal(err)
				}
			case "nonempty":
				ack.GetBytes()[1] = byte(coap.CodeChanged)
			case "type":
				ack.GetBytes()[0] = ack.GetBytes()[0]&^0x30 | byte(coap.TypeNonConfirmable)<<4
			}
			header := ip6.NewHeader(peer, destination, ip6.ProtoUDP, 64, uint16(8+len(ack.GetBytes())))
			raw := header.Bytes()
			wire := append([]byte(nil), raw[:]...)
			udp := fixtureUDPHeader(peer, destination, port, tmf.Port, ack.GetBytes())
			wire = append(wire, udp[:]...)
			wire = append(wire, ack.GetBytes()...)
			sendOwnQueryPacket(t, parent, fixture, wire, true)
			mustSRPLoop(t, fixture.node.inst, func() error {
				active := 0
				for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
					if pending != nil {
						active++
					}
				}
				if active != 1 || len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("invalid ACK changed response ownership or transmitted")
				}
				return nil
			})
		})
	}
	sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
			if pending != nil {
				return fmt.Errorf("genuine ACK did not complete control")
			}
		}
		return nil
	})
}

func TestDormantOwnAddressRetryFencesLiveAddressKeyAndHealth(t *testing.T) {
	for _, kind := range []string{"removed", "key", "health", "stop"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent := siteNativeFixture(t)
			origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
			sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7601, 1, nil), true)
			captureSitePacket(t, fixture.node)
			control := fixture.node.inst.ownedTMF
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				switch kind {
				case "removed":
					for _, address := range inst.netif.GetUnicastAddresses() {
						if address.Address == fixture.eid {
							inst.netif.RemoveUnicastAddress(&address)
							break
						}
					}
				case "key":
					inst.SetCurrentKeySequence(inst.keyManager.GetCurrentKeySequence()+1, key.ForceUpdate|key.ResetGuardTimer)
					if err := inst.PersistenceError(); err != nil {
						return err
					}
				case "health":
					inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
				case "stop":
					if err := inst.ThreadStop(); err != nil {
						return err
					}
				}
				before := inst.keyManager.GetMacFrameCounter()
				fixture.now = fixture.now.Add(4 * time.Second)
				inst.timers.processExpired()
				for _, pending := range control.ownNotifications {
					if pending != nil {
						return fmt.Errorf("stale admitted notification retained retry ownership")
					}
				}
				if inst.keyManager.GetMacFrameCounter() != before || len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("stale admitted retry consumed frame/counter")
				}
				return nil
			})
		})
	}
}

func TestDormantGroupReferencePressureCleanupRetryAndReReservation(t *testing.T) {
	fixture, _ := siteNativeFixture(t)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		var handles []*MulticastMembership
		for i := 0; i < 80; i++ {
			handle, err := inst.JoinMulticast(siteTestAddress(1))
			if err != nil {
				return err
			}

			handles = append(handles, handle)
		}
		if handle, err := inst.JoinMulticast(siteTestAddress(2)); handle != nil || !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("81st retained reference admitted")
		}
		for _, handle := range handles[:79] {
			if err := handle.Leave(); err != nil {
				return err
			}
		}
		last := handles[79]
		// A genuine conflicting Netif owner prevents cleanup; retry keeps its handle.
		inst.netif.UnsubscribeMulticast(siteTestAddress(1))
		if err := inst.netif.SubscribeExternalMulticast(siteTestAddress(1)); err != nil {
			return err
		}
		if err := last.Leave(); !errors.Is(err, goterrors.ErrRejected) || !last.active ||
			inst.siteGroups == nil {
			return fmt.Errorf("failed cleanup lost retry ownership: %v", err)
		}
		if err := inst.netif.UnsubscribeExternalMulticast(siteTestAddress(1)); err != nil {
			return err
		}
		if err := last.Leave(); err != nil {
			return err
		}
		if inst.siteGroups != nil {
			return fmt.Errorf("retried cleanup retained group owner")
		}
		next, err := inst.JoinMulticast(siteTestAddress(2))
		if err != nil {
			return err
		}
		if next.Status().State != MulticastPending {
			return fmt.Errorf("new lifecycle inherited stale lease")
		}
		return next.Leave()
	})
}
