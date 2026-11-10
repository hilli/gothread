package instance

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/tmf"
)

func ownQueryPacket(t *testing.T, fixture *ownedAttachFixture, origin, target ip6.Address, mid uint16, sequence uint8,
	change func(*coap.Message)) []byte {
	t.Helper()
	query := coap.NewMessage(coap.TypeNonConfirmable, coap.CodePost, mid)
	if err := query.SetToken([]byte{byte(mid >> 8), byte(mid)}); err != nil {
		t.Fatal(err)
	}
	if err := query.AppendURIPathOptions(tmf.UriPathAddressQuery); err != nil {
		t.Fatal(err)
	}
	payload := append([]byte{0, 16}, target[:]...)
	if err := query.AppendPayloadMarker(); err != nil {
		t.Fatal(err)
	}
	if err := query.AppendPayload(payload); err != nil {
		t.Fatal(err)
	}
	if change != nil {
		change(query)
	}
	destination := ip6.MulticastRealmLocalAllRouters
	header := ip6.NewHeader(origin, destination, 0, 64, uint16(16+len(query.GetBytes())))
	raw := header.Bytes()
	packet := append([]byte(nil), raw[:]...)
	seed := origin.GetIid().GetLocator()
	packet = append(packet, 17, 0, 0x6d, 4, 0x40, sequence, byte(seed>>8), byte(seed))
	udp := fixtureUDPHeader(origin, destination, tmf.Port, tmf.Port, query.GetBytes())
	packet = append(packet, udp[:]...)
	packet = append(packet, query.GetBytes()...)
	return packet
}

func sendOwnQueryPacket(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, packet []byte, secured bool) {
	for _, capture := range captureOwnQueryPacket(t, parent, fixture, packet, secured) {
		deliverNativeFrame(t, fixture.node, capture)
	}
	mustSRPLoop(t, fixture.node.inst, func() error { return nil })
}

func captureOwnQueryPacket(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, packet []byte, secured bool) []udpRadioCapture {
	t.Helper()
	var source, destination ip6.Address
	copy(source[:], packet[8:24])
	copy(destination[:], packet[24:40])
	mustSRPLoop(t, parent.inst, func() error {
		info := ip6.MessageInfo{SockAddr: source, PeerAddr: destination, HopLimit: packet[7]}
		payload := packet[40:]
		if packet[6] == ip6.ProtoUDP {
			info.SockPort = binary.BigEndian.Uint16(packet[40:42])
			info.PeerPort = binary.BigEndian.Uint16(packet[42:44])
			payload = packet[48:]
		}
		message := parent.inst.newUDPMessage(payload, info)
		message.Metadata.NextHeader = packet[6]
		message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
		message.Metadata.SecurityEnabled = secured
		message.Metadata.DstExtAddr = fragmentSource
		message.MeshDest = 0x0801
		return parent.inst.sendViaForwarder(message)
	})
	var captures []udpRadioCapture
	for count := 0; count < 16; count++ {
		capture := captureUDP(t, parent.driver.boundedUDPRadio)
		captures = append(captures, capture)
		completeNativeFrame(t, parent, capture, nil)
		var pending bool
		mustSRPLoop(t, parent.inst, func() error { pending = parent.inst.pendingTxMsg != nil; return nil })
		if !pending {
			break
		}
	}
	return captures
}

func ownNotificationPayload(t *testing.T, message *coap.Message) (target ip6.Address, iid [8]byte, rloc uint16) {
	t.Helper()
	payload := message.GetPayload()
	// Target EID18 + Mesh-Local IID10 + RLOC164, and no fabricated extras.
	if len(payload) != 32 || payload[0] != 0 || payload[1] != 16 || payload[18] != 3 || payload[19] != 8 ||
		payload[28] != 2 || payload[29] != 2 {
		t.Fatal("not the genuine three notification TLVs")
	}
	copy(target[:], payload[2:18])
	copy(iid[:], payload[20:28])
	return target, iid, binary.BigEndian.Uint16(payload[30:32])
}

func sendOwnNotificationAck(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, origin ip6.Address, mid uint16, secured bool) {
	t.Helper()
	response := coap.NewMessage(coap.TypeAck, coap.CodeEmpty, mid)
	destination := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
	header := ip6.NewHeader(origin, destination, ip6.ProtoUDP, 64, uint16(8+len(response.GetBytes())))
	raw := header.Bytes()
	packet := append([]byte(nil), raw[:]...)
	udp := fixtureUDPHeader(origin, destination, tmf.Port, tmf.Port, response.GetBytes())
	packet = append(packet, udp[:]...)
	packet = append(packet, response.GetBytes()...)
	sendOwnQueryPacket(t, parent, fixture, packet, secured)
}

func TestDormantOwnAddressRealmDeliveryProducesBoundActualNotificationAndAck(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if !fixture.node.inst.netif.IsMulticastSubscribed(ip6.MulticastRealmLocalAllRouters) {
			return fmt.Errorf("actual FTD role never subscribed realm queries")
		}
		return nil
	})
	query := ownQueryPacket(t, fixture, origin, fixture.eid, 0x7130, 1, nil)
	sendOwnQueryPacket(t, parent, fixture, query, true)
	packet := captureSitePacket(t, fixture.node, func(context *mesh.FrameContext) {
		if context.DstExtAddr != [8]byte(udpPeerExt) {
			t.Error("notification did not retain the captured parent MAC next hop")
		}
	})
	local := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
	if !bytes.Equal(packet[8:24], local[:]) || !bytes.Equal(packet[24:40], origin[:]) {
		t.Fatal("notification rewrote query origin to last-hop parent or fabricated source")
	}
	notification, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	if notification.GetType() != coap.TypeConfirmable || notification.GetCode() != coap.CodePost || len(notification.GetToken()) != 8 {
		t.Fatal("notification was fire-and-forget or missing captured token")
	}
	iterator := notification.GetOptionIterator()
	var path []string
	for {
		number, value, ok := iterator.Next()
		if !ok {
			break
		}
		if number == coap.OptionURIPath {
			path = append(path, string(value))
		}
	}
	if len(path) != 2 || path[0] != "a" || path[1] != "an" {
		t.Fatal("actual notification URI was not a/an")
	}
	target, iid, rloc := ownNotificationPayload(t, notification)
	if target != fixture.eid || iid != [8]byte(fixture.eid.GetIid()) || rloc != 0x0801 {
		t.Fatal("notification identity was synthesized")
	}
	// A repeated real realm query cannot allocate a second notification.
	sendOwnQueryPacket(t, parent, fixture, query, true)
	// A new CoAP identity cannot bypass the already-seen MPL sequence.
	sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7132, 1, nil), true)
	// A fresh MPL sequence cannot bypass the already-seen CoAP identity.
	sendOwnQueryPacket(t, parent, fixture, ownQueryPacket(t, fixture, origin, fixture.eid, 0x7130, 2, nil), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("duplicate query produced fresh wire")
		}
		return nil
	})
	sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), false)
	mustSRPLoop(t, fixture.node.inst, func() error {
		active := 0
		for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
			if pending != nil {
				active++
			}
		}
		if active != 1 {
			return fmt.Errorf("plain ACK completed own control")
		}
		fixture.now = fixture.now.Add(4 * time.Second)
		fixture.node.inst.timers.processExpired()
		return nil
	})
	retry := captureSitePacket(t, fixture.node)
	retransmitted, err := coap.ParseMessage(retry[48:])
	if err != nil {
		t.Fatal(err)
	}
	if retransmitted.GetMessageID() != notification.GetMessageID() || !bytes.Equal(retransmitted.GetToken(), notification.GetToken()) {
		t.Fatal("retry changed the exact admitted CoAP identity")
	}
	sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, pending := range fixture.node.inst.ownedTMF.ownNotifications {
			if pending != nil {
				return fmt.Errorf("actual authenticated ACK retained pending control")
			}
		}
		return nil
	})
	seedless := ownQueryPacket(t, fixture, origin, fixture.eid, 0x7131, 3, nil)
	copy(seedless[40:48], []byte{17, 0, 0x6d, 2, 0, 3, 1, 0})
	sendOwnQueryPacket(t, parent, fixture, seedless, true)
	seedlessReply := captureSitePacket(t, fixture.node)
	second, err := coap.ParseMessage(seedlessReply[48:])
	if err != nil {
		t.Fatal(err)
	}
	ownNotificationPayload(t, second)
	sendOwnNotificationAck(t, parent, fixture, origin, second.GetMessageID(), true)
}

func TestDormantOwnAddressInvalidRealmQueriesUseNoReplyCounterOrTag(t *testing.T) {
	for _, kind := range []string{"nonown", "plain", "wrong-type", "wrong-method", "duplicate-target", "missing-target", "foreign", "unknown-route", "no-mpl"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent := siteNativeFixture(t)
			origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
			target := fixture.eid
			if kind == "nonown" {
				target[15] ^= 1
			}
			if kind == "foreign" {
				origin[1] ^= 1
			}
			if kind == "unknown-route" {
				origin = meshLocator(fixture.node.inst.meshLocalPrefix, 0x1000)
			}
			packet := ownQueryPacket(t, fixture, origin, target, 0x7140, 1, func(message *coap.Message) {
				switch kind {
				case "wrong-type":
					message.GetBytes()[0] &^= 0x30
				case "wrong-method":
					message.GetBytes()[1] = byte(coap.CodeGet)
				case "duplicate-target":
					if err := message.AppendPayload(append([]byte{0, 16}, target[:]...)); err != nil {
						t.Fatal(err)
					}
				case "missing-target":
					message.GetPayload()[0] = 99
				}
			})
			if kind == "no-mpl" {
				stripped := append([]byte(nil), packet[:40]...)
				stripped[6] = 17
				binary.BigEndian.PutUint16(stripped[4:6], uint16(len(packet)-48))
				packet = append(stripped, packet[48:]...)
			}
			var counters [3]uint32
			mustSRPLoop(t, fixture.node.inst, func() error {
				counters = [3]uint32{fixture.node.inst.keyManager.GetMacFrameCounter(), fixture.node.inst.keyManager.GetMleFrameCounter(), uint32(fixture.node.inst.entropy.(*ownedTestEntropy).source.calls)}
				return nil
			})
			sendOwnQueryPacket(t, parent, fixture, packet, kind != "plain")
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				after := [3]uint32{inst.keyManager.GetMacFrameCounter(), inst.keyManager.GetMleFrameCounter(), uint32(inst.entropy.(*ownedTestEntropy).source.calls)}
				if after != counters || len(fixture.node.driver.captures) != 0 || inst.forwarder.GetBufferUsage().TxBytes != 0 {
					return fmt.Errorf("invalid query admitted response/tag/counter/entropy effects")
				}
				return nil
			})
		})
	}
}
