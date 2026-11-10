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
	"github.com/hilli/gothread/thread/lowpan"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/netdata"
	"github.com/hilli/gothread/thread/tmf"
)

func siteNativeFixture(t *testing.T) (*ownedAttachFixture, *fragmentEndpoint) {
	t.Helper()
	server := netdata.AppendServerValue(nil, netdata.ServerEntry{
		Server16: 0x0800, ServerData: []byte{7, 0, 5, 0, 0, 1, 0x2c}, // default300s, reregistration5s
	})
	sub := netdata.AppendTLV(nil, netdata.TLVTypeServer, true, server)
	service := netdata.AppendServiceValue(nil, netdata.ServiceTLVInfo{
		ServiceID: 4, EnterpriseNumber: netdata.ThreadEnterpriseNumber, ServiceData: []byte{1}, SubTLVsData: sub,
	})
	data := netdata.AppendTLV(nil, netdata.TLVTypeService, true, service)
	fixture, parent, _ := dormantFTDControlWithData(t, data)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.node.macKey = fixture.node.inst.keyManager.GetCurrentMacKey()
		return nil
	})
	return fixture, parent
}

func siteTestAddress(index byte) ip6.Address {
	return ip6.Address{0xff, 0x35, 0, 0x40, 0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, index}
}

// Observes real production MAC output and reassembles only as a software peer.
// It never changes the client's role, key, membership or accepted status.
func captureSitePacket(t *testing.T, node *fragmentEndpoint, observe ...func(*mesh.FrameContext)) []byte {
	t.Helper()
	decoder := mesh.NewForwarder()
	decoder.SetEnabled(true)
	for count := 0; count < 32; count++ {
		capture := captureUDP(t, node.driver.boundedUDPRadio)
		context, payload := nativeAdaptation(t, capture, node.macKey)
		for _, callback := range observe {
			callback(context)
		}
		addresses := lowpan.AddressContext{SrcExtAddr: context.SrcExtAddr, DstExtAddr: context.DstExtAddr}
		var packet []byte
		var err error
		if lowpan.IsFragment(payload) {
			header, n, parseErr := lowpan.ParseFragmentHeader(payload)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			body := payload[n:]
			if header.IsFirst {
				body, err = lowpan.DecompressDatagram(body, addresses, header.DatagramSize)
				if err != nil {
					t.Fatal(err)
				}
			}
			packet, err = decoder.HandleScopedFragment(mesh.FragmentKey{Scope: mesh.FragmentScope{
				Source: context.SrcExtAddr, Destination: context.DstExtAddr, PanID: context.PanId, Channel: 20, Secured: true,
			}, Tag: header.DatagramTag, Size: header.DatagramSize}, header.DatagramOffset, body)
		} else {
			packet, err = lowpan.DecompressDatagram(payload, addresses, 0)
		}
		if err != nil {
			t.Fatal(err)
		}
		completeNativeFrame(t, node, capture, nil)
		if packet != nil {
			return packet
		}
	}
	t.Fatal("no bounded complete native datagram")
	return nil
}

func sendSiteCoapResponse(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, request *coap.Message, status byte, failed [][16]byte) {
	sendSiteCoapResponseSecurity(t, parent, fixture, request, status, failed, true)
}

func sendSiteCoapResponseSecurity(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, request *coap.Message, status byte, failed [][16]byte, secured bool) {
	t.Helper()
	response := coap.NewMessage(coap.TypeAck, coap.CodeChanged, request.GetMessageID())
	if err := response.SetToken(request.GetToken()); err != nil {
		t.Fatal(err)
	}
	payload := []byte{byte(tmf.ThreadTLVStatus), 1, status}
	if len(failed) > 0 {
		payload = append(payload, byte(tmf.ThreadTLVIPv6Addresses), byte(16*len(failed)))
		for _, address := range failed {
			payload = append(payload, address[:]...)
		}
	}
	if err := response.AppendPayloadMarker(); err != nil {
		t.Fatal(err)
	}
	if err := response.AppendPayload(payload); err != nil {
		t.Fatal(err)
	}
	mustSRPLoop(t, parent.inst, func() error {
		message := parent.inst.newUDPMessage(response.GetBytes(), ip6.MessageInfo{
			SockAddr: meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800), PeerAddr: meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801), SockPort: 61631, PeerPort: 61631, HopLimit: 64,
		})
		message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
		message.Metadata.SecurityEnabled = secured
		message.Metadata.DstExtAddr = fragmentSource
		message.MeshDest = 0x0801
		return parent.inst.sendViaForwarder(message)
	})
	for count := 0; count < 16; count++ {
		capture := captureUDP(t, parent.driver.boundedUDPRadio)
		deliverNativeFrame(t, fixture.node, capture)
		completeNativeFrame(t, parent, capture, nil)
		var pending bool
		mustSRPLoop(t, parent.inst, func() error { pending = parent.inst.pendingTxMsg != nil; return nil })
		if !pending {
			break
		}
	}
	mustSRPLoop(t, fixture.node.inst, func() error { return nil })
}

func TestDormantSiteNative80ActualMlrBatchesAndLocalLeave(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var handles []*MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		for i := byte(1); i <= 80; i++ {
			handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(i))
			if err != nil {
				return err
			}
			handles = append(handles, handle)
			if !fixture.node.inst.netif.IsMulticastAddressExternal(siteTestAddress(i)) {
				return fmt.Errorf("actual distinct external filter%d not owned", i)
			}
			if handle.Status().State != MulticastPending {
				return fmt.Errorf("local join manufactured remote readiness")
			}
		}
		if handle, err := fixture.node.inst.JoinMulticast(siteTestAddress(81)); handle != nil || !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("reference capacity is not exact80: %v", err)
		}
		return nil
	})
	for _, count := range []int{15, 15, 15, 15, 15, 5} {
		packet := captureSitePacket(t, fixture.node)
		controlSource := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0801)
		controlDestination := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800)
		if !bytes.Equal(packet[8:24], controlSource[:]) || !bytes.Equal(packet[24:40], controlDestination[:]) {
			t.Fatal("ordinary non-link-local TMF did not use actual assigned RLOC tuple")
		}
		request, err := coap.ParseMessage(packet[48:])
		if err != nil {
			t.Fatal(err)
		}
		payload := request.GetPayload()
		if request.GetCode() != coap.CodePost || len(request.GetToken()) != 8 || len(payload) != 2+16*count ||
			payload[0] != 14 || int(payload[1]) != 16*count {
			t.Fatal("actual automatic wire batch is not expected address-only request")
		}
		if count == 15 && len(packet[48:]) != 260 {
			t.Fatal("actual maximal CoAP/UDP payload is not260")
		}
		sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		for _, handle := range handles {
			if status := handle.Status(); status.State != MulticastReady || status.RemoteLeaseUnknown {
				return fmt.Errorf("actual accepted subset not ready")
			}
		}
		beforeMac, beforeMle := fixture.node.inst.keyManager.GetMacFrameCounter(), fixture.node.inst.keyManager.GetMleFrameCounter()
		info := ip6.MessageInfo{SockAddr: fixture.eid, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540, HopLimit: 64}
		if err := handles[0].SendUDP(make([]byte, 1185), info); !errors.Is(err, goterrors.ErrNoBufs) {
			return fmt.Errorf("1185 threshold: %v", err)
		}
		if fixture.node.inst.keyManager.GetMacFrameCounter() != beforeMac || fixture.node.inst.keyManager.GetMleFrameCounter() != beforeMle ||
			len(fixture.node.driver.captures) != 0 || fixture.node.inst.forwarder.GetBufferUsage().TxBytes != 0 {
			return fmt.Errorf("1185 consumed queue/tag/counter/radio admission")
		}
		return handles[0].SendUDP(bytes.Repeat([]byte{0x77}, 1184), info)
	})
	packet := captureSitePacket(t, fixture.node)
	if len(packet) != 1280 || !bytes.Equal(packet[40:48], []byte{41, 0, 0x6d, 4, 0x40, 0, 8, 1}) {
		t.Fatal("actual native1184 path did not encode96-byte wrapper")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := handles[0].Leave(); err != nil {
			return err
		}
		status := handles[0].Status()
		if status.State != MulticastLocalLeft || !status.RemoteLeaseUnknown || !status.ExpiryPending ||
			fixture.node.inst.netif.IsMulticastSubscribed(siteTestAddress(1)) || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("last local leave retained filter or invented immediate remote prune")
		}
		return nil
	})
}

func TestDormantSiteRXOwnsInnerMetadataAndRevocation(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var membership *MulticastMembership
	received := 0
	var retained []byte
	var actual ip6.MessageInfo
	socket := &udp.Socket{}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := fixture.node.inst.udpManager.Open(socket, udp.NetifThreadInternal, func(payload []byte, info *ip6.MessageInfo) {
			received++
			retained = payload
			actual = *info
		}); err != nil {
			return err
		}
		if err := fixture.node.inst.udpManager.Bind(socket, ip6.SockAddr{Port: 5540}); err != nil {
			return err
		}
		var err error
		membership, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	requestPacket := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(requestPacket[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	send := func(sequence uint8) {
		t.Helper()
		outerSource := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800)
		packet, err := encodeSiteTunnel([]byte("retained-inner"), ip6.MessageInfo{
			SockAddr: outerSource, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540, HopLimit: 64,
		}, outerSource, 0x0800, sequence)
		if err != nil {
			t.Fatal(err)
		}
		mustSRPLoop(t, parent.inst, func() error {
			message := parent.inst.newUDPMessage(packet[40:], ip6.MessageInfo{SockAddr: outerSource, PeerAddr: realmMplForwarders, HopLimit: 64})
			message.Metadata.NextHeader = 0
			message.Metadata.UseSrcShort, message.Metadata.UseDstShort = false, false
			message.Metadata.DstExtAddr = fragmentSource
			message.MeshDest = 0x0801
			return parent.inst.sendViaForwarder(message)
		})
		for count := 0; count < 16; count++ {
			capture := captureUDP(t, parent.driver.boundedUDPRadio)
			deliverNativeFrame(t, fixture.node, capture)
			completeNativeFrame(t, parent, capture, nil)
			var pending bool
			mustSRPLoop(t, parent.inst, func() error { pending = parent.inst.pendingTxMsg != nil; return nil })
			if !pending {
				break
			}
		}
		mustSRPLoop(t, fixture.node.inst, func() error { return nil })
	}
	send(7)
	send(7)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if received != 1 || string(retained) != "retained-inner" || actual.SockAddr != siteTestAddress(1) ||
			actual.PeerAddr != meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800) || actual.PeerPort != 5540 ||
			actual.SockPort != 5540 || actual.HopLimit != 64 || actual.LinkInfo == nil || actual.LinkInfo.SrcExtAddr != udpPeerExt {
			return fmt.Errorf("owned inner tuple/payload/dedup/last-hop provenance lost")
		}
		return membership.Leave()
	})
	send(8)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if received != 1 {
			return fmt.Errorf("remote stale lease bypassed local leave")
		}
		return nil
	})
}
