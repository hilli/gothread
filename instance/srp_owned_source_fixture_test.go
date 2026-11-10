package instance

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/dns"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/srp"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/netdata"
)

// Existing accepted5aee APIs/helpers only. Model server replies are generated
// by the real SIG(0)-validating SRP server, not a manually set Registered flag.
type srpOwnedProofFixture struct {
	thread    *ownedAttachFixture
	parent    *fragmentEndpoint
	sources   [4]ip6.Address
	binding   *SRPBinding
	config    SRPConfig
	server    *srp.Server
	reply     []byte
	replyPeer ip6.SockAddr
}

func srpProofPrefixData(present, preferred [4]bool) []byte {
	data := publicFTDPrimaryData()
	for i := range present {
		if !present[i] {
			continue
		}
		prefix := modelOwnedPrefix
		prefix[5] = byte(i + 1)
		border := netdata.AppendBorderRouterEntry(nil, netdata.BorderRouterEntry{
			RLOC16: 0x0800, OnMesh: true, SLAAC: true, Preferred: preferred[i],
		})
		value := netdata.AppendPrefixValue(nil, netdata.PrefixTLVInfo{
			Prefix:      ip6.NewPrefix([16]byte(prefix), 64),
			SubTLVsData: netdata.AppendTLV(nil, netdata.TLVTypeBorderRouter, true, border),
		})
		data = netdata.AppendTLV(data, netdata.TLVTypePrefix, true, value)
	}
	return data
}

func newSRPOwnedProofFixture(t *testing.T, localGenerated, advertiseAll bool) *srpOwnedProofFixture {
	t.Helper()
	all := [4]bool{true, true, true, true}
	thread, parent, _ := publicFTDWireFixture(t, srpProofPrefixData(all, all))
	return newSRPOwnedProofFixtureFor(t, thread, parent, localGenerated, advertiseAll)
}

func newSRPOwnedProofFixtureFor(t *testing.T, thread *ownedAttachFixture, parent *fragmentEndpoint, localGenerated, advertiseAll bool) *srpOwnedProofFixture {
	t.Helper()
	fixture := &srpOwnedProofFixture{thread: thread, parent: parent}
	mustSRPLoop(t, thread.node.inst, func() error {
		inst := thread.node.inst
		count := 0
		for _, address := range inst.netif.GetUnicastAddresses() {
			if address.Origin != ip6.OriginSLAAC || !address.Valid || !address.Preferred {
				continue
			}
			for i := range fixture.sources {
				prefix := modelOwnedPrefix
				prefix[5] = byte(i + 1)
				if address.Address.GetPrefix() == prefix.GetPrefix() {
					fixture.sources[i] = address.Address
					count++
				}
			}
		}
		if count != 4 || len(inst.slaacManager.GetAddresses()) != 4 {
			return fmt.Errorf("actual authenticated manager4 assignments absent")
		}
		server := thread.eid
		server[15] ^= 0x55
		fixture.config = SRPConfig{
			Local:    ip6.SockAddr{Address: thread.eid, Port: 40000},
			Server:   ip6.SockAddr{Address: server, Port: 53},
			HostName: "owned-source-host", Addresses: []ip6.Address{thread.eid},
		}
		if localGenerated {
			fixture.config.Local.Address = fixture.sources[0]
		}
		if advertiseAll {
			fixture.config.Addresses = append([]ip6.Address(nil), fixture.sources[:]...)
		}
		var err error
		fixture.binding, err = inst.StartSRP(fixture.config)
		return err
	})
	fixture.server = srp.NewServer(
		srp.WithServerAfterFunc(func(time.Duration, func()) srp.Timer {
			// Only the model server's expiry clock is inert. Request parsing,
			// SIG(0), commit and response generation are real server code.
			return &srpLoopTimer{active: true, cancel: func() {}}
		}),
		srp.WithServerResponder(func(data []byte, peer ip6.SockAddr) {
			fixture.reply, fixture.replyPeer = append([]byte(nil), data...), peer
		}),
	)
	fixture.server.Enable(true)
	if err := fixture.server.Start(53); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fixture.server.Stop)
	return fixture
}

// Drive only actual owned client timers, with a finite step bound. This never
// calls a new App wrapper or forces a client state/source flag.
func driveOwnedSRPTimers(t *testing.T, fixture *srpOwnedProofFixture) {
	t.Helper()
	for range 3 {
		stop := false
		mustSRPLoop(t, fixture.thread.node.inst, func() error {
			stop = fixture.binding.closed || len(fixture.thread.node.driver.captures) != 0
			return nil
		})
		if stop {
			return
		}
		fireSRPTimer(t, fixture.binding)
	}
	t.Fatal("actual SRP timer did not send or terminate within its bounded renewal/update steps")
}

func captureOwnedSRPUpdate(t *testing.T, fixture *srpOwnedProofFixture) []byte {
	t.Helper()
	packet := captureSitePacket(t, fixture.thread.node, func(context *mesh.FrameContext) {
		if !context.SecurityEnabled || context.DstExtAddr != udpPeerExt {
			t.Error("SRP did not use actual secured parent MAC")
		}
	})
	if !bytes.Equal(packet[8:24], fixture.config.Local.Address[:]) ||
		!bytes.Equal(packet[24:40], fixture.config.Server.Address[:]) || !validNativeUDP(packet) {
		t.Fatal("actual native SRP packet changed immutable transport tuple")
	}
	var header dns.Header
	if err := header.UnmarshalBinary(packet[48:]); err != nil || header.GetOpCode() != dns.OpcodeUpdate || header.GetType() != dns.TypeQuery {
		t.Fatal("actual timer did not emit DNS UPDATE")
	}
	return packet
}

func makeOwnedSRPReply(t *testing.T, fixture *srpOwnedProofFixture, packet []byte) []byte {
	t.Helper()
	fixture.reply = nil
	fixture.server.ProcessMessage(packet[48:], fixture.config.Local)
	if len(fixture.reply) < dns.HeaderSize || fixture.replyPeer != fixture.config.Local {
		t.Fatal("real SRP server produced no matching response")
	}
	var header dns.Header
	if err := header.UnmarshalBinary(fixture.reply); err != nil || header.GetResponseCode() != dns.RcodeSuccess {
		t.Fatal("real SIG(0)-validating server rejected initial control update")
	}
	payload := append([]byte(nil), fixture.reply...)
	ipv6 := ip6.NewHeader(fixture.config.Server.Address, fixture.config.Local.Address, ip6.ProtoUDP, 64, uint16(8+len(payload)))
	raw := ipv6.Bytes()
	response := append([]byte(nil), raw[:]...)
	udp := fixtureUDPHeader(fixture.config.Server.Address, fixture.config.Local.Address, 53, fixture.config.Local.Port, payload)
	response = append(response, udp[:]...)
	return append(response, payload...)
}

func deliverOwnedSRPReply(t *testing.T, fixture *srpOwnedProofFixture, packet []byte) {
	t.Helper()
	// Peer model forwards the actual server response through the existing
	// secured native parent path, never as local outbound evidence.
	sendOwnQueryPacket(t, fixture.parent, fixture.thread, packet, true)
	mustSRPLoop(t, fixture.thread.node.inst, func() error { return nil })
}

func registerOwnedSRPControl(t *testing.T, fixture *srpOwnedProofFixture, port uint16) {
	t.Helper()
	service := nativeService("owned-generation")
	service.Port = port
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		_, err := fixture.binding.UpsertService(service)
		return err
	})
	driveOwnedSRPTimers(t, fixture)
	packet := captureOwnedSRPUpdate(t, fixture)
	deliverOwnedSRPReply(t, fixture, makeOwnedSRPReply(t, fixture, packet))
	notice := nextSRPNotice(t, fixture.binding)
	if notice.Err != nil || len(notice.Services) != 1 || notice.Services[0].State != srp.ItemStateRegistered ||
		notice.Services[0].Port != port {
		t.Fatal("real timer/mutation control did not receive actual matching server ACK")
	}
}

func replaceOwnedSRPSourceGeneration(t *testing.T, fixture *srpOwnedProofFixture, index int) {
	t.Helper()
	all := [4]bool{true, true, true, true}
	withdrawn := all
	withdrawn[index] = false
	var before ThreadAttachmentObservation
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		var err error
		before, err = fixture.thread.attempt.ObserveAttachment(fixture.sources[index])
		return err
	})
	sendOwnedPrefixUpdate(t, fixture.thread, fixture.parent, srpProofPrefixData(withdrawn, all), 1, 70, true)
	sendOwnedPrefixUpdate(t, fixture.thread, fixture.parent, srpProofPrefixData(all, all), 2, 71, true)
	mustSRPLoop(t, fixture.thread.node.inst, func() error {
		current, err := fixture.thread.attempt.ObserveAttachment(fixture.sources[index])
		if err != nil || current.Source != before.Source || current.Epoch != before.Epoch || current.SourceGeneration == before.SourceGeneration {
			return fmt.Errorf("actual authenticated withdraw/readd did not replace only source generation")
		}
		return nil
	})
}
