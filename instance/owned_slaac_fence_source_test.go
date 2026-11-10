package instance

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/thread/mle"
	"github.com/hilli/gothread/thread/netdata"
)

func ownedPrefixResponse(data []byte, version uint8) *mle.Message {
	message := mle.NewMessage(mle.CommandDataResponse)
	message.AppendSourceAddressTLV(0x0800)
	message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2, DataVersion: version})
	message.AppendNetworkDataTLV(data)
	return message
}

func TestOwnedSlaacQueuedOldSourceCannotSurviveAuthenticatedWithdrawReadd(t *testing.T) {
	fixture, parent, _ := publicFTDWireFixture(t, ownedPrefixWire(true))
	source := actualOwnedSlaacAddress(t, fixture)
	var old ThreadAttachmentObservation
	destination := ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 0x61}
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		old, err = fixture.attempt.ObserveAttachment(source)
		if err != nil {
			return err
		}
		return fixture.node.inst.SendUDP(bytes.Repeat([]byte{0x62}, 1232), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	first := captureUDP(t, fixture.node.driver.boundedUDPRadio)
	withdraw := captureParentAttachMessage(t, parent, fixture, ownedPrefixResponse(nil, 1), 70, nil)
	readd := captureParentAttachMessage(t, parent, fixture, ownedPrefixResponse(ownedPrefixWire(true), 2), 71, nil)
	if len(withdraw) != 1 || len(readd) != 1 {
		t.Fatal("model update unexpectedly needs a new unsecured fragment exception")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		// First data frame was already handed to Radio; its late completion
		// is not rolled back. Two real authenticated parent updates queue.
		deliverPhase2RawFrames(fixture, withdraw)
		deliverPhase2RawFrames(fixture, readd)
		return nil
	})
	var counter uint32
	mustSRPLoop(t, fixture.node.inst, func() error {
		current, err := fixture.attempt.ObserveAttachment(source)
		if err != nil || current == old || current.Epoch != old.Epoch {
			return fmt.Errorf("actual same-address prefix readdition did not replace only source generation")
		}
		counter = fixture.node.inst.keyManager.GetMacFrameCounter()
		return nil
	})
	completeNativeFrame(t, fixture.node, first, nil)
	waitUDPCondition(t, fixture.node.inst, func() bool {
		return fixture.node.inst.forwarder.GetBufferUsage().TxDatagrams == 0 ||
			fixture.node.inst.keyManager.GetMacFrameCounter() != counter || len(fixture.node.driver.captures) != 0
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.keyManager.GetMacFrameCounter() != counter || len(fixture.node.driver.captures) != 0 ||
			fixture.node.inst.forwarder.GetCounters().TxDropped == 0 {
			return fmt.Errorf("old admitted source produced a later fragment/counter after withdraw/readd")
		}
		return fixture.node.inst.SendUDP([]byte("fresh-source-generation"), ip6.MessageInfo{
			SockAddr: source, PeerAddr: destination, SockPort: 5540, PeerPort: 5540,
		})
	})
	packet := captureSitePacket(t, fixture.node)
	if !bytes.Equal(packet[8:24], source[:]) || string(packet[48:]) != "fresh-source-generation" {
		t.Fatal("fresh trusted source generation could not use ordinary native sender")
	}
}

func modelPrefixConfig(length, domain uint8, entry netdata.BorderRouterEntry) []byte {
	border := netdata.AppendBorderRouterEntry(nil, entry)
	sub := netdata.AppendTLV(nil, netdata.TLVTypeBorderRouter, true, border)
	value := netdata.AppendPrefixValue(nil, netdata.PrefixTLVInfo{
		DomainID: domain, Prefix: ip6.NewPrefix([16]byte(modelOwnedPrefix), length), SubTLVsData: sub,
	})
	return netdata.AppendTLV(nil, netdata.TLVTypePrefix, true, value)
}

func TestOwnedSlaacBadUnsupportedOrUnauthenticatedPrefixesHaveNoSourceEffects(t *testing.T) {
	for _, kind := range []string{"length", "domain", "dhcp", "configure", "domain-prefix", "malformed", "unsecured", "nonparent"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent, _ := publicFTDWireFixture(t, nil)
			entry := netdata.BorderRouterEntry{RLOC16: 0x0800, OnMesh: true, SLAAC: true, Preferred: true}
			length, domain := uint8(64), uint8(0)
			switch kind {
			case "length":
				length = 48
			case "domain":
				domain = 1
			case "dhcp":
				entry.DHCP = true
			case "configure":
				entry.Configure = true
			case "domain-prefix":
				entry.Dp = true
			}
			data := modelPrefixConfig(length, domain, entry)
			if kind == "malformed" {
				data = data[:len(data)-1]
			}
			mustSRPLoop(t, fixture.node.inst, fixture.node.inst.mleService.ChildHandlers.SendDataRequest)
			ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
			var counters phase2AdmissionCounters
			mustSRPLoop(t, fixture.node.inst, func() error { counters = phase2AdmissionSnapshot(fixture.node.inst); return nil })
			message := ownedPrefixResponse(data, 1)
			if kind == "unsecured" {
				message = mle.NewUnsecuredMessage(mle.CommandDataResponse)
				message.AppendSourceAddressTLV(0x0800)
				message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 1, Weighting: 64, LeaderRouterID: 2})
				message.AppendNetworkDataTLV(data)
			}
			sender := parent
			if kind == "nonparent" {
				sender = newFragmentEndpoint(t, controlPeerExt, fragmentSource, 0x0c00, 0x0801, simulation.NewSimSettings())
			}
			sendParentAttachMessage(t, sender, fixture, message, 70)
			mustSRPLoop(t, fixture.node.inst, func() error {
				inst := fixture.node.inst
				for _, address := range inst.netif.GetUnicastAddresses() {
					if address.Origin == ip6.OriginSLAAC {
						return fmt.Errorf("bad/untrusted prefix created actual Netif source")
					}
				}
				if phase2AdmissionSnapshot(inst) != counters || len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("bad prefix consumed entropy/counters or emitted control response")
				}
				return nil
			})
		})
	}
}

func TestOwnedSlaacPublicSettersAndExternalFlagsDoNotCreateAuthority(t *testing.T) {
	fixture, _, _ := publicFTDWireFixture(t, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		if err := inst.netdataLeader.RegisterNetworkData(0x0800, ownedPrefixWire(true)); err != nil {
			return err
		}
		inst.updateSlaacAddresses()
		// A caller may own an externally assigned global address, but cannot
		// turn OriginSLAAC into authenticated prefix provenance.
		manual := modelOwnedPrefix
		manual[15] = 0x71
		if err := inst.netif.AddExternalUnicastAddress(&ip6.UnicastAddress{
			Address: manual, PrefixLength: 64, Origin: ip6.OriginSLAAC, Valid: true, Preferred: true,
		}); err != nil {
			return err
		}
		if _, err := fixture.attempt.ObserveAttachment(manual); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
			return fmt.Errorf("generic setter/Origin flag became trusted source authority: %v", err)
		}
		err := inst.SendUDP([]byte("not-owned"), ip6.MessageInfo{
			SockAddr: manual, PeerAddr: ip6.Address{0x20, 1, 0x0d, 0xb8, 0, 2, 15: 1}, SockPort: 5540, PeerPort: 5540,
		})
		if !errors.Is(err, goterrors.ErrInvalidSourceAddress) || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("untrusted public flags admitted owned OMR handoff")
		}
		return nil
	})
}

func TestOwnedSlaacActualLeaderTransitionCannotMintBeforeAcceptedNetworkData(t *testing.T) {
	for _, withData := range []bool{false, true} {
		t.Run(fmt.Sprint(withData), func(t *testing.T) {
			data := ownedPrefixWire(true)
			fixture, parent, _ := publicFTDWireFixture(t, data)
			source := actualOwnedSlaacAddress(t, fixture)
			var old ThreadAttachmentObservation
			mustSRPLoop(t, fixture.node.inst, func() error {
				var err error
				old, err = fixture.attempt.ObserveAttachment(source)
				return err
			})
			message := mle.NewMessage(mle.CommandDataResponse)
			message.AppendSourceAddressTLV(0x0800)
			message.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 2, Weighting: 64, LeaderRouterID: 2, DataVersion: 1})
			if withData {
				message.AppendNetworkDataTLV(data)
			}
			sendParentAttachMessage(t, parent, fixture, message, 70)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if !fixture.node.inst.mleService.Mle().NeedsNewNetworkData() || fixture.node.inst.netif.HasUnicastAddress(source) {
					return fmt.Errorf("pending new leader data retained/minted an actual owned source")
				}
				if _, err := fixture.attempt.ObserveAttachment(source); !errors.Is(err, goterrors.ErrInvalidSourceAddress) {
					return fmt.Errorf("unaccepted new-leader data became source authority")
				}
				return nil
			})
			accepted := mle.NewMessage(mle.CommandDataResponse)
			accepted.AppendSourceAddressTLV(0x0800)
			accepted.AppendLeaderDataTLV(mle.LeaderData{PartitionID: 2, Weighting: 64, LeaderRouterID: 2, DataVersion: 2})
			accepted.AppendNetworkDataTLV(data)
			sendParentAttachMessage(t, parent, fixture, accepted, 71)
			mustSRPLoop(t, fixture.node.inst, func() error {
				current, err := fixture.attempt.ObserveAttachment(source)
				if err != nil || current == old || current.Epoch != old.Epoch {
					return fmt.Errorf("accepted same-address new-leader data revived old source proof or rotated epoch")
				}
				return nil
			})
		})
	}
}
