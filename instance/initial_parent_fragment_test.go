package instance

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/mac/types"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/platform/simulation"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mesh"
	"github.com/hilli/gothread/thread/mle"
)

func initialParentPending(t *testing.T, timeout time.Duration) (*ownedAttachFixture, *fragmentEndpoint, *datasetWriteFault, []byte) {
	t.Helper()
	store := &datasetWriteFault{SimSettings: simulation.NewSimSettings()}
	fixture := newOwnedAttachFixtureWithSettings(t, true, store)
	parent := newFragmentEndpoint(t, udpPeerExt, fragmentSource, 0x0800, 0x0400, simulation.NewSimSettings())
	mustSRPLoop(t, parent.inst, func() error {
		parent.inst.SetCurrentKeySequence(0x1234, key.ForceUpdate)
		return parent.inst.PersistenceError()
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		fixture.attempt, err = fixture.node.inst.BeginThreadAttach(timeout)
		return err
	})
	fixture.fireProtocolTimer(t)
	command, records := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandParentRequest {
		t.Fatal("no actual outstanding Parent Request")
	}
	challenge, ok := mle.FindTLV(records, mle.TLVChallenge)
	if !ok {
		t.Fatal("missing actual fresh request challenge")
	}
	return fixture, parent, store, append([]byte(nil), challenge...)
}

// Deliberately use the IPv6 dispatch/literal UDP form rather than the
// production compressor: the approved missing case is 1+40+8+81=130>104.
func uncompressedParentPacket(t *testing.T, parent *fragmentEndpoint, fixture *ownedAttachFixture, message *mle.Message, counter uint32, mutate func([]byte)) []byte {
	t.Helper()
	var packet []byte
	mustSRPLoop(t, parent.inst, func() error {
		source, destination := parent.inst.GetLinkLocalAddress(), fixture.node.inst.GetLinkLocalAddress()
		if err := message.Finalize(mle.NewSecurityHeader(parent.inst.keyManager.GetCurrentKeySequence(), counter),
			parent.inst.keyManager.GetCurrentMleKey(), parent.inst.GetExtAddress(), source, destination); err != nil {
			return err
		}
		if mutate != nil {
			mutate(message.Bytes())
		}
		packet = make([]byte, 48+len(message.Bytes()))
		packet[0], packet[6], packet[7] = 0x60, 17, 255
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
		copy(packet[8:24], source[:])
		copy(packet[24:40], destination[:])
		binary.BigEndian.PutUint16(packet[40:42], 19788)
		binary.BigEndian.PutUint16(packet[42:44], 19788)
		binary.BigEndian.PutUint16(packet[44:46], uint16(len(packet)-40))
		copy(packet[48:], message.Bytes())
		literalParentUDPChecksum(packet)
		return nil
	})
	if len(packet) != 129 {
		t.Fatalf("fixture no longer exercises literal 130-byte adaptation form: %d", len(packet)+1)
	}
	return packet
}

func literalParentUDPChecksum(packet []byte) {
	packet[46], packet[47] = 0, 0
	sum := uint32(len(packet)-40) + 17
	for i := 8; i < len(packet); i += 2 {
		sum += uint32(packet[i]) << 8
		if i+1 < len(packet) {
			sum += uint32(packet[i+1])
		}
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	value := ^uint16(sum)
	if value == 0 {
		value = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:48], value)
}

func literalParentFragments(t *testing.T, packet []byte, source, destination types.ExtAddress, tag uint16) []udpRadioCapture {
	t.Helper()
	frameContext := mesh.FrameContext{SrcExtAddr: source, DstExtAddr: destination, PanId: 0xface, AckRequest: true}
	framer := mesh.NewFramer()
	if framer.GetMaxPayloadSize(&frameContext) != 104 {
		t.Fatal("extended/extended unsecured MAC budget is not104")
	}
	var captures []udpRadioCapture
	for offset := 0; offset < len(packet); {
		limit, dispatch := 96, byte(0xe0)
		if offset == 0 {
			dispatch = 0xc0
		}
		end := min(offset+limit, len(packet))
		payload := []byte{dispatch | byte(len(packet)>>8), byte(len(packet)), byte(tag >> 8), byte(tag)}
		if offset == 0 {
			payload = append(payload, 0x41)
		} else {
			payload = append(payload, byte(offset/8))
		}
		payload = append(payload, packet[offset:end]...)
		psdu, err := framer.BuildDataFrame(&frameContext, payload)
		if err != nil {
			t.Fatal(err)
		}
		captures = append(captures, udpRadioCapture{frame: radio.Frame{PSDU: psdu, Channel: 20}})
		offset = end
	}
	return captures
}

type initialParentObservation struct {
	record    []byte
	writes    int
	mac, mle  uint32
	addresses int
}

func observeInitialParent(t *testing.T, fixture *ownedAttachFixture, store *datasetWriteFault) initialParentObservation {
	t.Helper()
	var observation initialParentObservation
	mustSRPLoop(t, fixture.node.inst, func() error {
		record, err := store.Get(platform.SettingsKeyNetworkInfo, 0)
		observation = initialParentObservation{
			record: append([]byte(nil), record...), writes: store.writes,
			mac: fixture.node.inst.keyManager.GetMacFrameCounter(), mle: fixture.node.inst.keyManager.GetMleFrameCounter(),
			addresses: len(fixture.node.inst.netif.GetUnicastAddresses()),
		}
		return err
	})
	return observation
}

func requireNoInitialParentProgress(t *testing.T, fixture *ownedAttachFixture, store *datasetWriteFault, before initialParentObservation) {
	t.Helper()
	after := observeInitialParent(t, fixture, store)
	if !bytes.Equal(before.record, after.record) || before.writes != after.writes ||
		before.mac != after.mac || before.mle != after.mle || before.addresses != after.addresses {
		t.Fatal("unauthenticated/incomplete candidate changed durable state, counters or addresses")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		_, hasCandidate := inst.mleService.Attacher.GetCandidate()
		if hasCandidate || inst.threadAttach == nil || inst.threadAttach.parentAuthenticated ||
			inst.ownedAttachment != nil || inst.mleService.Mle().GetParent().IsStateValid() ||
			inst.mleService.Mle().IsChild() || inst.keyManager.GetCurrentKeySequence() != 0 {
			return fmt.Errorf("unauthenticated/incomplete candidate progressed parent/role/identity")
		}
		select {
		case <-fixture.attempt.Result():
			return fmt.Errorf("candidate published terminal attach result")
		default:
		}
		return nil
	})
}

func TestInitialParentLiteral130RequiresCompleteAuthenticationBeforeWrites(t *testing.T) {
	fixture, parent, store, challenge := initialParentPending(t, 30*time.Second)
	packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 80, nil)
	frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7101)
	if len(frames) != 2 {
		t.Fatal("not the actual two-fragment130-byte form")
	}
	before := observeInitialParent(t, fixture, store)
	deliverAttachCaptures(t, fixture, frames[1:]) // No FRAG1: no candidate/header.
	deliverAttachCaptures(t, fixture, frames[:1])
	requireNoInitialParentProgress(t, fixture, store, before)
	mustSRPLoop(t, fixture.node.inst, func() error {
		candidate := fixture.node.inst.initialMLEFragment
		if candidate == nil || candidate.key.Scope.Source != [8]byte(udpPeerExt) ||
			candidate.state != mle.AttachStateParentRequest || candidate.complete {
			return fmt.Errorf("untrusted FRAG1 not isolated in single owned quarantine")
		}
		return nil
	})
	deliverAttachCaptures(t, fixture, frames[1:])
	after := observeInitialParent(t, fixture, store)
	if after.writes <= before.writes || binary.BigEndian.Uint32(after.record[33:37]) != 0x1234 ||
		binary.BigEndian.Uint32(after.record[37:41]) < binary.BigEndian.Uint32(before.record[37:41]) ||
		binary.BigEndian.Uint32(after.record[41:45]) < binary.BigEndian.Uint32(before.record[41:45]) {
		t.Fatal("complete authenticated response did not adopt durably without high-water rollback")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != nil || !fixture.attempt.parentAuthenticated ||
			fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("authenticated ParentResponse falsely connected or retained quarantine")
		}
		return nil
	})
	fixture.fireProtocolTimer(t)
	command, _ := ownedSentMLE(t, fixture.node, captureUDP(t, fixture.node.driver.boundedUDPRadio))
	if command != mle.CommandChildIDRequest {
		t.Fatal("no subsequent actual CID request")
	}
	sendParentAttachMessage(t, parent, fixture, childIDResponseWithNetworkData(0x0801, largeBootstrapNetworkData()), 81)
	if result := awaitOwnedAttach(t, fixture.attempt); result.Err != nil || result.KeySequence != 0x1234 {
		t.Fatalf("same single quarantine did not support subsequent authenticated CID: %v", result.Err)
	}
}

func TestInitialParentFragmentUnauthenticatedOrIncompleteCannotWriteState(t *testing.T) {
	for _, name := range []string{"wrong-challenge", "bad-mic", "bad-checksum", "forged-sequence", "bad-index", "missing-required", "wrong-command"} {
		t.Run(name, func(t *testing.T) {
			fixture, parent, store, challenge := initialParentPending(t, 30*time.Second)
			if name == "wrong-challenge" {
				challenge[0] ^= 1
			}
			message := parentResponse(challenge)
			if name == "missing-required" {
				message.Bytes()[len(message.Bytes())-10] = 254 // Authenticated but no required Challenge TLV.
			}
			if name == "wrong-command" {
				message.Payload()[0] = byte(mle.CommandChildIDResponse)
			}
			packet := uncompressedParentPacket(t, parent, fixture, message, 90, func(wire []byte) {
				switch name {
				case "bad-mic":
					wire[len(wire)-1] ^= 1
				case "forged-sequence":
					binary.BigEndian.PutUint32(wire[6:10], 0x5678)
					wire[10] = mle.KeyIndexFromSequence(0x5678)
				case "bad-index":
					wire[10] ^= 1
				}
			})
			if name == "bad-checksum" {
				packet[46] ^= 1
			}
			before := observeInitialParent(t, fixture, store)
			deliverAttachCaptures(t, fixture, literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7102))
			requireNoInitialParentProgress(t, fixture, store, before)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if fixture.node.inst.initialMLEFragment != nil {
					return fmt.Errorf("rejected candidate retained quarantine")
				}
				return nil
			})
		})
	}
}

func TestInitialParentSingleCandidateDuplicatesDoNotExtendDeadline(t *testing.T) {
	fixture, parent, store, challenge := initialParentPending(t, 2*time.Minute)
	packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 100, nil)
	frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7103)
	before := observeInitialParent(t, fixture, store)
	deliverAttachCaptures(t, fixture, frames[:1])
	var candidate *initialMLEFragment
	var until time.Time
	mustSRPLoop(t, fixture.node.inst, func() error {
		candidate = fixture.node.inst.initialMLEFragment
		if candidate == nil {
			return fmt.Errorf("missing candidate")
		}
		until = candidate.until
		fixture.now = fixture.now.Add(time.Nanosecond)
		return nil
	})
	otherSource := udpPeerExt
	otherSource[7] ^= 1
	otherPacket := append([]byte(nil), packet...)
	otherIP := linkLocalAddress(otherSource)
	copy(otherPacket[8:24], otherIP[:])
	literalParentUDPChecksum(otherPacket)
	other := literalParentFragments(t, otherPacket, otherSource, fragmentSource, 0x7104)
	deliverAttachCaptures(t, fixture, other[:1])
	deliverAttachCaptures(t, fixture, frames[:1])
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != candidate || !candidate.until.Equal(until) {
			return fmt.Errorf("second peer/duplicate replaced or extended single candidate")
		}
		return nil
	})
	requireNoInitialParentProgress(t, fixture, store, before)
	// A conflicting duplicate, unlike an exact duplicate, must retire the
	// original shared-pool range and cannot be repaired by later FRAGN.
	conflict := literalParentFragments(t, append([]byte(nil), packet...), udpPeerExt, fragmentSource, 0x7103)
	conflict[0].frame.PSDU[len(conflict[0].frame.PSDU)-1] ^= 1
	deliverAttachCaptures(t, fixture, conflict[:1])
	deliverAttachCaptures(t, fixture, frames[1:])
	requireNoInitialParentProgress(t, fixture, store, before)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != nil {
			return fmt.Errorf("conflicting duplicate retained quarantine")
		}
		return nil
	})
}

func TestInitialParentFragmentCancelFencesQueuedAuthentication(t *testing.T) {
	fixture, parent, _, challenge := initialParentPending(t, 30*time.Second)
	packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 110, nil)
	frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7105)
	deliverAttachCaptures(t, fixture, frames[:1])
	mustSRPLoop(t, fixture.node.inst, func() error {
		last := frames[1].frame
		last.RxInfo = &radio.RxInfo{RSSI: -37, LQI: 90}
		fixture.node.inst.subMac.HandleReceiveDone(&last, nil)
		// The copied native MLE task is queued, not allowed to authenticate
		// recursively while the MAC RX lock is held.
		if fixture.node.inst.pendingOwnedMLE == 0 {
			return fmt.Errorf("fixture did not queue completed candidate")
		}
		return fixture.attempt.Cancel()
	})
	if result := awaitOwnedAttach(t, fixture.attempt); !errors.Is(result.Err, context.Canceled) {
		t.Fatal("cancel cause lost")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.keyManager.GetCurrentKeySequence() != 0 ||
			fixture.node.inst.mleService.Mle().IsChild() {
			return fmt.Errorf("late authentication revived stopped generation")
		}
		return nil
	})
}

func TestInitialParentFragmentTupleAndMACSourceFormsFailClosed(t *testing.T) {
	for _, name := range []string{"port", "hop", "ip-source", "ip-destination", "pan", "channel", "short-source", "broadcast-destination"} {
		t.Run(name, func(t *testing.T) {
			fixture, parent, store, challenge := initialParentPending(t, 30*time.Second)
			packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 120, nil)
			switch name {
			case "port":
				binary.BigEndian.PutUint16(packet[42:44], 5540)
			case "hop":
				packet[7] = 64
			case "ip-source":
				packet[23] ^= 1
			case "ip-destination":
				packet[39] ^= 1
			}
			literalParentUDPChecksum(packet)
			frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7106)
			for i := range frames {
				frameContext, offset, err := mesh.NewFramer().ParseFrameHeader(frames[i].frame.PSDU)
				if err != nil {
					t.Fatal(err)
				}
				switch name {
				case "pan":
					frameContext.PanId ^= 1
				case "channel":
					frames[i].frame.Channel = 21
				case "short-source":
					frameContext.UseSrcShort, frameContext.SrcShortAddr = true, 0x0800
				case "broadcast-destination":
					frameContext.UseDstShort, frameContext.DstShortAddr = true, 0xffff
				}
				frames[i].frame.PSDU, err = mesh.NewFramer().BuildDataFrame(frameContext, frames[i].frame.PSDU[offset:])
				if err != nil {
					t.Fatal(err)
				}
			}
			before := observeInitialParent(t, fixture, store)
			deliverAttachCaptures(t, fixture, frames)
			requireNoInitialParentProgress(t, fixture, store, before)
			mustSRPLoop(t, fixture.node.inst, func() error {
				if fixture.node.inst.initialMLEFragment != nil {
					return fmt.Errorf("wrong tuple/source form retained candidate")
				}
				return nil
			})
		})
	}
}

func TestInitialParentFragmentSharesPoolAndExpiresWithoutRemainingFrames(t *testing.T) {
	for _, pressure := range []bool{false, true} {
		t.Run(fmt.Sprint(pressure), func(t *testing.T) {
			fixture, parent, store, challenge := initialParentPending(t, 2*time.Minute)
			var occupied []mesh.FragmentKey
			if pressure {
				mustSRPLoop(t, fixture.node.inst, func() error {
					for i := byte(1); i <= 2; i++ {
						k := mesh.FragmentKey{Scope: mesh.FragmentScope{
							Source: [8]byte{0x20, i}, Destination: [8]byte{0x22, 9}, PanID: 0xface, Channel: 20, Secured: true,
						}, Tag: uint16(i), Size: 1280}
						if _, err := fixture.node.inst.forwarder.HandleScopedFragment(k, 0, make([]byte, 48)); err != nil {
							return err
						}
						occupied = append(occupied, k)
					}
					return nil
				})
			}
			packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 130, nil)
			frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7107)
			before := observeInitialParent(t, fixture, store)
			deliverAttachCaptures(t, fixture, frames[:1])
			requireNoInitialParentProgress(t, fixture, store, before)
			mustSRPLoop(t, fixture.node.inst, func() error {
				candidate := fixture.node.inst.initialMLEFragment
				if pressure {
					if candidate != nil {
						return fmt.Errorf("candidate bypassed existing2560-byte pool pressure")
					}
					for _, k := range occupied {
						fixture.node.inst.forwarder.RejectFragment(k)
					}
					return nil
				}
				if candidate == nil || candidate.until.After(fixture.now.Add(60*time.Second)) {
					return fmt.Errorf("candidate lacks bounded fixed expiry")
				}
				fixture.now = candidate.until.Add(time.Nanosecond)
				fixture.node.inst.timers.processExpired()
				if fixture.node.inst.initialMLEFragment != nil {
					return fmt.Errorf("quarantine needs another incoming frame to expire")
				}
				return nil
			})
			deliverAttachCaptures(t, fixture, frames[1:])
			mustSRPLoop(t, fixture.node.inst, func() error {
				if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.keyManager.GetCurrentKeySequence() != 0 ||
					fixture.node.inst.mleService.Mle().IsChild() {
					return fmt.Errorf("rejected/expired remaining fragments progressed identity/role")
				}
				return nil
			})
		})
	}
}

func TestInitialParentFragmentLegitimateAdoptionWriteFailureIsClosed(t *testing.T) {
	for _, commit := range []bool{false, true} {
		t.Run(fmt.Sprint(commit), func(t *testing.T) {
			fixture, parent, store, challenge := initialParentPending(t, 30*time.Second)
			packet := uncompressedParentPacket(t, parent, fixture, parentResponse(challenge), 140, nil)
			frames := literalParentFragments(t, packet, udpPeerExt, fragmentSource, 0x7108)
			before := observeInitialParent(t, fixture, store)
			deliverAttachCaptures(t, fixture, frames[:1])
			mustSRPLoop(t, fixture.node.inst, func() error {
				store.fail, store.commit = platform.SettingsKeyNetworkInfo, commit
				return nil
			})
			deliverAttachCaptures(t, fixture, frames[1:])
			if result := awaitOwnedAttach(t, fixture.attempt); !errors.Is(result.Err, errOwnedDatasetWrite) ||
				!errors.Is(fixture.node.inst.PersistenceError(), errOwnedDatasetWrite) {
				t.Fatal("original ambiguous adoption error/latch lost")
			}
			after := observeInitialParent(t, fixture, store)
			if binary.BigEndian.Uint32(after.record[37:41]) < binary.BigEndian.Uint32(before.record[37:41]) ||
				binary.BigEndian.Uint32(after.record[41:45]) < binary.BigEndian.Uint32(before.record[41:45]) {
				t.Fatal("failed adoption rewound durable counter high-waters")
			}
			mustSRPLoop(t, fixture.node.inst, func() error {
				if fixture.node.inst.initialMLEFragment != nil || fixture.node.inst.mleService.Mle().IsChild() ||
					len(fixture.node.driver.captures) != 0 {
					return fmt.Errorf("failed adoption retained candidate or admitted CID/success")
				}
				return nil
			})
		})
	}
}
