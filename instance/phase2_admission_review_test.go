package instance

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/net/udp"
	"github.com/hilli/gothread/platform"
	"github.com/hilli/gothread/radio"
	"github.com/hilli/gothread/thread/key"
	"github.com/hilli/gothread/thread/mle"
)

// These oracles use only APIs/helpers present in exactaa2. The identical files
// must compile there before any later old/fixed executed assertion comparison.
type phase2AdmissionCounters struct {
	mac, mle uint32
	entropy  int
}

func phase2AdmissionSnapshot(inst *Instance) phase2AdmissionCounters {
	return phase2AdmissionCounters{mac: inst.keyManager.GetMacFrameCounter(),
		mle: inst.keyManager.GetMleFrameCounter(), entropy: inst.entropy.(*ownedTestEntropy).source.calls}
}

func deliverPhase2RawFrames(fixture *ownedAttachFixture, captures []udpRadioCapture) {
	for _, capture := range captures {
		frame := capture.frame
		frame.PSDU = append([]byte(nil), frame.PSDU...)
		frame.RxInfo = &radio.RxInfo{RSSI: -37, LQI: 90}
		fixture.node.inst.subMac.HandleReceiveDone(&frame, nil)
		clear(frame.PSDU)
	}
}

func phase2ParentRotationFrames(t *testing.T, fixture *ownedAttachFixture, parent *fragmentEndpoint) []udpRadioCapture {
	t.Helper()
	advertisement := mle.NewMessage(mle.CommandAdvertisement)
	advertisement.AppendSourceAddressTLV(0x0800)
	mustSRPLoop(t, fixture.node.inst, func() error {
		advertisement.AppendLeaderDataTLV(fixture.node.inst.mleService.Mle().GetLeaderData())
		return nil
	})
	mustSRPLoop(t, parent.inst, func() error {
		parent.inst.SetCurrentKeySequence(1, key.ForceUpdate|key.ResetGuardTimer)
		return parent.inst.PersistenceError()
	})
	return captureParentAttachMessage(t, parent, fixture, advertisement, 2, nil)
}

func TestPhase2QueuedOwnQueryRetainsAdmissionAcrossActualParentRotation(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	stale := captureOwnQueryPacket(t, parent, fixture,
		ownQueryPacket(t, fixture, origin, fixture.eid, 0x7801, 1, nil), true)
	previous := captureOwnQueryPacket(t, parent, fixture,
		ownQueryPacket(t, fixture, origin, fixture.eid, 0x7802, 2, nil), true)
	rotation := phase2ParentRotationFrames(t, fixture, parent)
	var afterRotation phase2AdmissionCounters
	var rotationErr error
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		epoch := inst.threadEpoch
		before, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
		if err != nil {
			return err
		}
		before = append([]byte(nil), before...)
		deliverPhase2RawFrames(fixture, rotation)
		if inst.pendingOwnedMLE != 1 || inst.keyManager.GetCurrentKeySequence() != 0 {
			return fmt.Errorf("actual parent RX was not deferred ahead of query admission")
		}
		// This observation runs after real deferred MLE adoption but before
		// the following query task. It does not change security/role state.
		inst.taskCh <- loopTask{fn: func() {
			after, err := fixture.store.Get(platform.SettingsKeyNetworkInfo, 0)
			if err != nil {
				rotationErr = err
			} else if inst.keyManager.GetCurrentKeySequence() != 1 ||
				inst.mleService.Mle().GetParent().KeySequence != 1 || inst.threadEpoch != epoch ||
				inst.PersistenceError() != nil || bytes.Equal(before, after) {
				rotationErr = fmt.Errorf("parent did not actually adopt/persist S+1 without changing attachment epoch")
			}
			afterRotation = phase2AdmissionSnapshot(inst)
			fixture.node.macKey = inst.keyManager.GetCurrentMacKey()
		}}
		deliverPhase2RawFrames(fixture, stale)
		if !inst.ownedTMF.pendingRx || inst.keyManager.GetCurrentKeySequence() != 0 {
			return fmt.Errorf("S-authenticated query did not queue behind actual parent adoption")
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if rotationErr != nil {
			return rotationErr
		}
		inst := fixture.node.inst
		if phase2AdmissionSnapshot(inst) != afterRotation || len(fixture.node.driver.captures) != 0 ||
			inst.forwarder.GetBufferUsage().TxBytes != 0 {
			return fmt.Errorf("old queued query acquired S+1 response/token/entropy/counter authority")
		}
		for _, pending := range inst.ownedTMF.ownNotifications {
			if pending != nil {
				return fmt.Errorf("old queued query created notification ownership")
			}
		}
		return nil
	})
	// A genuine previous-key packet first admitted AFTER rotation retains the
	// existing MAC grace policy; only a crossing queued authorization is stale.
	var replayLeader mle.LeaderData
	mustSRPLoop(t, fixture.node.inst, func() error {
		replayLeader = fixture.node.inst.mleService.Mle().GetLeaderData()
		return nil
	})
	replayLeader.DataVersion++
	replay := mle.NewMessage(mle.CommandAdvertisement)
	replay.AppendSourceAddressTLV(0x0800)
	replay.AppendLeaderDataTLV(replayLeader)
	// A newly encoded authentic message reusing the already-accepted S+1
	// counter must not reach the handler and trigger its Data Request.
	sendParentAttachMessage(t, parent, fixture, replay, 2)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if phase2AdmissionSnapshot(fixture.node.inst) != afterRotation || len(fixture.node.driver.captures) != 0 ||
			fixture.node.inst.mleService.Mle().GetParent().Counters.MleFrameCounter != 2 {
			return fmt.Errorf("same-key authentic counter replay changed handler/security/traffic state")
		}
		return nil
	})
	for _, kind := range []string{"previous-key-new-admission", "current-key-new-admission"} {
		if kind == "previous-key-new-admission" {
			for _, frame := range previous {
				deliverNativeFrame(t, fixture.node, frame)
			}
			mustSRPLoop(t, fixture.node.inst, func() error { return nil })
		} else {
			sendOwnQueryPacket(t, parent, fixture,
				ownQueryPacket(t, fixture, origin, fixture.eid, 0x7803, 3, nil), true)
		}
		packet := captureSitePacket(t, fixture.node)
		notification, err := coap.ParseMessage(packet[48:])
		if err != nil {
			t.Fatal(err)
		}
		target, iid, rloc := ownNotificationPayload(t, notification)
		if notification.GetType() != coap.TypeConfirmable || target != fixture.eid ||
			iid != [8]byte(fixture.eid.GetIid()) || rloc != 0x0801 || !bytes.Equal(packet[24:40], origin[:]) {
			t.Fatalf("%s lost real current-admission own notification", kind)
		}
		sendOwnNotificationAck(t, parent, fixture, origin, notification.GetMessageID(), true)
	}
}

func phase2ReviewGroupPacket(t *testing.T, fixture *ownedAttachFixture, sequence uint8, payload string) []byte {
	t.Helper()
	source := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0800)
	packet, err := encodeSiteTunnel([]byte(payload), ip6.MessageInfo{
		SockAddr: source, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540, HopLimit: 64,
	}, source, 0x0800, sequence)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestPhase2QueuedGroupRXRetainsAdmissionAcrossActualParentRotation(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
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
	requestPacket := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(requestPacket[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	stale := captureOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 1, "stale-admission"), true)
	previous := captureOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 2, "previous-key-new-admission"), true)
	rotation := phase2ParentRotationFrames(t, fixture, parent)
	var afterRotation phase2AdmissionCounters
	var rotationErr error
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		epoch := inst.threadEpoch
		deliverPhase2RawFrames(fixture, rotation)
		if inst.pendingOwnedMLE != 1 || inst.keyManager.GetCurrentKeySequence() != 0 {
			return fmt.Errorf("actual parent adoption did not queue before old group admission")
		}
		inst.taskCh <- loopTask{fn: func() {
			if inst.keyManager.GetCurrentKeySequence() != 1 || inst.mleService.Mle().GetParent().KeySequence != 1 ||
				inst.threadEpoch != epoch || inst.PersistenceError() != nil {
				rotationErr = fmt.Errorf("actual parent rotation did not retain the current attached epoch")
			}
			afterRotation = phase2AdmissionSnapshot(inst)
			fixture.node.macKey = inst.keyManager.GetCurrentMacKey()
		}}
		deliverPhase2RawFrames(fixture, stale)
		if inst.siteGroups == nil || inst.siteGroups.pendingRx != 1 {
			return fmt.Errorf("S-authenticated group did not queue through normal UDP owner delivery")
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		if rotationErr != nil {
			return rotationErr
		}
		if len(received) != 0 || phase2AdmissionSnapshot(fixture.node.inst) != afterRotation {
			return fmt.Errorf("S-admitted group crossed rotation into the application callback")
		}
		return nil
	})
	for _, capture := range previous {
		deliverNativeFrame(t, fixture.node, capture)
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(received) != 1 || received[0] != "previous-key-new-admission" {
			return fmt.Errorf("fresh valid admission blanket-rejected previous-key group")
		}
		return nil
	})
	sendOwnQueryPacket(t, parent, fixture, phase2ReviewGroupPacket(t, fixture, 3, "current-key-new-admission"), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if len(received) != 2 || received[1] != "current-key-new-admission" {
			return fmt.Errorf("current-key group did not reach actual application socket")
		}
		return nil
	})
}
