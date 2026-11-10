package instance

import (
	"fmt"
	"testing"
	"time"

	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
	"github.com/hilli/gothread/radio"
)

func TestDormantOwnAddressControlsShareEngineAndBoundPressureStop(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
	control := fixture.node.inst.ownedTMF
	engine := control.engine
	var notifications []*coap.Message
	for index := 0; index < maxOwnedAddressNotifications; index++ {
		query := ownQueryPacket(t, fixture, origin, fixture.eid, uint16(0x7200+index), uint8(index+1), nil)
		sendOwnQueryPacket(t, parent, fixture, query, true)
		packet := captureSitePacket(t, fixture.node)
		message, err := coap.ParseMessage(packet[48:])
		if err != nil {
			t.Fatal(err)
		}
		notifications = append(notifications, message)
	}
	var before [3]uint32
	var group *MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		before = [3]uint32{fixture.node.inst.keyManager.GetMacFrameCounter(), fixture.node.inst.keyManager.GetMleFrameCounter(), uint32(fixture.node.inst.entropy.(*ownedTestEntropy).source.calls)}
		return nil
	})
	query := ownQueryPacket(t, fixture, origin, fixture.eid, 0x7300, 20, nil)
	sendOwnQueryPacket(t, parent, fixture, query, true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		after := [3]uint32{inst.keyManager.GetMacFrameCounter(), inst.keyManager.GetMleFrameCounter(), uint32(inst.entropy.(*ownedTestEntropy).source.calls)}
		if after != before || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("own-control pressure admitted entropy/state/response")
		}
		handle, err := inst.JoinMulticast(siteTestAddress(1))
		if err != nil {
			return err
		}
		if inst.siteGroups.client.engine != engine || inst.siteGroups.client != control {
			return fmt.Errorf("group added a second control engine")
		}
		group = handle
		return nil
	})
	captureSitePacket(t, fixture.node)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := group.Leave(); err != nil {
			return err
		}
		active := 0
		for _, pending := range control.ownNotifications {
			if pending != nil {
				active++
			}
		}
		if active != maxOwnedAddressNotifications || control.engine != engine || control.stopped {
			return fmt.Errorf("group Leave canceled unrelated own controls")
		}
		return nil
	})
	// Complete one real ACK after group leave, then stop the actual attachment.
	sendOwnNotificationAck(t, parent, fixture, origin, notifications[0].GetMessageID(), true)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if err := fixture.node.inst.ThreadStop(); err != nil {
			return err
		}
		for _, pending := range control.ownNotifications {
			if pending != nil {
				return fmt.Errorf("Stop deferred control cancellation until a later deadline")
			}
		}
		return nil
	})
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.now = fixture.now.Add(time.Minute)
		fixture.node.inst.timers.processExpired()
		if fixture.node.inst.ownedTMF != nil || fixture.node.inst.netif.IsMulticastSubscribed(ip6.MulticastRealmLocalAllRouters) {
			return fmt.Errorf("role stop retained owned query resource/subscription")
		}
		for _, pending := range control.ownNotifications {
			if pending != nil {
				return fmt.Errorf("stop retained response ownership")
			}
		}
		return nil
	})
}

func TestDormantOwnAddressRemovalAndHealthFenceQueuedQuery(t *testing.T) {
	for _, kind := range []string{"removed", "health", "stop"} {
		t.Run(kind, func(t *testing.T) {
			fixture, parent := siteNativeFixture(t)
			origin := meshLocator(fixture.node.inst.meshLocalPrefix, 0x0c00)
			query := ownQueryPacket(t, fixture, origin, fixture.eid, 0x7401, 1, nil)
			captures := captureOwnQueryPacket(t, parent, fixture, query, true)
			mustSRPLoop(t, fixture.node.inst, func() error {
				for _, capture := range captures {
					frame := capture.frame
					frame.RxInfo = &radio.RxInfo{RSSI: -37, LQI: 90}
					fixture.node.inst.subMac.HandleReceiveDone(&frame, nil)
				}
				if fixture.node.inst.ownedTMF == nil || !fixture.node.inst.ownedTMF.pendingRx {
					return fmt.Errorf("actual realm frame did not queue owned control")
				}
				switch kind {
				case "removed":
					for _, address := range fixture.node.inst.netif.GetUnicastAddresses() {
						if address.Address == fixture.eid {
							assigned := address
							fixture.node.inst.netif.RemoveUnicastAddress(&assigned)
							break
						}
					}
				case "health":
					fixture.node.inst.entropy.(*ownedTestEntropy).latch(errSRPEntropy)
				case "stop":
					return fixture.node.inst.ThreadStop()
				}
				return nil
			})
			mustSRPLoop(t, fixture.node.inst, func() error {
				if len(fixture.node.driver.captures) != 0 || fixture.node.inst.forwarder.GetBufferUsage().TxBytes != 0 {
					return fmt.Errorf("removed/failed/stopped owner admitted notification")
				}
				return nil
			})
		})
	}
}
