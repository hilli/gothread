package instance

import (
	"fmt"
	"testing"

	"github.com/hilli/gothread/net/coap"
)

func TestDormantAcceptedMlrIdleDoesNotAllocateAnotherToken(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	mustSRPLoop(t, fixture.node.inst, func() error {
		_, err := fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	packet := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		entropy := fixture.node.inst.entropy.(*ownedTestEntropy)
		calls := entropy.source.calls
		client := fixture.node.inst.siteGroups.client
		for i := 0; i < 80; i++ {
			if err := client.start(); err != nil {
				return err
			}
		}
		if entropy.source.calls != calls || client.pending != nil || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("idle accepted memberships consumed fresh token/state/TX")
		}
		return nil
	})
}
