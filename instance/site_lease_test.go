package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/net/coap"
	"github.com/hilli/gothread/net/ip6"
)

func TestDormantGroupDefaultLeaseExpiresWithoutManufacturingReadiness(t *testing.T) {
	fixture, parent := siteNativeFixture(t)
	var handle *MulticastMembership
	mustSRPLoop(t, fixture.node.inst, func() error {
		var err error
		handle, err = fixture.node.inst.JoinMulticast(siteTestAddress(1))
		return err
	})
	packet := captureSitePacket(t, fixture.node)
	request, err := coap.ParseMessage(packet[48:])
	if err != nil {
		t.Fatal(err)
	}
	sendSiteCoapResponse(t, parent, fixture, request, 0, nil)
	mustSRPLoop(t, fixture.node.inst, func() error {
		if status := handle.Status(); status.State != MulticastReady || status.Err != nil {
			return fmt.Errorf("real default-lease response not ready")
		}
		fixture.now = fixture.now.Add(301 * time.Second)
		before := fixture.node.inst.keyManager.GetMacFrameCounter()
		if status := handle.Status(); status.State != MulticastPending || !status.RemoteLeaseUnknown {
			return fmt.Errorf("unrenewed300s lease stayed ready")
		}
		if err := handle.SendUDP([]byte("expired"), ip6.MessageInfo{
			SockAddr: fixture.eid, PeerAddr: siteTestAddress(1), SockPort: 5540, PeerPort: 5540,
		}); !errors.Is(err, goterrors.ErrInvalidState) {
			return fmt.Errorf("expired lease admitted data: %v", err)
		}
		if fixture.node.inst.keyManager.GetMacFrameCounter() != before || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("expired lease consumed a frame")
		}
		return handle.Leave()
	})
}
