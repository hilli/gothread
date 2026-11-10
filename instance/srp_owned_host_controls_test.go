package instance

import (
	"errors"
	"fmt"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestOwnedSRPHOSTEveryAdvertisedSlotWithdrawalAndDeprecationKeepsExactCause(t *testing.T) {
	for _, action := range []string{"withdraw", "deprecate"} {
		for slot := range 4 {
			t.Run(fmt.Sprintf("%s-%d", action, slot), func(t *testing.T) {
				fixture := newSRPOwnedProofFixture(t, false, true)
				registerOwnedSRPControl(t, fixture, 5540)
				present, preferred := [4]bool{true, true, true, true}, [4]bool{true, true, true, true}
				if action == "withdraw" {
					present[slot] = false
				} else {
					preferred[slot] = false
				}
				sendOwnedPrefixUpdate(t, fixture.thread, fixture.parent, srpProofPrefixData(present, preferred), 1, 70, true)
				driveOwnedSRPTimers(t, fixture)
				mustSRPLoop(t, fixture.thread.node.inst, func() error {
					inst := fixture.thread.node.inst
					if !errors.Is(fixture.binding.Err(), goterrors.ErrInvalidSourceAddress) ||
						!fixture.binding.closed || inst.udpManager.IsPortInUse(fixture.config.Local.Port) ||
						len(fixture.thread.node.driver.captures) != 0 || inst.forwarder.GetBufferUsage().TxDatagrams != 0 {
						return fmt.Errorf("actual slot%d %s lost exact invalid-source cause/cleanup or emitted new wire", slot, action)
					}
					return nil
				})
			})
		}
	}
}
