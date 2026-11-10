package instance

import (
	"errors"
	"fmt"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/mle"
)

func TestThreadDiscoveryBusyAttachRejectsBeforeNonceRoleOrRegistrationEffects(t *testing.T) {
	fixture, _ := discoverySourceFixture(t, false)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := phase2AdmissionSnapshot(inst)
		mode, role := inst.mleService.Mle().GetDeviceMode(), inst.mleService.Mle().Role()
		if attach, err := inst.BeginThreadAttachWithConfig(ThreadAttachConfig{Timeout: time.Second, Profile: ThreadAttachAwakeFTDChild}); attach != nil || !errors.Is(err, goterrors.ErrBusy) {
			return fmt.Errorf("live scan did not exclude new attachment admission")
		}
		if phase2AdmissionSnapshot(inst) != before || inst.threadAttach != nil ||
			inst.mleService.Mle().GetDeviceMode() != mode || inst.mleService.Mle().Role() != role ||
			len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("scan-busy attach consumed nonce/counters or changed role/registration")
		}
		return attempt.Cancel()
	})
	awaitDiscoveryOutcome(t, attempt)
}

func TestThreadDiscoveryDoesNotBroadenNormalPostAttachSuiteNoneSender(t *testing.T) {
	fixture, _ := discoverySourceFixture(t, true)
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	mustSRPLoop(t, fixture.node.inst, func() error {
		inst := fixture.node.inst
		before := phase2AdmissionSnapshot(inst)
		for _, command := range []mle.Command{mle.CommandParentResponse, mle.CommandDiscoveryRequest, mle.CommandDiscoveryResponse} {
			message := mle.NewUnsecuredMessage(command)
			if err := inst.SendMLE(message.Bytes(), mle.LinkLocalAllNodesMulticast); err == nil {
				return fmt.Errorf("ordinary caller acquired private scan plaintext TX privilege")
			}
		}
		if phase2AdmissionSnapshot(inst) != before || len(fixture.node.driver.captures) != 0 {
			return fmt.Errorf("rejected plain caller consumed counters or produced a frame")
		}
		return attempt.Cancel()
	})
	awaitDiscoveryOutcome(t, attempt)
}

func TestThreadDiscoveryNilRestoreWithoutActualDriverSleepRetainsOwner(t *testing.T) {
	fixture, driver := discoverySourceFixture(t, false)
	mustSRPLoop(t, fixture.node.inst, func() error {
		fixture.node.inst.mac.SetRxOnWhenIdle(false)
		return nil
	})
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	mustSRPLoop(t, fixture.node.inst, func() error {
		driver.sleepStateMismatch = true
		return attempt.Cancel()
	})
	outcome := awaitDiscoveryOutcome(t, attempt)
	if !errors.Is(outcome.Err, goterrors.ErrInvalidState) {
		t.Fatal("nil setter result masqueraded as actual sleep restoration")
	}
	mustSRPLoop(t, fixture.node.inst, func() error {
		if fixture.node.inst.nativeDiscovery == nil {
			return fmt.Errorf("wrong actual driver state released lease")
		}
		driver.sleepStateMismatch = false
		return attempt.RetryCleanup()
	})
}
