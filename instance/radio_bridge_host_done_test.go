package instance

import (
	"errors"
	"sync"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestSDKRadioBridgeStopMilestoneWaitsForActualLoopCleanupReturn(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	scan := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	logger := &radioBridgeLogGate{cause: goterrors.ErrBusy.Error(), entered: make(chan struct{}), release: make(chan struct{})}
	var once sync.Once
	unblock := func() { once.Do(func() { close(logger.release) }) }
	t.Cleanup(unblock)
	mustSRPLoop(t, inst, func() error { inst.logger = logger; return nil })
	if err := inst.StopRadioQuiescent(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("named stop returned before actual loop stop admission")
	}
	waitRadioBridgeSource(t, logger.entered) // Actual loop defer logs retained cleanup Busy.
	if err := inst.StopRadioQuiescent(); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("stop milestone returned before the genuine loop cleanup invocation returned")
	}
	select {
	case <-inst.doneCh:
		t.Fatal("actual loop completion closed inside active cleanup")
	default:
	}
	unblock()
	stopRadioBridgeSource(t, inst)
	_ = awaitDiscoveryOutcome(t, scan)
	if err := inst.RestoreRadioQuiescent(&radioBridgeModelRestorer{inst: inst, driver: driver}); err != nil {
		t.Fatal(err)
	}
}
