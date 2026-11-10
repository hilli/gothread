package mac

import (
	"testing"

	"github.com/hilli/gothread/mac/submac"
	"github.com/hilli/gothread/radio"
)

func TestDiscoveryHOSTStoppedRestoreDoesNotSchedulePendingMAC(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		driver := newMockRadio(radio.CapNone)
		sm := submac.New(submac.Config{Radio: driver})
		runner := &operationRunner{}
		m := New(Config{SubMac: sm, PostOperation: runner.post})
		if err := m.Enable(); err != nil {
			t.Fatal(err)
		}
		m.SetRxOnWhenIdle(true)
		lease, err := m.AcquireDiscoveryRadio()
		if err != nil {
			t.Fatal(err)
		}
		m.RequestBeaconTransmission()
		runner.run()
		pending := m.GetPendingOperations()
		if pending != OperationTransmitBeacon || len(runner.pending) != 0 {
			t.Fatal("actual lease did not retain requested ordinary MAC operation")
		}
		if stopped {
			err = lease.RestoreStopped()
		} else {
			err = lease.Restore()
		}
		if err != nil {
			t.Fatal(err)
		}
		if stopped && len(runner.pending) != 0 {
			t.Fatal("stopped restore scheduled pending MAC operation")
		}
		if !stopped && len(runner.pending) != 1 {
			t.Fatal("ordinary restoration positive control did not schedule pending operation")
		}
		if m.GetPendingOperations() != pending || m.GetCurrentOperation() != OperationIdle ||
			driver.GetState() != radio.StateReceive {
			t.Fatal("restoration consumed pending operation or failed actual home receive")
		}
	}
}
