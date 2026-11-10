package instance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	goterrors "github.com/hilli/gothread/errors"
)

func TestDiscoveryHOSTCleanupRejectedWhileActualStopWaitsForStartedDo(t *testing.T) {
	fixture, driver := discoveryDSFixture(t, nil, false)
	inst := fixture.node.inst
	attempt := beginSourceDiscovery(t, fixture, 1<<15)
	assertActualDiscoveryRequest(t, fixture, 15)
	restore := errors.New("HOST retained home restoration fault")
	mustSRPLoop(t, inst, func() error {
		driver.failChannel, driver.receiveErr = 20, restore
		return attempt.Cancel()
	})
	if result := awaitDiscoveryOutcome(t, attempt); !errors.Is(result.Err, restore) {
		t.Fatal("no actual failed restoration before Stop control")
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	opDone := make(chan error, 1)
	go func() {
		opDone <- inst.Do(context.Background(), func() error { close(entered); <-release; return nil })
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("actual Do did not start")
	}
	stopped := make(chan struct{})
	go func() { inst.Stop(); close(stopped) }()
	deadline := time.Now().Add(time.Second)
	for {
		inst.runningMu.Lock()
		stopping := inst.stopping
		inst.runningMu.Unlock()
		if stopping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("actual Stop did not close admission")
		}
		time.Sleep(time.Millisecond)
	}
	if err := attempt.CleanupStopped(); !errors.Is(err, goterrors.ErrInvalidState) {
		t.Fatalf("cleanup admitted while actual Stop waits: %v", err)
	}
	select {
	case <-stopped:
		t.Fatal("Stop returned before actual started Do")
	default:
	}
	unblock()
	if err := <-opDone; err != nil {
		t.Fatal(err)
	}
	<-stopped
	driver.receiveErr = nil
	if err := attempt.CleanupStopped(); err != nil {
		t.Fatal(err)
	}
}
