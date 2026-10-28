package instance

import (
	"testing"
	"time"
)

func TestCancelledLoopTimersReleaseStorage(t *testing.T) {
	scheduler := &timerScheduler{}
	for range 2000 {
		cancel := scheduler.scheduleWithCancel(7*24*time.Hour, func() {
			t.Error("cancelled long lease timer ran")
		})
		cancel()
		cancel()
	}
	if scheduler.count() != 0 {
		t.Fatal("replaced/paused long-lease timers accumulate")
	}
}
