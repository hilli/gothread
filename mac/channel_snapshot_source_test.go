package mac

import (
	"testing"
	"time"
)

func TestPanChannelSnapshotDoesNotReenterFrameMutex(t *testing.T) {
	mac := New(Config{})
	if got := mac.GetPanChannelSnapshot(); got != mac.GetPanChannel() {
		t.Fatal("constructor channel snapshot differs")
	}
	mac.SetPanChannel(20)
	mac.mu.Lock()
	defer mac.mu.Unlock()
	result := make(chan uint8, 1)
	go func() { result <- mac.GetPanChannelSnapshot() }()
	select {
	case channel := <-result:
		if channel != 20 {
			t.Fatal("configured channel not observed")
		}
	case <-time.After(time.Second):
		t.Fatal("snapshot re-entered held frame callback mutex")
	}
}
