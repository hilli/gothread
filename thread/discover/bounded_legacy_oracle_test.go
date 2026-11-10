package discover

import (
	"errors"
	"testing"
	"time"
)

// Existing APIs only: applicable unchanged to accepted5aee before any future
// compile-first causal comparison. No execution is claimed by this source.
type boundLegacySender struct {
	calls  int
	failAt int
	cause  error
}

func (sender *boundLegacySender) SendDiscoveryRequest(uint16, uint16, bool) error {
	sender.calls++
	if sender.calls == sender.failAt {
		return sender.cause
	}
	return nil
}

type boundLegacyTimer struct{ running bool }

func (timer *boundLegacyTimer) Start(uint32)    { timer.running = true }
func (timer *boundLegacyTimer) Stop()           { timer.running = false }
func (timer *boundLegacyTimer) IsRunning() bool { return timer.running }

func boundedLegacyResult(index byte) ScanResult {
	return ScanResult{NetworkName: "network", ExtPanID: [8]byte{1, 2, 3},
		SteeringData: []byte{1, 2}, ExtAddress: [8]byte{2, 0, 0, 0, 0, 0, 0, index},
		Channel: 11, PanID: 0x1234, Version: 4}
}

func TestDiscoveryExistingResultsOwnBothIngressAndReturnedSteeringData(t *testing.T) {
	scanner := NewScanner(&boundLegacySender{}, &boundLegacyTimer{})
	if err := scanner.Discover(1<<11, 0xffff, false, func(*ScanResult) {}); err != nil {
		t.Fatal(err)
	}
	result := boundedLegacyResult(1)
	scanner.HandleDiscoveryResponse(&result)
	result.SteeringData[0] = 9
	first := scanner.Results()
	if first[0].SteeringData[0] != 1 {
		t.Fatal("scanner retained caller/driver steering alias")
	}
	first[0].SteeringData[0] = 8
	if scanner.Results()[0].SteeringData[0] != 1 {
		t.Fatal("Results exposed retained steering storage")
	}
}

func TestDiscoveryExistingInitialSendFailureReleasesAndCompletes(t *testing.T) {
	cause := errors.New("initial actual sender failure")
	sender, timer := &boundLegacySender{failAt: 1, cause: cause}, &boundLegacyTimer{}
	scanner := NewScanner(sender, timer)
	terminal := 0
	if err := scanner.Discover(1<<11, 0xffff, false, func(result *ScanResult) {
		if result == nil {
			terminal++
		}
	}); !errors.Is(err, cause) {
		t.Fatal("initial sender cause lost")
	}
	if scanner.IsScanning() || terminal != 1 || timer.IsRunning() {
		t.Fatal("initial sender failure retained scan or omitted terminal cleanup")
	}
}

func TestDiscoveryExistingRetentionIsFiniteAndDuplicatesDoNotConsumeSlots(t *testing.T) {
	scanner := NewScanner(&boundLegacySender{}, &boundLegacyTimer{})
	terminal := 0
	if err := scanner.Discover(1<<11, 0xffff, false, func(result *ScanResult) {
		if result == nil {
			terminal++
		}
	}); err != nil {
		t.Fatal(err)
	}
	first := boundedLegacyResult(1)
	for count := 0; count < 32; count++ {
		scanner.HandleDiscoveryResponse(&first)
	}
	if len(scanner.Results()) != 1 {
		t.Fatal("duplicate response consumed retained slots")
	}
	for index := byte(2); index <= 17; index++ {
		result := boundedLegacyResult(index)
		scanner.HandleDiscoveryResponse(&result)
	}
	if len(scanner.Results()) != 16 || scanner.IsScanning() || terminal != 1 {
		t.Fatal("unique discovery overflow was unbounded or looked like continuing success")
	}
}

func TestDiscoveryExistingCallbacksCanReenterWithoutMutexAndCannotFinishNewScan(t *testing.T) {
	scanner := NewScanner(&boundLegacySender{}, &boundLegacyTimer{})
	done := make(chan error, 1)
	handler := func(result *ScanResult) {
		if result != nil {
			_ = scanner.Results()
			scanner.Stop()
			return
		}
		if scanner.IsScanning() {
			done <- errors.New("terminal callback retained active lock/state")
			return
		}
		done <- scanner.Discover(1<<12, 0xffff, false, func(*ScanResult) {})
	}
	if err := scanner.Discover(1<<11, 0xffff, false, handler); err != nil {
		t.Fatal(err)
	}
	go func() { result := boundedLegacyResult(1); scanner.HandleDiscoveryResponse(&result) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("result/terminal callback reentry deadlocked Scanner mutex")
	}
	if !scanner.IsScanning() || scanner.CurrentChannel() != 12 {
		t.Fatal("old result callback finished or rewound reentrant new scan")
	}
}
