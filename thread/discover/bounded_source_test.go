package discover

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

// New bounded outcome/identity/cleanup APIs: candidate-only, not old proof.
type boundedSourceBackend struct {
	boundLegacySender
	cleanupErr   error
	cleanupCalls int
}

func (backend *boundedSourceBackend) FinishDiscovery(uint64) error {
	backend.cleanupCalls++
	return backend.cleanupErr
}

type boundedSourceTimer struct {
	boundLegacyTimer
	id uint64
}

func (timer *boundedSourceTimer) StartFor(_ uint32, id uint64) { timer.id, timer.running = id, true }
func (timer *boundedSourceTimer) StopFor(id uint64) {
	if timer.id == id {
		timer.running = false
	}
}

func TestBoundedDiscoveryExactLaterCauseAndCleanupOwnerRetention(t *testing.T) {
	sendCause, restoreCause := errors.New("later send"), errors.New("RX restoration")
	backend := &boundedSourceBackend{boundLegacySender: boundLegacySender{failAt: 2, cause: sendCause}, cleanupErr: restoreCause}
	scanner := NewScanner(backend, &boundedSourceTimer{})
	var outcomes []ScanOutcome
	id, err := scanner.DiscoverBounded(1<<11|1<<12, 0xffff, false, nil, func(outcome ScanOutcome) { outcomes = append(outcomes, outcome) })
	if err != nil {
		t.Fatal(err)
	}
	result := boundedLegacyResult(1)
	scanner.HandleDiscoveryResponseFor(id, &result)
	scanner.HandleTimerFor(id)
	if len(outcomes) != 1 || !errors.Is(outcomes[0].Err, sendCause) || !errors.Is(outcomes[0].Err, restoreCause) ||
		len(outcomes[0].Results) != 1 || !scanner.IsScanning() {
		t.Fatal("later/cleanup cause or explicitly partial owned terminal outcome lost")
	}
	if _, err := scanner.DiscoverBounded(1<<11, 0xffff, false, nil, func(ScanOutcome) {}); !errors.Is(err, goterrors.ErrBusy) {
		t.Fatal("terminal callback released failed-restoration ownership")
	}
	backend.cleanupErr = nil
	if err := scanner.RetryCleanup(id); err != nil {
		t.Fatal(err)
	}
	if scanner.IsScanning() || len(outcomes) != 1 {
		t.Fatal("cleanup retry repeated terminal or retained successful cleanup")
	}
}

func TestBoundedDiscoveryStaleTimersResponsesAndOversizedInput(t *testing.T) {
	for _, kind := range []string{"name", "steering", "tuple"} {
		t.Run(kind, func(t *testing.T) {
			scanner := NewScanner(&boundedSourceBackend{}, &boundedSourceTimer{})
			var last ScanOutcome
			calls := 0
			id, err := scanner.DiscoverBounded(1<<11, 0xffff, false, nil, func(outcome ScanOutcome) { last = outcome; calls++ })
			if err != nil {
				t.Fatal(err)
			}
			result := boundedLegacyResult(1)
			switch kind {
			case "name":
				result.NetworkName = "0123456789abcdefX"
			case "steering":
				result.SteeringData = make([]byte, 17)
			case "tuple":
				result.ExtAddress[0] |= 1
			}
			scanner.HandleDiscoveryResponseFor(id, &result)
			if calls != 1 || !errors.Is(last.Err, goterrors.ErrParse) {
				t.Fatal("invalid tuple/oversize silently truncated or succeeded")
			}
			newID, err := scanner.DiscoverBounded(1<<12, 0xffff, false, nil, func(ScanOutcome) { calls++ })
			if err != nil {
				t.Fatal(err)
			}
			scanner.HandleTimerFor(id)
			scanner.HandleDiscoveryResponseFor(id, &result)
			scanner.Cancel(id, goterrors.ErrAbort)
			if calls != 1 || scanner.Identity() != newID || scanner.CurrentChannel() != 12 {
				t.Fatal("late old timer/result/cancel completed the new scan")
			}
		})
	}
}

func TestBoundedDiscoveryOverflowIsExplicitPartialErrorAndNoopBackendRefused(t *testing.T) {
	scanner := NewScanner(nil, &boundedSourceTimer{})
	if id, err := scanner.DiscoverBounded(1<<11, 0xffff, false, nil, func(ScanOutcome) {}); id != 0 || !errors.Is(err, goterrors.ErrNotCapable) {
		t.Fatal("absent sender looked like a scan")
	}
	scanner = NewScanner(&boundedSourceBackend{}, &boundedSourceTimer{})
	var outcome ScanOutcome
	id, err := scanner.DiscoverBounded(1<<11, 0xffff, false, nil, func(result ScanOutcome) { outcome = result })
	if err != nil {
		t.Fatal(err)
	}
	for index := byte(1); index <= 17; index++ {
		result := boundedLegacyResult(index)
		scanner.HandleDiscoveryResponseFor(id, &result)
	}
	if !errors.Is(outcome.Err, goterrors.ErrNoBufs) || len(outcome.Results) != 16 || scanner.IsScanning() {
		t.Fatal("overflow masqueraded as a complete nil-error scan")
	}
	outcome.Results[0].SteeringData[0] = 9
	if scanner.Results()[0].SteeringData[0] != 1 {
		t.Fatal("terminal result aliases retained payload")
	}
}
