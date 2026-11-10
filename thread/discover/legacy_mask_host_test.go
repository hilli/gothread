package discover

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestDiscoveryHOSTLegacyMaskCompatibilityDoesNotRelaxTypedAdmission(t *testing.T) {
	for _, mask := range []uint32{1, 1 | 1<<15} {
		sender := &mockSender{}
		scanner := NewScanner(sender, &mockTimer{})
		completed := 0
		if err := scanner.Discover(mask, PanIDBroadcast, false, func(result *ScanResult) {
			if result == nil {
				completed++
			}
		}); err != nil {
			t.Fatal(err)
		}
		if mask == 1 {
			if completed != 1 || sender.callCount() != 0 || scanner.IsScanning() {
				t.Fatal("legacy empty valid mask did not complete without a send")
			}
		} else if completed != 0 || sender.callCount() != 1 || sender.getCall(0).Channel != 15 {
			t.Fatal("legacy mask failed to ignore unsupported bits")
		}
		strict := NewScanner(&mockSender{}, &mockTimer{})
		if id, err := strict.DiscoverBounded(mask, PanIDBroadcast, false, nil, func(ScanOutcome) { completed++ }); id != 0 || !errors.Is(err, goterrors.ErrInvalidArgs) {
			t.Fatal("legacy compatibility relaxed typed mask admission")
		}
	}
}
