package instance

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

// Existing5aee APIs only; no absent new consumer method is an old proof.
func TestExistingDiscoveryBackendAbsenceIsExplicitNotNoopSuccess(t *testing.T) {
	for _, missing := range []string{"service", "handler"} {
		t.Run(missing, func(t *testing.T) {
			inst := New(Config{})
			pan, channel := inst.mac.GetPanID(), inst.mac.GetPanChannel()
			if missing == "service" {
				inst.mleService = nil
			} else {
				inst.mleService.DiscoveryHandler = nil
			}
			if err := (&discoverySenderAdapter{inst: inst}).SendDiscoveryRequest(15, 0xffff, false); !errors.Is(err, goterrors.ErrNotCapable) {
				t.Fatal("absent actual discovery backend returned success")
			}
			if inst.mac.GetPanID() != pan || inst.mac.GetPanChannel() != channel {
				t.Fatal("refusal changed home tuple")
			}
		})
	}
}
