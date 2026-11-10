package key

import "testing"

// Existing APIs only: can be overlaid on exact fb8753 for the later authorized
// compile-first baseline run. This oracle is independent of framer helpers.
func TestMACKeyIndexLiteralThreadMapping(t *testing.T) {
	manager := NewManager()
	for _, test := range []struct {
		sequence uint32
		index    uint8
	}{
		{0, 1}, {1, 2}, {127, 128}, {128, 1}, {255, 128}, {0x1234, 0x35}, {0xffffffff, 128},
	} {
		manager.SetCurrentKeySequence(test.sequence, ForceUpdate)
		if got := manager.GetMacKeyId(); got != test.index {
			t.Errorf("sequence%#x wireindex%d want%d", test.sequence, got, test.index)
		}
	}
}
