package meshcop

import (
	"bytes"
	"testing"
)

// Existing APIs only: this file can be overlaid on exact fb8753 for the later
// granted before-fix compile/run. No new validator API is needed by the oracle.
func TestOperationalChannelMaskLiteralThreadWire(t *testing.T) {
	// Pinned OT ChannelMaskEntry.SetMask reverses host bit positions: channel
	// zero is the first/MSB wire bit, not the least significant native bit.
	literal := []byte{0x35, 0x06, 0x00, 0x04, 0x00, 0x1f, 0xff, 0xe0}
	var dataset Dataset
	if err := dataset.SetFrom(literal); err != nil {
		t.Fatal(err)
	}
	info := dataset.ConvertToInfo()
	if !bytes.Equal(dataset.Bytes(), literal) {
		t.Fatal("read conversion rewrote raw credentials")
	}
	if !info.Components.ChannelMask || info.ChannelMask != 0x07fff800 {
		t.Fatalf("literal Thread mask decoded %#08x, want native channels11..26", info.ChannelMask)
	}
	encoded := InfoToDataset(&Info{ChannelMask: 0x07fff800, Components: Components{ChannelMask: true}})
	if !bytes.Equal(encoded.Bytes(), literal) {
		t.Fatalf("native channel bits encoded nonstandard wire: got% x want% x", encoded.Bytes(), literal)
	}
}
