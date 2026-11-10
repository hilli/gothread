package meshcop

import (
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
	"github.com/hilli/gothread/thread/key"
)

func completeValidationDataset() *Dataset {
	info := &Info{
		NetworkName: "OwnedThread", NetworkKey: [16]byte{1, 2, 3, 4, 5},
		ExtendedPanID:   [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		MeshLocalPrefix: [8]byte{0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
		PanID:           0xface, Channel: 20, ChannelMask: Page0ThreadChannelMask,
		Components: Components{
			ActiveTimestamp: true, NetworkKey: true, NetworkName: true,
			ExtendedPanID: true, MeshLocalPrefix: true, PanID: true,
			Channel: true, ChannelMask: true, PSKc: true, SecurityPolicy: true,
		},
	}
	info.ActiveTimestamp.SetSeconds(1)
	info.SecurityPolicy = key.SecurityPolicy{}
	info.SecurityPolicy.SetToDefault()
	return InfoToDataset(info)
}

func TestStrictOperationalDatasetValidation(t *testing.T) {
	active := completeValidationDataset()
	if err := ValidateOperationalDataset(active.Bytes(), DatasetActive, 1<<20); err != nil {
		t.Fatal(err)
	}
	pending := completeValidationDataset()
	var timestamp Timestamp
	timestamp.SetSeconds(2)
	raw, _ := timestamp.MarshalBinary()
	if err := pending.WriteTLV(TLVPendingTimestamp, raw); err != nil {
		t.Fatal(err)
	}
	if err := pending.WriteUint32TLV(TLVDelayTimer, 1000); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperationalDataset(pending.Bytes(), DatasetPending, 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := ValidateOperationalDataset(pending.Bytes(), DatasetActive, 1<<20); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatal("pending transition accepted as active")
	}
}

func TestStrictDatasetRejectsBeforeMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*Dataset)
		mask   uint32
		want   error
	}{
		{"missing-key", func(d *Dataset) { d.RemoveTLV(TLVNetworkKey) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"short-key", func(d *Dataset) { _ = d.WriteTLV(TLVNetworkKey, []byte{1}) }, 1 << 20, goterrors.ErrParse},
		{"non-page-zero", func(d *Dataset) { _ = d.WriteTLV(TLVChannel, []byte{1, 0, 20}) }, 1 << 20, goterrors.ErrNotCapable},
		{"unsupported-radio", func(*Dataset) {}, 1 << 11, goterrors.ErrNotCapable},
		{"unknown-radio", func(*Dataset) {}, 0, goterrors.ErrNotCapable},
		{"missing-selected-channel", func(d *Dataset) {
			mask := []byte{0, 4, 0, 0x10, 0, 0} // Literal Thread wire bit for channel11, not channel20.
			_ = d.WriteTLV(TLVChannelMask, mask)
		}, 1 << 20, goterrors.ErrNotCapable},
		{"channel-range", func(d *Dataset) { _ = d.WriteTLV(TLVChannel, []byte{0, 0, 27}) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"broadcast-pan", func(d *Dataset) { _ = d.WriteUint16TLV(TLVPanID, 0xffff) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"non-ula-prefix", func(d *Dataset) { _ = d.WriteTLV(TLVMeshLocalPrefix, make([]byte, 8)) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"nul-name", func(d *Dataset) { _ = d.WriteTLV(TLVNetworkName, []byte{'a', 0}) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"invalid-utf8", func(d *Dataset) { _ = d.WriteTLV(TLVNetworkName, []byte{0xff}) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"invalid-timestamp", func(d *Dataset) {
			value := make([]byte, 8)
			for i := range value {
				value[i] = 0xff
			}
			_ = d.WriteTLV(TLVActiveTimestamp, value)
		}, 1 << 20, goterrors.ErrInvalidArgs},
		{"zero-rotation", func(d *Dataset) { _ = d.WriteTLV(TLVSecurityPolicy, []byte{0, 0, 0xff}) }, 1 << 20, goterrors.ErrInvalidArgs},
		{"unknown-field", func(d *Dataset) { _ = d.WriteTLV(TLVType(200), []byte{1}) }, 1 << 20, goterrors.ErrNotCapable},
	} {
		t.Run(test.name, func(t *testing.T) {
			dataset := completeValidationDataset()
			test.change(dataset)
			if err := ValidateOperationalDataset(dataset.Bytes(), DatasetActive, test.mask); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
	base := completeValidationDataset().Bytes()
	duplicate := append(append([]byte(nil), base...), byte(TLVPanID), 2, 0, 1)
	if err := ValidateOperationalDataset(duplicate, DatasetActive, 1<<20); !errors.Is(err, goterrors.ErrParse) {
		t.Fatal("duplicate TLV accepted")
	}
}
