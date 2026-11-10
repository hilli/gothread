package meshcop

import (
	"bytes"
	"errors"
	"testing"

	goterrors "github.com/hilli/gothread/errors"
)

func TestStrictMaskRejectsFormerEncodingWithoutRewriting(t *testing.T) {
	dataset := completeValidationDataset()
	// Former helper encoded native bit positions directly as network bytes.
	if err := dataset.WriteTLV(TLVChannelMask, []byte{0, 4, 0x07, 0xff, 0xf8, 0}); err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), dataset.Bytes()...)
	if err := ValidateOperationalDataset(dataset.Bytes(), DatasetActive, Page0ThreadChannelMask); !errors.Is(err, goterrors.ErrInvalidArgs) {
		t.Fatalf("former nonstandard encoding silently accepted: %v", err)
	}
	_ = dataset.ConvertToInfo()
	if !bytes.Equal(before, dataset.Bytes()) {
		t.Fatal("validation/read automatically rewrote stored bytes")
	}
}
