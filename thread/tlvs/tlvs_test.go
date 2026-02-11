// Copyright (c) 2024, The GoThread Authors.
// All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

package tlvs

import (
	"bytes"
	"testing"
)

func TestTargetTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	target := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	tlv := TargetTlv{Target: target}

	if tlv.Type() != TypeTarget {
		t.Errorf("Type() = %d, want %d", tlv.Type(), TypeTarget)
	}

	data := tlv.Serialize()
	if len(data) != 18 {
		t.Fatalf("Serialize() length = %d, want 18", len(data))
	}
	if data[0] != TypeTarget || data[1] != 16 {
		t.Errorf("header = [%d, %d], want [%d, 16]", data[0], data[1], TypeTarget)
	}

	parsed, err := ParseTargetTlv(data)
	if err != nil {
		t.Fatalf("ParseTargetTlv() error: %v", err)
	}
	if parsed.Target != target {
		t.Errorf("parsed Target = %v, want %v", parsed.Target, target)
	}
}

func TestRloc16Tlv_SerializeParse(t *testing.T) {
	t.Parallel()

	tlv := Rloc16Tlv{RLOC16: 0x0400}

	if tlv.Type() != TypeRLOC16 {
		t.Errorf("Type() = %d, want %d", tlv.Type(), TypeRLOC16)
	}

	data := tlv.Serialize()
	if len(data) != 4 {
		t.Fatalf("Serialize() length = %d, want 4", len(data))
	}

	parsed, err := ParseRloc16Tlv(data)
	if err != nil {
		t.Fatalf("ParseRloc16Tlv() error: %v", err)
	}
	if parsed.RLOC16 != 0x0400 {
		t.Errorf("parsed RLOC16 = 0x%04X, want 0x0400", parsed.RLOC16)
	}
}

func TestMeshLocalEidTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	iid := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	tlv := MeshLocalEidTlv{IID: iid}

	if tlv.Type() != TypeMeshLocalEID {
		t.Errorf("Type() = %d, want %d", tlv.Type(), TypeMeshLocalEID)
	}

	data := tlv.Serialize()
	if len(data) != 10 {
		t.Fatalf("Serialize() length = %d, want 10", len(data))
	}

	parsed, err := ParseMeshLocalEidTlv(data)
	if err != nil {
		t.Fatalf("ParseMeshLocalEidTlv() error: %v", err)
	}
	if parsed.IID != iid {
		t.Errorf("parsed IID = %v, want %v", parsed.IID, iid)
	}
}

func TestStatusTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status uint8
	}{
		{"success", StatusSuccess},
		{"no address", StatusNoAddressAvailable},
		{"too few routers", StatusTooFewRouters},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tlv := StatusTlv{Status: tt.status}

			if tlv.Type() != TypeStatus {
				t.Errorf("Type() = %d, want %d", tlv.Type(), TypeStatus)
			}

			data := tlv.Serialize()
			if len(data) != 3 {
				t.Fatalf("Serialize() length = %d, want 3", len(data))
			}

			parsed, err := ParseStatusTlv(data)
			if err != nil {
				t.Fatalf("ParseStatusTlv() error: %v", err)
			}
			if parsed.Status != tt.status {
				t.Errorf("parsed Status = %d, want %d", parsed.Status, tt.status)
			}
		})
	}
}

func TestTimeoutTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	tlv := TimeoutTlv{Timeout: 240}

	if tlv.Type() != TypeTimeout {
		t.Errorf("Type() = %d, want %d", tlv.Type(), TypeTimeout)
	}

	data := tlv.Serialize()
	if len(data) != 6 {
		t.Fatalf("Serialize() length = %d, want 6", len(data))
	}

	parsed, err := ParseTimeoutTlv(data)
	if err != nil {
		t.Fatalf("ParseTimeoutTlv() error: %v", err)
	}
	if parsed.Timeout != 240 {
		t.Errorf("parsed Timeout = %d, want 240", parsed.Timeout)
	}
}

func TestLastTransactionTimeTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	tlv := LastTransactionTimeTlv{Time: 12345678}

	if tlv.Type() != TypeLastTransactionTime {
		t.Errorf("Type() = %d, want %d", tlv.Type(), TypeLastTransactionTime)
	}

	data := tlv.Serialize()
	if len(data) != 6 {
		t.Fatalf("Serialize() length = %d, want 6", len(data))
	}

	parsed, err := ParseLastTransactionTimeTlv(data)
	if err != nil {
		t.Fatalf("ParseLastTransactionTimeTlv() error: %v", err)
	}
	if parsed.Time != 12345678 {
		t.Errorf("parsed Time = %d, want 12345678", parsed.Time)
	}
}

func TestRouterMaskTlv_SerializeParse(t *testing.T) {
	t.Parallel()

	mask := RouterMaskTlv{
		IDSequence:  5,
		RouterIDSet: [8]byte{0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
	}

	if mask.Type() != TypeRouterMask {
		t.Errorf("Type() = %d, want %d", mask.Type(), TypeRouterMask)
	}

	data := mask.Serialize()
	if len(data) != 11 {
		t.Fatalf("Serialize() length = %d, want 11", len(data))
	}

	parsed, err := ParseRouterMaskTlv(data)
	if err != nil {
		t.Fatalf("ParseRouterMaskTlv() error: %v", err)
	}
	if parsed.IDSequence != 5 {
		t.Errorf("parsed IDSequence = %d, want 5", parsed.IDSequence)
	}
	if parsed.RouterIDSet != mask.RouterIDSet {
		t.Errorf("parsed RouterIDSet = %v, want %v", parsed.RouterIDSet, mask.RouterIDSet)
	}
}

func TestParse_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parse func([]byte) error
		data  []byte
	}{
		{"target empty", func(d []byte) error { _, err := ParseTargetTlv(d); return err }, nil},
		{"target short", func(d []byte) error { _, err := ParseTargetTlv(d); return err }, []byte{TypeTarget, 16}},
		{"target wrong type", func(d []byte) error { _, err := ParseTargetTlv(d); return err }, []byte{0xFF, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"target bad length", func(d []byte) error { _, err := ParseTargetTlv(d); return err }, []byte{TypeTarget, 8, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"rloc16 empty", func(d []byte) error { _, err := ParseRloc16Tlv(d); return err }, nil},
		{"status empty", func(d []byte) error { _, err := ParseStatusTlv(d); return err }, nil},
		{"timeout empty", func(d []byte) error { _, err := ParseTimeoutTlv(d); return err }, nil},
		{"last txn empty", func(d []byte) error { _, err := ParseLastTransactionTimeTlv(d); return err }, nil},
		{"router mask empty", func(d []byte) error { _, err := ParseRouterMaskTlv(d); return err }, nil},
		{"mesh eid empty", func(d []byte) error { _, err := ParseMeshLocalEidTlv(d); return err }, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.parse(tt.data); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestTlv_RoundTrip(t *testing.T) {
	t.Parallel()

	// Verify that serializing and re-parsing each TLV produces identical data.
	target := TargetTlv{Target: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	d := target.Serialize()
	p, err := ParseTargetTlv(d)
	if err != nil {
		t.Fatalf("round-trip error: %v", err)
	}
	d2 := p.Serialize()
	if !bytes.Equal(d, d2) {
		t.Errorf("round-trip mismatch: %v vs %v", d, d2)
	}
}
